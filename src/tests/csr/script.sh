#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
# AI generated script for testing CSR reading

OUT_DIR="test_csrs"
TMP_DIR="${OUT_DIR}/tmp"
MAX_RUNS=60  
run_count=0

if [[ -x "./test" ]]; then
    BIN="./test"
elif [[ -x "./test_csr" ]]; then
    BIN="./test_csr"
else
    BIN="" 
fi

mkdir -p "$OUT_DIR" "$TMP_DIR"

log() { echo "[INFO] $*"; }
err() { echo "[ERROR] $*" >&2; }

CNs=("test1.example.com" "test2.local" "localhost" "api.service.test")
Orgs=("OrgA" "OrgB Inc" "SmallOrg")
OUs=("QA" "Dev" "Ops" "")
States=("California" "New York" "")
Localities=("San Francisco" "Toronto" "")
Countries=("US" "CA" "GB")
Emails=("admin@example.com" "ops@example.com" "")
KEY_SIZES=(1024 2048 3072)
SAN_TYPES=("none" "dns_single" "dns_multi" "ip")

results_csv="${OUT_DIR}/results.csv"
echo "csr_file,key_file,exit_code,log_snippet" > "$results_csv"

write_san_conf() {
    local out="$1"; shift
    local -n arr=$1
    cat > "$out" <<EOF
    [ req ]
    distinguished_name = req_distinguished_name
    req_extensions = v3_req
    prompt = no

    [ req_distinguished_name ]
    CN = ${arr[0]}

    [ v3_req ]
    subjectAltName = @alt_names

    [ alt_names ]
EOF

local idx=1
for name in "${arr[@]}"; do
    if [[ "$name" =~ ^[0-9]+(\.[0-9]+){3}$ ]]; then
        echo "IP.${idx} = ${name}" >> "$out"
    else
        echo "DNS.${idx} = ${name}" >> "$out"
    fi
    idx=$((idx+1))
done
}

if [[ -z "$BIN" ]]; then
    log "No test binary found (tried ./test and ./test_csr). Script will still generate CSRs but won't run tests."
else
    log "Using test binary: $BIN"
fi

for CN in "${CNs[@]}"; do
    for O in "${Orgs[@]}"; do
        for OU in "${OUs[@]}"; do
            for ST in "${States[@]}"; do
                for L in "${Localities[@]}"; do
                    for C in "${Countries[@]}"; do
                        for EMAIL in "${Emails[@]}"; do
                            for KSIZE in "${KEY_SIZES[@]}"; do
                                for SANTYPE in "${SAN_TYPES[@]}"; do

                                    run_count=$((run_count+1))
                                    if (( run_count > MAX_RUNS )); then
                                        log "Reached MAX_RUNS ($MAX_RUNS). Stopping."
                                        log "Generated $((run_count-1)) CSRs (limit reached). See $OUT_DIR."
                                        exit 0
                                    fi

                                    fn_cn="${CN//[^A-Za-z0-9._-]/_}"
                                    fn_o="${O//[^A-Za-z0-9._-]/_}"
                                    fn_ou="${OU//[^A-Za-z0-9._-]/_}"
                                    fn_c="${C//[^A-Za-z0-9._-]/_}"
                                    base="${fn_cn}_${fn_o}_${fn_ou}_${fn_c}_${KSIZE}_${SANTYPE}_${run_count}"

                                    KEY_FILE="${OUT_DIR}/${base}.key.pem"
                                    CSR_FILE="${OUT_DIR}/${base}.csr.pem"
                                    LOG_FILE="${OUT_DIR}/${base}.run.log"

                                    log "Generating RSA ${KSIZE}-bit key -> $KEY_FILE"
                                    openssl genpkey -algorithm RSA -out "$KEY_FILE" -pkeyopt rsa_keygen_bits:${KSIZE} >/dev/null 2>&1

                                    subj=""
                                    [[ -n "$C" ]] && subj+="/C=$C"
                                    [[ -n "$ST" ]] && subj+="/ST=$ST"
                                    [[ -n "$L" ]] && subj+="/L=$L"
                                    [[ -n "$O" ]] && subj+="/O=$O"
                                    [[ -n "$OU" ]] && subj+="/OU=$OU"
                                    [[ -n "$CN" ]] && subj+="/CN=$CN"
                                    [[ -n "$EMAIL" ]] && subj+="/emailAddress=$EMAIL"

                                    case "$SANTYPE" in
                                        none)
                                            log "Generating CSR (no SAN) -> $CSR_FILE"
                                            openssl req -new -key "$KEY_FILE" -out "$CSR_FILE" -subj "$subj" -sha256 >/dev/null 2>&1
                                            ;;
                                        dns_single)
                                            dnsarr=("$CN")
                                            sanconf="${TMP_DIR}/${base}_san.cnf"
                                            write_san_conf "$sanconf" dnsarr
                                            log "Generating CSR (single DNS SAN) -> $CSR_FILE"
                                            openssl req -new -key "$KEY_FILE" -out "$CSR_FILE" -subj "$subj" -config "$sanconf" -reqexts v3_req -sha256 >/dev/null 2>&1
                                            ;;
                                        dns_multi)
                                            dnsarr=("$CN" "www.${CN}" "api.${CN}")
                                            sanconf="${TMP_DIR}/${base}_san.cnf"
                                            write_san_conf "$sanconf" dnsarr
                                            log "Generating CSR (multi DNS SANs) -> $CSR_FILE"
                                            openssl req -new -key "$KEY_FILE" -out "$CSR_FILE" -subj "$subj" -config "$sanconf" -reqexts v3_req -sha256 >/dev/null 2>&1
                                            ;;
                                        ip)
                                            dnsarr=("$CN" "127.0.0.1")
                                            sanconf="${TMP_DIR}/${base}_san.cnf"
                                            write_san_conf "$sanconf" dnsarr
                                            log "Generating CSR (DNS + IP SAN) -> $CSR_FILE"
                                            openssl req -new -key "$KEY_FILE" -out "$CSR_FILE" -subj "$subj" -config "$sanconf" -reqexts v3_req -sha256 >/dev/null 2>&1
                                            ;;
                                        *)
                                            err "Unknown SAN type: $SANTYPE"
                                            ;;
                                    esac

                                    if [[ -n "$BIN" && -x "$BIN" ]]; then
                                        log "Running $BIN on $CSR_FILE"
                                        set +e
                                        "$BIN" "$CSR_FILE" > "$LOG_FILE" 2>&1
                                        rc=$?
                                        set -e
                                        snippet=$(head -c 1000 "$LOG_FILE" | tr '\n' ' ' | sed 's/,/;/g')
                                        echo "${CSR_FILE},${KEY_FILE},${rc},${snippet}" >> "$results_csv"
                                        log "Run exit code: $rc (log: $LOG_FILE)"
                                    else
                                        echo "${CSR_FILE},${KEY_FILE},-1,not_run" >> "$results_csv"
                                    fi

                                done
                            done
                        done
                    done
                done
            done
        done
    done
done

log "Done: generated $run_count CSRs into $OUT_DIR"
log "Results recorded in $results_csv"
rm -rf "$TMP_DIR"

