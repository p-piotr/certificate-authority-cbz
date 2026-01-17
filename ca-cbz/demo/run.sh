#!/usr/bin/env bash
set -e

BASE_DIR="$PWD/local-ca"
CA_NAME="Demonstration CA"
DOMAIN="localhost"
PORT=4433

CA_CBZ="../build/out/ca-cbz"
CA_DIR="$BASE_DIR/ca"
STATIC_DIR="$BASE_DIR/static"
SITE_DIR="$BASE_DIR/site"
CERTS="$BASE_DIR/certs"
PRIVATE="$BASE_DIR/private"

CA_KEY="$PRIVATE/ca.key.pem"
CA_CERT="$CERTS/ca.cert.pem"

SITE_KEY="$PRIVATE/site.key.pem"
SITE_CERT="$CERTS/site.cert.pem"
SITE_CSR="$BASE_DIR/site.csr.pem"

FIREFOX_PROFILES="$HOME/.mozilla/firefox"

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: Run as root (needed for trust store & /etc/hosts)"
  exit 1
fi

echo "Creating directories..."
mkdir -p "$CERTS" "$PRIVATE"
chmod 700 "$PRIVATE"
echo

echo "Generating Encrypted CA key..."
openssl genrsa -aes256 -out "$CA_KEY" 4096
chmod 400 "$CA_KEY"
echo

echo "Generating CA certificate with ca-cbz..."
sudo "$CA_CBZ" gen-self-signed-cert \
  --key "$CA_KEY" \
  --out "$CA_CERT" \
  --days 3650
echo


echo "Installing CA into system trust..."
cp "$CA_CERT" /etc/ca-certificates/trust-source/anchors/demo-ca.crt
update-ca-trust
echo


echo "Generating encrypted site key..."
openssl genrsa -aes256 -out "$SITE_KEY" 2048
chmod 400 "$SITE_KEY"
echo


echo "Generating CSR with ca-cbz..."
sudo "$CA_CBZ" gen-csr \
  --key "$SITE_KEY" \
  --out "$SITE_CSR"
echo

echo "Signing site certificate with ca-cbz..."
sudo "$CA_CBZ" gen-cert \
  --cacert "$CA_CERT" \
  --cakey "$CA_KEY" \
  --csr "$SITE_CSR" \
  --out "$SITE_CERT" \
  --days 825
echo
chmod 600 "$SITE_CERT"

echo "Updating /etc/hosts..."
grep -q "$DOMAIN" /etc/hosts || echo "127.0.0.1 $DOMAIN" >> /etc/hosts
echo

echo "Installing CA into Firefox..."
for profile in "$FIREFOX_PROFILES"/*.default*; do
  if [ -d "$profile" ]; then
    certutil -A -n "$CA_NAME" -t "C,," -i "$CA_CERT" -d sql:"$profile"
  fi
done
echo

echo "Starting HTTPS server with certificate display..."
echo "https://$DOMAIN:$PORT"
echo "Press Ctrl+C to stop"

python3 server.py "$SITE_CERT" "$SITE_KEY" "$DOMAIN" "$PORT" "$CA_NAME"

echo "#!/bin/bash" > rerun_server.sh
echo "sudo python3 server.py $SITE_CERT $SITE_KEY $DOMAIN $PORT $CA_NAME" >> rerun_server.sh
chmod +x rerun_server.sh



echo "Starting HTTPS server..."
echo "https://$DOMAIN:$PORT"
echo "Press Ctrl+C to stop"
