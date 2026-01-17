#!/usr/bin/env bash
set -e

BASE_DIR="$PWD/local-ca"
CA_NAME="Local Dev Root CA"
DOMAIN="localhost"
PORT=4433

CA_CBZ="../build/out/ca-cbz"
CA_DIR="$BASE_DIR/ca"
SITE_DIR="$BASE_DIR/site"
CERTS="$BASE_DIR/certs"
PRIVATE="$BASE_DIR/private"

CA_KEY="$PRIVATE/ca.key.pem"
CA_CERT="$CERTS/ca.cert.pem"

SITE_KEY="$PRIVATE/site.key.pem"
SITE_CERT="$CERTS/site.cert.pem"
SITE_CSR="$BASE_DIR/site.csr.pem"

FIREFOX_PROFILES="$HOME/.mozilla/firefox"

### CHECK ROOT ###
if [[ $EUID -ne 0 ]]; then
  echo "❌ Run as root (needed for trust store & /etc/hosts)"
  exit 1
fi

echo "Creating directories..."
mkdir -p "$CERTS" "$PRIVATE"
# chmod 700 "$PRIVATE"

echo "🔑 Generating CA key (encrypted)..."
openssl genrsa -aes256 -out "$CA_KEY" 4096
# chmod 400 "$CA_KEY"

echo "Generating CA certificate with ca-cbz..."
sudo "$CA_CBZ" gen-self-signed-cert \
  --key "$CA_KEY" \
  --out "$CA_CERT" \
  --days 3650

echo "Installing CA into system trust..."
cp "$CA_CERT" /etc/ca-certificates/trust-source/anchors/demo-ca.crt
update-ca-trust

echo "Generating site key (encrypted)..."
openssl genrsa -aes256 -out "$SITE_KEY" 2048
# chmod 400 "$SITE_KEY"

echo "Generating CSR with ca-cbz..."
sudo "$CA_CBZ" gen-csr \
  --key "$SITE_KEY" \
  --out "$SITE_CSR"

echo "Signing site certificate with ca-cbz..."
echo "gen-cert \
  --cacert $CA_CERT \
  --cakey $CA_KEY \
  --csr $SITE_CSR \
  --out $SITE_CERT \
  --days 825"

sudo "$CA_CBZ" gen-cert \
  --cacert "$CA_CERT" \
  --cakey "$CA_KEY" \
  --csr "$SITE_CSR" \
  --out "$SITE_CERT" \
  --days 825

echo "Updating /etc/hosts..."
grep -q "$DOMAIN" /etc/hosts || echo "127.0.0.1 $DOMAIN" >> /etc/hosts

echo "Installing CA into Firefox..."
for profile in "$FIREFOX_PROFILES"/*.default*; do
  if [ -d "$profile" ]; then
    certutil -A -n "$CA_NAME" -t "C,," -i "$CA_CERT" -d sql:"$profile"
  fi
done

echo "📄 Creating demo website..."
cat > index.html <<EOF
<!doctype html>
<html>
  <body>
    <h1>🔒 Trusted HTTPS</h1>
    <p>Certificate signed by <b>$CA_NAME</b></p>
    <p>Generated with ca-cbz utility</p>
  </body>
</html>
EOF

echo "Starting HTTPS server..."
echo "https://$DOMAIN:$PORT"
echo "Press Ctrl+C to stop"

python - <<EOF
from http.server import HTTPServer, SimpleHTTPRequestHandler
import ssl

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(
    certfile="$SITE_CERT",
    keyfile="$SITE_KEY",
)

httpd = HTTPServer(("0.0.0.0", $PORT), SimpleHTTPRequestHandler)
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

httpd.serve_forever()
EOF
