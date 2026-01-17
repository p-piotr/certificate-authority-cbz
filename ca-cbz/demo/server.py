from http.server import HTTPServer, SimpleHTTPRequestHandler
import ssl
import sys
from datetime import datetime, timezone
from jinja2 import Template

# Check if cryptography is available
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    print("Error: 'cryptography' package not found. Install with: pip install cryptography")
    exit(1)

# Read arguments
SITE_CERT = sys.argv[1]
SITE_KEY = sys.argv[2]
DOMAIN = sys.argv[3]
PORT = int(sys.argv[4])
CA_NAME = sys.argv[5]

cert_info = {}

if HAS_CRYPTO:
    try:
        with open(SITE_CERT, 'rb') as f:
            cert_data = f.read()
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())

        cert_info = {
            'subject': cert.subject.rfc4514_string(),
            'issuer': cert.issuer.rfc4514_string(),
            'not_before': cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
            'not_after': cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
            'serial': hex(cert.serial_number)[2:].upper(),
            'fingerprint': cert.fingerprint(cert.signature_hash_algorithm).hex().upper(),
            'days_left': (cert.not_valid_after_utc - datetime.now(timezone.utc)).days,
            'ca_name': CA_NAME,
            'domain': DOMAIN,
            'port': PORT
        }

        cert_info['fingerprint_formatted'] = ':'.join(
            cert_info['fingerprint'][i:i+2] for i in range(0, len(cert_info['fingerprint']), 2)
        )
        cert_info['expiring_soon'] = cert_info['days_left'] < 30
        cert_info['is_valid'] = cert_info['days_left'] > 0
    except Exception as e:
        print(f"Error parsing certificate: {e}")

# Load template
try:
    with open('static/index.html', 'r') as f:
        template = Template(f.read())
except Exception as e:
    print(f"Error loading template: {e}")
    template = None

class CertInfoHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory="static", **kwargs)
    
    def do_GET(self):
        if self.path == '/' or self.path == '/index.html':
            try:
                if template and cert_info:
                    html = template.render(
                        subject=cert_info['subject'],
                        issuer=cert_info['issuer'],
                        not_before=cert_info['not_before'],
                        not_after=cert_info['not_after'],
                        serial=cert_info['serial'],
                        fingerprint=cert_info['fingerprint_formatted'],
                        days_left=cert_info['days_left'],
                        ca_name=cert_info['ca_name'],
                        domain=cert_info['domain'],
                        port=cert_info['port'],
                        expiring_soon=cert_info['expiring_soon'],
                        is_valid=cert_info['is_valid']
                    )
                elif template:
                    # Fallback if cert parsing failed
                    html = template.render(
                        subject='N/A',
                        issuer='N/A',
                        not_before='N/A',
                        not_after='N/A',
                        serial='N/A',
                        fingerprint='N/A',
                        days_left=0,
                        ca_name=CA_NAME,
                        domain=DOMAIN,
                        port=PORT,
                        expiring_soon=False,
                        is_valid=False
                    )
                else:
                    raise Exception("Template not loaded")
                
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(html.encode())
            except Exception as e:
                print(f"Error serving index: {e}")
                self.send_error(500)
        else:
            super().do_GET()

# Set up SSL context
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile=SITE_CERT, keyfile=SITE_KEY)

# Start server
httpd = HTTPServer(("0.0.0.0", PORT), CertInfoHandler)
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

print(f"Starting HTTPS server...")
print(f"https://{DOMAIN}:{PORT}")
if cert_info:
    print(f"Certificate expires in {cert_info['days_left']} days")
print("Press Ctrl+C to stop")

try:
    httpd.serve_forever()
except KeyboardInterrupt:
    print("\nServer stopped.")
    httpd.shutdown()
