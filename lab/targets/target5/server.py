#!/usr/bin/env python3
"""Target 5: HTTPS with TLS 1.0 enabled."""

import datetime
import ssl
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

PORT = 8005
DIR = Path(__file__).resolve().parent
CERT_FILE = DIR / "server5.pem"
KEY_FILE = DIR / "server5.key"


def ensure_cert():
    if CERT_FILE.exists() and KEY_FILE.exists():
        return
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(1001)
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    CERT_FILE.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    KEY_FILE.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


class Handler(BaseHTTPRequestHandler):
    server_version = ""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Target 5: TLS 1.0 enabled</h1></body></html>")

    def log_message(self, format, *args):
        msg = f"{self.address_string()} - - [{self.log_date_time_string()}] {format % args}\n"
        sys.stderr.write(msg)


if __name__ == "__main__":
    ensure_cert()
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(CERT_FILE), str(KEY_FILE))
    context.options &= ~ssl.OP_NO_TLSv1
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"Target 5 running on port {PORT} (HTTPS TLS 1.0 enabled)")
    server.serve_forever()
