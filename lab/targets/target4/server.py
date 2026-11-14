#!/usr/bin/env python3
"""Target 4: HTTPS with self-signed certificate."""
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl
import os
import subprocess
import sys

PORT = 8004
CERT_FILE = "/tmp/server.pem"
KEY_FILE = "/tmp/server.key"


def ensure_cert():
    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", KEY_FILE, "-out", CERT_FILE,
                "-days", "1", "-nodes",
                "-subj", "/CN=localhost",
            ],
            capture_output=True,
        )


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Target 4: Self-signed cert</h1></body></html>")

    def log_message(self, format, *args):
        sys.stderr.write("%s - - [%s] %s\n" % (self.address_string(), self.log_date_time_string(), format % args))


if __name__ == "__main__":
    ensure_cert()
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERT_FILE, KEY_FILE)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"Target 4 running on port {PORT} (HTTPS self-signed cert)")
    server.serve_forever()