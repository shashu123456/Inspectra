#!/usr/bin/env python3
"""Target 5: HTTPS with TLS 1.0 enabled."""

import os
import ssl
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = 8005
CERT_FILE = "/tmp/server5.pem"
KEY_FILE = "/tmp/server5.key"


def ensure_cert():
    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                KEY_FILE,
                "-out",
                CERT_FILE,
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=localhost",
            ],
            capture_output=True,
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
    context.load_cert_chain(CERT_FILE, KEY_FILE)
    context.options &= ~ssl.OP_NO_TLSv1
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"Target 5 running on port {PORT} (HTTPS TLS 1.0 enabled)")
    server.serve_forever()
