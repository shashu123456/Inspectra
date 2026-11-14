#!/usr/bin/env python3
"""Target 3: Missing X-Frame-Options header."""

import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = 8003


class Handler(BaseHTTPRequestHandler):
    server_version = ""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Permissions-Policy", "camera=()")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Target 3: Missing X-Frame-Options</h1></body></html>")

    def log_message(self, format, *args):
        msg = f"{self.address_string()} - - [{self.log_date_time_string()}] {format % args}\n"
        sys.stderr.write(msg)


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"Target 3 running on port {PORT} (missing X-Frame-Options)")
    server.serve_forever()
