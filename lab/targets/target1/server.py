#!/usr/bin/env python3
"""Target 1: Missing HSTS header."""
from http.server import HTTPServer, BaseHTTPRequestHandler
import sys

PORT = 8001


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Permissions-Policy", "camera=()")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        # NOTE: No Strict-Transport-Security header (HDR-001)
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Target 1: Missing HSTS</h1></body></html>")

    def log_message(self, format, *args):
        sys.stderr.write("%s - - [%s] %s\n" % (self.address_string(), self.log_date_time_string(), format % args))


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"Target 1 running on port {PORT} (missing HSTS)")
    server.serve_forever()