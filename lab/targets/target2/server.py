#!/usr/bin/env python3
"""Target 2: Missing CSP header."""
from http.server import HTTPServer, BaseHTTPRequestHandler
import sys

PORT = 8002


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Permissions-Policy", "camera=()")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        # NOTE: No Content-Security-Policy header (HDR-002)
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Target 2: Missing CSP</h1></body></html>")

    def log_message(self, format, *args):
        sys.stderr.write("%s - - [%s] %s\n" % (self.address_string(), self.log_date_time_string(), format % args))


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"Target 2 running on port {PORT} (missing CSP)")
    server.serve_forever()