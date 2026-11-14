#!/usr/bin/env python3
"""Target 10: robots.txt with secret path."""

import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = 8010


class Handler(BaseHTTPRequestHandler):
    server_version = ""

    def do_GET(self):
        if self.path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow: /secret/admin\nDisallow: /private/config\n")
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Target 10: robots.txt</h1></body></html>")

    def log_message(self, format, *args):
        msg = f"{self.address_string()} - - [{self.log_date_time_string()}] {format % args}\n"
        sys.stderr.write(msg)


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"Target 10 running on port {PORT} (robots.txt with secret path)")
    server.serve_forever()
