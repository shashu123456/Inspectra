#!/usr/bin/env python3
"""Target 6: Server banner disclosure."""

import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = 8006


class Handler(BaseHTTPRequestHandler):
    server_version = "nginx/1.18.0"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Target 6: Server banner disclosed</h1></body></html>")

    def log_message(self, format, *args):
        msg = f"{self.address_string()} - - [{self.log_date_time_string()}] {format % args}\n"
        sys.stderr.write(msg)


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"Target 6 running on port {PORT} (server banner: nginx/1.18.0)")
    server.serve_forever()
