#!/usr/bin/env python3
"""Target 12: Verbose error messages."""

import sys
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = 8012


class Handler(BaseHTTPRequestHandler):
    server_version = ""

    def do_GET(self):
        if self.path == "/error":
            try:
                raise ValueError("Database connection failed")
            except Exception:
                self.send_response(500)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                tb = traceback.format_exc()
                tb = traceback.format_exc()
                html = f"<html><body><h1>Internal Server Error</h1><pre>{tb}</pre></body></html>"
                self.wfile.write(html.encode())
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Target 12: Verbose errors</h1></body></html>")

    def log_message(self, format, *args):
        msg = f"{self.address_string()} - - [{self.log_date_time_string()}] {format % args}\n"
        sys.stderr.write(msg)


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"Target 12 running on port {PORT} (verbose error messages)")
    server.serve_forever()
