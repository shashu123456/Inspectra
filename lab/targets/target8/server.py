#!/usr/bin/env python3
"""Target 8: Directory listing enabled."""

import os
import sys
from http.server import HTTPServer, SimpleHTTPRequestHandler

PORT = 8008


class Handler(SimpleHTTPRequestHandler):
    server_version = ""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory="/app", **kwargs)

    def list_directory(self, path):
        try:
            entries = os.listdir(path)
        except OSError:
            return None
        entries.sort(key=lambda a: a.lower())
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"<html><head><title>Directory listing</title></head>")
        self.wfile.write(b"<body><h1>Directory listing</h1><hr><ul>")
        for entry in entries:
            encoded = entry.encode()
            self.wfile.write(b"<li><a href='" + encoded + b"'>" + encoded + b"</a></li>")
        self.wfile.write(b"</ul><hr></body></html>")

    def log_message(self, format, *args):
        msg = f"{self.address_string()} - - [{self.log_date_time_string()}] {format % args}\n"
        sys.stderr.write(msg)


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"Target 8 running on port {PORT} (directory listing enabled)")
    server.serve_forever()
