#!/usr/bin/env python3
"""Target 8: Directory listing enabled."""
from http.server import HTTPServer, SimpleHTTPRequestHandler
import sys

PORT = 8008


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory="/app", **kwargs)

    def list_directory(self, path):
        """Enable directory listing."""
        try:
            entries = os.listdir(path)
        except os.error:
            return None
        entries.sort(key=lambda a: a.lower())
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"<html><head><title>Directory listing</title></head>")
        self.wfile.write(b"<body><h1>Directory listing</h1><hr><ul>")
        for entry in entries:
            self.wfile.write(b"<li><a href='" + entry.encode() + b"'>" + entry.encode() + b"</a></li>")
        self.wfile.write(b"</ul><hr></body></html>")

    def log_message(self, format, *args):
        sys.stderr.write("%s - - [%s] %s\n" % (self.address_string(), self.log_date_time_string(), format % args))


import os

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"Target 8 running on port {PORT} (directory listing enabled)")
    server.serve_forever()