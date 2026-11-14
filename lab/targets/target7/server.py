#!/usr/bin/env python3
"""Target 7: Exposed .git directory."""

import sys
from http.server import HTTPServer, SimpleHTTPRequestHandler

PORT = 8007


class Handler(SimpleHTTPRequestHandler):
    server_version = ""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory="/app/.git", **kwargs)

    def log_message(self, format, *args):
        msg = f"{self.address_string()} - - [{self.log_date_time_string()}] {format % args}\n"
        sys.stderr.write(msg)


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"Target 7 running on port {PORT} (.git exposed)")
    server.serve_forever()
