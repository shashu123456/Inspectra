#!/usr/bin/env python3
"""Target 7: Exposed .git directory."""
from http.server import HTTPServer, SimpleHTTPRequestHandler
import os
import sys

PORT = 8007


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory="/app/.git", **kwargs)

    def log_message(self, format, *args):
        sys.stderr.write("%s - - [%s] %s\n" % (self.address_string(), self.log_date_time_string(), format % args))


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"Target 7 running on port {PORT} (.git exposed)")
    server.serve_forever()