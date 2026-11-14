#!/usr/bin/env python3
"""Target 12: Verbose error messages."""
from http.server import HTTPServer, BaseHTTPRequestHandler
import sys
import traceback

PORT = 8012


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/error":
            # Simulate a verbose error with stack trace
            try:
                raise ValueError("Database connection failed: Could not connect to mysql://user:password@db-server:3306/mydb")
            except Exception as e:
                self.send_response(500)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                tb = traceback.format_exc()
                self.wfile.write(f"<html><body><h1>Internal Server Error</h1><pre>{tb}</pre></body></html>".encode())
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Target 12: Verbose errors</h1><p>Try /error</p></body></html>")

    def log_message(self, format, *args):
        sys.stderr.write("%s - - [%s] %s\n" % (self.address_string(), self.log_date_time_string(), format % args))


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"Target 12 running on port {PORT} (verbose error messages)")
    server.serve_forever()