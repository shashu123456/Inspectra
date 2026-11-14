#!/usr/bin/env python3
"""Target 9: HTTP server on port 8009 + TCP server on port 3306."""

import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

HTTP_PORT = 8009
TCP_PORT = 3306


class Handler(BaseHTTPRequestHandler):
    server_version = ""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Target 9: Open port 3306</h1></body></html>")

    def log_message(self, format, *args):
        msg = f"{self.address_string()} - - [{self.log_date_time_string()}] {format % args}\n"
        sys.stderr.write(msg)


def run_http_server():
    server = HTTPServer(("0.0.0.0", HTTP_PORT), Handler)
    print(f"Target 9 HTTP running on port {HTTP_PORT}")
    server.serve_forever()


def run_tcp_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", TCP_PORT))
    server.listen(5)
    print(f"Target 9 TCP running on port {TCP_PORT}")
    while True:
        conn, addr = server.accept()
        conn.close()


if __name__ == "__main__":
    http_thread = threading.Thread(target=run_http_server, daemon=True)
    tcp_thread = threading.Thread(target=run_tcp_server, daemon=True)
    http_thread.start()
    tcp_thread.start()
    http_thread.join()
