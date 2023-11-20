import logging
import subprocess
import threading
import os
import time
import sys
import http.server
import http

from functools import partial

from http.server import SimpleHTTPRequestHandler
from http.server import ThreadingHTTPServer
from http.server import BaseHTTPRequestHandler


def httpf(HandlerClass=BaseHTTPRequestHandler,
         ServerClass=ThreadingHTTPServer,
         protocol="HTTP/1.0", port=8000, bind=None):
    """Test the HTTP request handler class.

    This runs an HTTP server on port 8000 (or the port argument).

    """
    class DualStackServer(ThreadingHTTPServer):
        def server_bind(self):
            # suppress exception when protocol is IPv4
            with contextlib.suppress(Exception):
                self.socket.setsockopt(
                    socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            return super().server_bind()

    ServerClass.address_family, addr = http.server._get_best_family(bind, port)

    HandlerClass.protocol_version = protocol
    with ServerClass(addr, HandlerClass) as httpd:
        host, port = httpd.socket.getsockname()[:2]
        url_host = f'[{host}]' if ':' in host else host
        print(
            f"Serving HTTP on {host} port {port} "
            f"(http://{url_host}:{port}/) ..."
        )

        return httpd

class httpThread(threading.Thread):
    def __init__(self, name, ip, port, directory):
        super(httpThread, self).__init__()
        handler_class = partial(SimpleHTTPRequestHandler, directory=directory)
        self.httpfd = httpf(handler_class, ThreadingHTTPServer, port, ip)
        self.name = name


    def run(self):
        # 循环等待客户端请求
        self.httpfd.serve_forever()

if __name__ == "__main__":
    httpdx = httpThread("http_server", "10.17.7.88", 80, "./")
    httpdx.start()

    while True:
        print("test")
        time.sleep(1)
