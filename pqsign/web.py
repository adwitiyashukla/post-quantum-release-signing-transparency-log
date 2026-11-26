import re
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LENGTH = re.compile(r"[0-9]{1,9}")


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, handler, max_connections: int, timeout: float):
        self.slots = threading.BoundedSemaphore(max_connections)
        self.request_timeout = timeout
        super().__init__(address, handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        self.timeout = self.server.request_timeout
        super().setup()

    def log_message(self, *args):
        pass

    def send(self, status: int, body: bytes, ctype: str = "text/plain; charset=utf-8", cache: str = "no-store"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache)
        self.end_headers()
        self.wfile.write(body)

    def refuse(self, status: int, body: bytes) -> None:
        self.send(status, body)
        self.close_connection = True
        end = time.monotonic() + self.server.request_timeout
        try:
            self.connection.shutdown(socket.SHUT_WR)
            while (left := end - time.monotonic()) > 0:
                self.connection.settimeout(left)
                if not self.connection.recv(65536):
                    break
        except OSError:
            pass

    def body(self, limit: int) -> bytes | None:
        raw = self.headers.get("Content-Length", "")
        if not LENGTH.fullmatch(raw) or int(raw) == 0:
            self.refuse(400, b"bad Content-Length\n")
            return None
        size = int(raw)
        if size > limit:
            self.refuse(413, b"body too large\n")
            return None
        deadline = time.monotonic() + self.server.request_timeout
        data = bytearray()
        while len(data) < size:
            chunk = self.rfile.read1(size - len(data))
            if not chunk or time.monotonic() > deadline:
                raise TimeoutError("request body was not sent in time")
            data += chunk
        return bytes(data)
