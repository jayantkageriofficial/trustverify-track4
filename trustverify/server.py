"""Loopback-only organizer mock services. No deployment or external targets."""

import contextlib
import json
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from cryptography.exceptions import InvalidSignature

from .authority import Authority, Denied, NODES
from .crypto import canonical

MAX_BODY = 64 * 1024
# Requests that fail authentication share one bucket per node; valid identities never draw from it.
UNAUTHENTICATED_BURST = 20
UNAUTHENTICATED_PER_SECOND = 10.0
# Each connection gets its own thread, so one slow or stalled client cannot block the node.
# Beyond this many in-flight connections a node answers 503 at once instead of queueing.
MAX_CONNECTIONS = 64


class TokenBucket:
    def __init__(self, capacity, rate, clock=time.monotonic):
        self.capacity, self.rate, self.clock = capacity, rate, clock
        self.tokens, self.updated = float(capacity), clock()
        self.lock = threading.Lock()

    def take(self):
        with self.lock:
            now = self.clock()
            self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
            self.updated = now
            if self.tokens < 1:
                return False
            self.tokens -= 1
            return True


def serve(directory, operator, node, port):
    if node not in NODES or not (port == 0 or 1024 <= port <= 65535):
        raise ValueError("invalid node or port")
    authority = Authority(directory, operator)
    authority.recover()
    unauthenticated = TokenBucket(UNAUTHENTICATED_BURST, UNAUTHENTICATED_PER_SECOND)
    slots = threading.BoundedSemaphore(MAX_CONNECTIONS)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"
        server_version = "trustverify-node"
        sys_version = ""

        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def handle(self):
            if not slots.acquire(blocking=False):
                body = canonical({"error": "node connection capacity reached; retry later"})
                headers = ("HTTP/1.0 503 Service Unavailable\r\nContent-Type: application/json\r\n"
                           f"Content-Length: {len(body)}\r\nServer: trustverify-node\r\n"
                           "Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n"
                           "Connection: close\r\n\r\n").encode("ascii")
                with contextlib.suppress(OSError):
                    self.connection.sendall(headers + body)
                return
            try:
                super().handle()
            finally:
                slots.release()

        def log_message(self, *_):
            pass

        def respond(self, status, value):
            body = canonical(value)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def handle_api(self):
            if self.command == "GET" and self.path == "/health":
                return {"node": node, "service": NODES[node], "status": "running"}
            target = urlsplit(self.path)
            if self.command == "GET" and target.path == "/challenge":
                devices = parse_qs(target.query, max_num_fields=1).get("device", [None])
                return {"nonce": authority.challenge(node, devices[0])}
            if self.command != "POST" or self.path != "/request":
                raise Denied("unknown endpoint", 404)
            if self.headers.get("Transfer-Encoding"):
                raise Denied("chunked HTTP requests are unsupported", 400)
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) != 1:
                raise Denied("one Content-Length is required", 400)
            length = int(lengths[0])
            if not 0 < length <= MAX_BODY:
                raise Denied("request exceeds sandbox limit", 413)
            if self.headers.get_content_type() != "application/json":
                raise Denied("application/json required", 415)
            body = self.rfile.read(length)
            if len(body) != length:
                raise Denied("truncated request", 400)
            # Duplicate JSON names create interpretation differences between consumers.
            def unique_pairs(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError("duplicate JSON field")
                    result[key] = value
                return result
            request = json.loads(body, object_pairs_hook=unique_pairs,
                                 parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid number")))
            if not (isinstance(request, dict) and authority.authenticates(request)) and not unauthenticated.take():
                raise Denied("too many unauthenticated requests; slow down", 429)
            return authority.execute(node, request)

        def do_GET(self):
            try:
                self.respond(200, self.handle_api())
            except Denied as exc:
                self.respond(exc.status, {"error": str(exc)})
            except (ValueError, TypeError, KeyError, InvalidSignature, RecursionError):
                self.respond(400, {"error": "invalid request or integrity check"})
            except (sqlite3.Error, OSError):
                self.respond(503, {"error": "authority unavailable; access denied"})
            except Exception:  # noqa: BLE001 - fail closed without a traceback or internal detail
                self.respond(500, {"error": "internal error; access denied"})

        do_POST = do_GET

    ThreadingHTTPServer.daemon_threads = True
    with ThreadingHTTPServer(("127.0.0.1", port), Handler) as server:
        print(json.dumps({"node": node, "url": f"http://127.0.0.1:{server.server_address[1]}"}), flush=True)
        server.serve_forever(poll_interval=0.1)
