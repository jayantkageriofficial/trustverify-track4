"""Local web UI for the interactive lab: ``python -m trustverify ui``.

Standard library only (``http.server``) plus the prototype's own dependencies. It binds
to 127.0.0.1, checks the Host header (no DNS rebinding) and requires a random per-launch
token on every API call (no cross-site requests from other pages in the browser).
Optional and separate from the grader path.
"""

import json
import secrets
import signal
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources

from .authority import Denied
from .lab import Lab, LabError

MAX_BODY = 3 * 1024 * 1024

ACTIONS = {
    "reset": lambda lab, a: lab.reset(),
    "enroll": lambda lab, a: lab.enroll(a.get("user")),
    "grant": lambda lab, a: lab.grant(a.get("user"), a.get("service"), a.get("mode", "approved")),
    "access": lambda lab, a: lab.access(a.get("user"), a.get("node", "node-a"), a.get("note", ""), a.get("key", "current")),
    "rotate": lambda lab, a: lab.rotate(a.get("user")),
    "revoke": lambda lab, a: lab.revoke(a.get("user")),
    "replay": lambda lab, a: lab.replay(a.get("user")),
    "send": lambda lab, a: lab.send(a.get("sender"), a.get("recipient"), a.get("text", ""), a.get("payload_b64"),
                                    a.get("filename"), a.get("drop", 0), a.get("reorder", False), a.get("tamper", "none")),
    "crash": lambda lab, a: lab.crash(a.get("user"), a.get("phase", "rotation_committed")),
    "backup": lambda lab, a: lab.backup(bool(a.get("corrupt"))),
    "verify": lambda lab, a: lab.verify_log(a.get("tamper", "none")),
    "detect": lambda lab, a: lab.detect(),
    "watch": lambda lab, a: lab.watch(),
    "adapter": lambda lab, a: lab.adapter(a.get("request")),
    "protected_read": lambda lab, a: lab.adapter_protected_read(a.get("actor"), a.get("asset")),
    "adapter_tamper": lambda lab, a: lab.adapter_tamper(a.get("kind")),
    "attacks": lambda lab, a: lab.adapter_attacks(),
}


def page(token):
    html = resources.files("trustverify").joinpath("lab.html").read_text(encoding="utf-8")
    return html.replace("__LAB_TOKEN__", token)


def make_server(lab, port=8765, token=None):
    token = token or secrets.token_urlsafe(24)

    class Handler(BaseHTTPRequestHandler):
        server_version = "trustverify-lab"
        sys_version = ""
        protocol_version = "HTTP/1.0"

        def log_message(self, *_):
            pass

        def send(self, status, body, content_type="application/json"):
            data = body if isinstance(body, bytes) else json.dumps(body, default=str).encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
                             "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(data)

        def allowed_host(self):
            port_text = str(self.server.server_address[1])
            return self.headers.get("Host", "") in {f"127.0.0.1:{port_text}", f"localhost:{port_text}"}

        def authorized(self):
            return secrets.compare_digest(self.headers.get("X-Lab-Token", ""), token)

        def do_GET(self):
            if not self.allowed_host():
                return self.send(421, {"error": "unexpected Host header"})
            if self.path in {"/", "/index.html"}:
                return self.send(200, page(token).encode(), "text/html; charset=utf-8")
            if self.path == "/api/state":
                if not self.authorized():
                    return self.send(403, {"error": "missing or wrong lab token"})
                with lab.lock:
                    return self.send(200, lab.state())
            return self.send(404, {"error": "not found"})

        def do_POST(self):
            if not self.allowed_host():
                return self.send(421, {"error": "unexpected Host header"})
            if not self.authorized():
                return self.send(403, {"error": "missing or wrong lab token"})
            action = self.path.removeprefix("/api/")
            if action not in ACTIONS:
                return self.send(404, {"error": "unknown action"})
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return self.send(400, {"error": "bad Content-Length"})
            if not 0 <= length <= MAX_BODY:
                return self.send(413, {"error": "request too large"})
            try:
                args = json.loads(self.rfile.read(length) or b"{}")
                if not isinstance(args, dict):
                    raise ValueError("arguments must be a JSON object")
                result = ACTIONS[action](lab, args)
            except (LabError, ValueError, TypeError, KeyError) as exc:
                return self.send(400, {"ok": False, "summary": str(exc) or type(exc).__name__, "outcome": "error"})
            except Denied as exc:
                return self.send(200, {"ok": True, "summary": f"Denied: {exc}", "outcome": "denied",
                                       "detail": {"status": exc.status}})
            except Exception as exc:  # noqa: BLE001 - the lab reports, never crashes
                return self.send(500, {"ok": False, "summary": f"internal error ({type(exc).__name__})",
                                       "outcome": "error"})
            return self.send(200, result)

    ThreadingHTTPServer.daemon_threads = True
    return ThreadingHTTPServer(("127.0.0.1", port), Handler), token


def run(port=8765, open_browser=True):
    print("Starting three sandbox nodes and the grader adapter...", flush=True)
    lab = Lab()
    server, _ = make_server(lab, port)
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    print(json.dumps({"lab": url, "sandbox": str(lab.base), "stop": "Ctrl+C"}), flush=True)
    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()

    def stop_on_sigterm(_signum, _frame):
        raise KeyboardInterrupt  # `kill` takes the same cleanup path as Ctrl+C

    signal.signal(signal.SIGTERM, stop_on_sigterm)
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        lab.shutdown()
    return 0
