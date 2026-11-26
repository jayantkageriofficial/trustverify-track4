from urllib.error import HTTPError
from urllib.request import Request, urlopen
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

import pytest

from trustverify.authority import Denied, NODES
from trustverify.client import Client, Remote
from trustverify.demo import nodes


def test_three_real_http_processes_binding_and_authority_outage(sandbox):
    authority, _, alice, _ = sandbox
    with nodes(authority) as remotes:
        clients = {node: Client(api, alice, authority.trust) for node, api in remotes.items()}
        for node, client in clients.items():
            assert client.call("access")["service"] == NODES[node]
            assert client.directory(alice.device)["owner"] == "alice"
        envelope = clients["node-a"].envelope("access", {})
        with pytest.raises(Denied, match="binding"):
            remotes["node-b"].request(envelope)
        assert remotes["node-a"].request(envelope)["actor"] == "alice"
        bad = Request(remotes["node-a"].url + "/request", data=b'{"device":"alice-device","device":"operator-device"}',
                      headers={"Content-Type": "application/json"})
        with pytest.raises(HTTPError) as failed:
            urlopen(bad, timeout=5)
        assert failed.value.code == 400
        signed = {node: client.envelope("access", {}) for node, client in clients.items()}
        offline = authority.path.with_suffix(".offline")
        authority.path.rename(offline)
        try:
            for node, api in remotes.items():
                with pytest.raises(Denied) as failed:
                    api.request(signed[node])
                assert failed.value.status == 503
        finally:
            offline.rename(authority.path)


@pytest.mark.parametrize("status,method", [(302, "challenge"), (307, "request")])
def test_client_does_not_follow_mock_service_redirects(status, method):
    paths = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            paths.append(self.path)
            if self.path != "/outside":
                self.send_response(status)
                self.send_header("Location", "/outside")
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                body = b'{"nonce":"redirected"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        do_POST = do_GET

    with HTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        try:
            api = Remote(f"http://127.0.0.1:{server.server_address[1]}", "node-a")
            with pytest.raises(Denied, match="redirect"):
                api.challenge() if method == "challenge" else api.request({})
            assert paths == ["/challenge" if method == "challenge" else "/request"]
        finally:
            server.shutdown()
            thread.join(timeout=5)
            assert not thread.is_alive()


def test_unauthenticated_flood_is_throttled_without_locking_out_valid_users(sandbox):
    authority, _, alice, _ = sandbox
    junk = {"node": "node-a", "device": "nobody", "version": 1, "nonce": "x",
            "action": "access", "data": {}, "signature": "AA=="}
    with nodes(authority) as remotes:
        statuses = []
        for _ in range(40):
            with pytest.raises(Denied) as failed:
                remotes["node-a"].request(dict(junk))
            statuses.append(failed.value.status)
        assert 429 in statuses
        assert Client(remotes["node-a"], alice, authority.trust).call("access")["actor"] == "alice"


def test_directory_is_not_an_anonymous_http_endpoint(sandbox):
    authority, _, alice, bob = sandbox
    with nodes(authority) as remotes:
        with pytest.raises(HTTPError) as failed:
            urlopen(remotes["node-a"].url + "/directory/" + bob.device, timeout=5)
        assert failed.value.code == 404
        assert Client(remotes["node-a"], alice, authority.trust).directory(bob.device)["owner"] == "bob"


def test_anonymous_client_naming_admin_cannot_evict_its_pending_challenge(sandbox):
    authority, operator, _, _ = sandbox
    with nodes(authority) as remotes:
        admin = Client(remotes["node-a"], operator.identity, authority.trust)
        pending = admin.envelope("access", {})
        for _ in range(20):
            with urlopen(remotes["node-a"].url + "/challenge?device=operator-device", timeout=5) as reply:
                assert reply.status == 200
        assert admin.api.request(pending)["actor"] == "operator"


def test_stalled_clients_cannot_block_a_node(sandbox):
    import socket
    import time
    from urllib.parse import urlsplit
    authority, _, alice, _ = sandbox
    with nodes(authority) as remotes:
        target = urlsplit(remotes["node-a"].url)
        stalled = []
        for _ in range(8):
            sock = socket.create_connection((target.hostname, target.port), timeout=5)
            sock.sendall(b"POST /request HTTP/1.0\r\nContent-Length: 100\r\n")  # never finishes
            stalled.append(sock)
        try:
            started = time.monotonic()
            assert Client(remotes["node-a"], alice, authority.trust).call("access")["actor"] == "alice"
            assert time.monotonic() - started < 2
            with urlopen(remotes["node-a"].url + "/health", timeout=5) as reply:
                assert "Python" not in reply.headers.get("Server", "")
                assert reply.headers.get("X-Content-Type-Options") == "nosniff"
        finally:
            for sock in stalled:
                sock.close()


def test_connection_capacity_is_a_json_503_that_remote_can_handle(sandbox):
    import json
    import selectors
    import socket
    import subprocess
    import sys
    import time
    from urllib.parse import urlsplit

    authority, _, alice, _ = sandbox
    # Use the production rejection path with a small cap instead of opening 64 stalled sockets.
    code = ("import sys; from trustverify import server; server.MAX_CONNECTIONS=2; "
            "server.serve(sys.argv[1], sys.argv[2], 'node-a', 0)")
    process = subprocess.Popen([sys.executable, "-c", code, str(authority.directory), str(authority.operator)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stalled = []
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            assert selector.select(timeout=10)
        url = json.loads(process.stdout.readline())["url"]
        api = Remote(url, "node-a")
        client = Client(api, alice, authority.trust)
        pending = client.envelope("access", {})
        target = urlsplit(url)
        for _ in range(2):
            sock = socket.create_connection((target.hostname, target.port), timeout=3)
            sock.sendall(b"GET /health HTTP/1.0\r\nX-Test: hold")
            stalled.append(sock)
        for _ in range(50):
            try:
                with urlopen(url + "/health", timeout=3):
                    pass
            except HTTPError as error:
                assert error.code == 503
                assert error.headers.get_content_type() == "application/json"
                assert error.headers.get("X-Content-Type-Options") == "nosniff"
                assert "capacity" in json.load(error)["error"]
                break
            time.sleep(0.01)
        else:
            pytest.fail("connection slots never filled")
        for request in (lambda: api.challenge(alice.device), lambda: api.request(pending)):
            with pytest.raises(Denied, match="capacity") as denied:
                request()
            assert denied.value.status == 503
        for sock in stalled:
            sock.sendall(b"\r\n\r\n")
            while sock.recv(4096):
                pass
            sock.close()
        stalled.clear()
        assert api.request(pending)["actor"] == "alice"
    finally:
        for sock in stalled:
            sock.close()
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()
