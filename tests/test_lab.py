"""The interactive lab drives the real prototype; check every action and the server guards."""

import base64
import json
import threading
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

pytest.importorskip("cryptography")


@pytest.fixture(scope="module")
def lab_server(tmp_path_factory):
    from trustverify.lab import Lab
    from trustverify.ui import make_server
    lab = Lab(tmp_path_factory.mktemp("lab"))
    server, token = make_server(lab, 0)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}", token, lab
    server.shutdown()
    server.server_close()
    lab.shutdown()


def call(server, action, token=None, **args):
    url, real_token, _ = server
    request = Request(f"{url}/api/{action}", data=json.dumps(args).encode(),
                      headers={"Content-Type": "application/json", "X-Lab-Token": token or real_token})
    try:
        with urlopen(request, timeout=120) as reply:
            return json.load(reply)
    except HTTPError as exc:
        with exc:
            return {"http_status": exc.code, **json.load(exc)}


def test_page_and_api_require_the_launch_token_and_local_host(lab_server):
    url, token, _ = lab_server
    with urlopen(url + "/", timeout=10) as reply:
        page = reply.read().decode()
    assert token in page and "TrustVerify Lab" in page
    assert call(lab_server, "detect", token="wrong")["http_status"] == 403
    with pytest.raises(HTTPError) as rebound:
        urlopen(Request(url + "/", headers={"Host": "evil.example:80"}), timeout=10)
    assert rebound.value.code == 421


def test_identity_lifecycle_actions(lab_server):
    assert call(lab_server, "access", user="alice", node="node-c")["outcome"] == "allowed"
    rotated = call(lab_server, "rotate", user="alice")
    assert set(rotated["detail"]["old_key_on_each_node"].values()) == {"rejected old key"}
    assert call(lab_server, "access", user="alice", key="retired")["outcome"] == "denied"
    revoked = call(lab_server, "revoke", user="bob")
    assert all(v["rejected"] for v in revoked["detail"]["per_node"].values())
    assert revoked["detail"]["other_users"]["alice"] == "still has access"
    assert call(lab_server, "access", user="bob", key="revoked")["outcome"] == "denied"
    assert call(lab_server, "enroll", user="bob")["ok"]
    assert call(lab_server, "access", user="bob")["outcome"] == "allowed"
    assert call(lab_server, "replay", user="alice")["outcome"] == "denied"
    assert call(lab_server, "grant", user="carol", service="billing", mode="self_approved")["outcome"] == "denied"
    injected = call(lab_server, "access", user="alice", note='x\n{"actor":"operator"}')
    assert injected["detail"]["recorded_event"]["actor"] == "alice"
    assert call(lab_server, "enroll", user="bad name!")["http_status"] == 400


def test_messages_files_and_attacks_on_delivery(lab_server):
    sent = call(lab_server, "send", sender="alice", recipient="bob", text="hello bob", drop=1, reorder=True)
    assert sent["outcome"] == "allowed" and sent["detail"]["text"] == "hello bob" and sent["detail"]["matches_sent"]
    blob = bytes(range(256)) * 300
    file_sent = call(lab_server, "send", sender="bob", recipient="alice", payload_b64=base64.b64encode(blob).decode(),
                     filename="data.bin", drop=2)
    assert file_sent["detail"]["matches_sent"] and file_sent["detail"]["text"] is None
    for tamper in ("recipient", "corrupt", "incomplete"):
        assert call(lab_server, "send", sender="alice", recipient="bob", text="x", tamper=tamper)["outcome"] == "denied"


def test_recovery_integrity_and_detection(lab_server):
    crashed = call(lab_server, "crash", user="alice", phase="rotation_committed")
    assert crashed["outcome"] == "recovered" and call(lab_server, "access", user="alice")["outcome"] == "allowed"
    assert call(lab_server, "backup", corrupt=True)["outcome"] == "denied"
    assert call(lab_server, "backup")["outcome"] == "allowed"
    assert call(lab_server, "verify")["outcome"] == "verified"
    for tamper in ("edit", "actor", "truncate", "reorder"):
        assert call(lab_server, "verify", tamper=tamper)["outcome"] == "rejected"
    call(lab_server, "grant", user="carol", service="secrets", mode="unapproved")
    call(lab_server, "access", user="carol", node="node-a")
    call(lab_server, "access", user="carol", node="node-c")
    rules = {a["rule"] for a in call(lab_server, "detect")["detail"]["alerts"]}
    assert {"unapproved_privilege_grant", "revoked_credential_use"} <= rules
    live = call(lab_server, "watch")["detail"]["alerts"]
    assert any(a["rule"] == "unapproved_privilege_grant" and a["response"]["status"] == "applied" for a in live)
    assert call(lab_server, "access", user="carol", node="node-c")["outcome"] == "denied"


def test_grader_adapter_console(lab_server):
    assert call(lab_server, "adapter", request={"op": "read", "actor": "maya", "asset": "brief", "request_id": "t1"})[
        "detail"]["reply"]["body"] == "Maya's protected brief"
    assert call(lab_server, "adapter", request="garbage")["detail"]["exit_code"] == 0
    assert call(lab_server, "protected_read", actor="omar", asset="plan")["detail"]["proof_verified"] is True
    assert call(lab_server, "protected_read", actor="omar", asset="brief")["outcome"] == "denied"
    assert call(lab_server, "adapter_tamper", kind="clear_revocations")["outcome"] == "deny"
    state = json.loads(urlopen(Request(lab_server[0] + "/api/state", headers={"X-Lab-Token": lab_server[1]}),
                               timeout=10).read())
    assert {u["name"] for u in state["users"]} >= {"alice", "bob", "carol"} and state["events"]
    assert "frontend" in {s for u in state["users"] for s in u["permissions"]}
    assert call(lab_server, "reset")["ok"]
    assert call(lab_server, "adapter", request={"op": "read", "actor": "maya", "asset": "brief", "request_id": "t1"})[
        "detail"]["reply"]["decision"] == "allow"
