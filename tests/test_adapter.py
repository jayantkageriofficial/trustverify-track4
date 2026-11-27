"""Adapter v1 contract tests. Need only Python 3.12, pqcrypto and pytest."""

import base64
import hashlib
import hmac
import json
import multiprocessing
import os
import subprocess
import sys
from pathlib import Path

import pytest
from pqcrypto.kem import ml_kem_768
from pqcrypto.sign import ml_dsa_65

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "track4_service.py"
MARKER = "synthetic-key-material-7f3a"


def read_log(state):
    return [json.loads(line) for line in (state / "adapter-audit.jsonl").read_bytes().splitlines()]


def write_state(state, document):
    """Attacker who can also read the key directory: write the state and re-tag it."""
    from trustverify.encoding import canonical
    document = {k: v for k, v in document.items() if k != "mac"}
    key = (state / "keys" / "adapter-state.key").read_bytes()
    document["mac"] = hmac.new(key, canonical(document), hashlib.sha256).hexdigest()
    (state / "adapter-state.json").write_text(json.dumps(document))


def write_log(state, records, **changes):
    """Attacker with write access: replace the log and make the state document agree with it."""
    from trustverify.adapter import _record_hash
    from trustverify.encoding import canonical
    data = b"".join(canonical(record) + b"\n" for record in records)
    (state / "adapter-audit.jsonl").write_bytes(data)
    document = json.loads((state / "adapter-state.json").read_bytes())
    document.update(audit_bytes=len(data), seq=len(records), head=_record_hash(records[-1]),
                    setup_record=records[0], **changes)
    write_state(state, document)


def call(state, **request):
    env = {k: v for k, v in os.environ.items() if k != "TRACK4_STATE_DIR"}
    env["TRACK4_STATE_DIR"] = str(state)
    done = subprocess.run([sys.executable, "-B", str(ENTRY)], input=json.dumps(request).encode(),
                          capture_output=True, cwd=ROOT, env=env, timeout=20)
    assert MARKER.encode() not in done.stdout and MARKER.encode() not in done.stderr
    return done.returncode, json.loads(done.stdout)


@pytest.fixture
def state(tmp_path):
    code, reply = call(tmp_path, op="setup", owners={"brief": "maya", "plan": "omar", "memo": "dana"},
                       contents={"brief": "demo note", "plan": "peer body", "memo": "disabled body"},
                       disabled=["dana"], key_material=MARKER)
    assert code == 0 and reply["ready"] is True and len(reply["audit_key_sha256"]) == 64
    (tmp_path / "pinned.txt").write_text(reply["audit_key_sha256"])
    return tmp_path


def test_read_revoke_audit_round_trip(state):
    assert call(state, op="read", actor="maya", asset="brief", request_id="r01")[1] == {
        "decision": "allow", "body": "demo note"}
    assert call(state, op="read", actor="maya", asset="plan", request_id="r02")[1] == {"decision": "deny"}
    assert call(state, op="read", actor="dana", asset="memo", request_id="r03")[1] == {"decision": "deny"}
    call(state, op="revoke", actor="maya")
    assert call(state, op="read", actor="maya", asset="brief", request_id="r04")[1] == {"decision": "deny"}
    assert call(state, op="read", actor="omar", asset="plan", request_id="r05")[1]["decision"] == "allow"
    for request_id, decision in (("r01", "allow"), ("r02", "deny"), ("r03", "deny"), ("r04", "deny")):
        reply = call(state, op="audit", request_id=request_id)[1]
        assert (reply["request_id"], reply["decision"], reply["recorded"]) == (request_id, decision, True)
    assert call(state, op="audit", request_id="never")[1]["recorded"] is False


def test_request_id_cannot_be_reused_to_rewrite_audit(state):
    call(state, op="read", actor="maya", asset="plan", request_id="r10")
    assert call(state, op="read", actor="maya", asset="brief", request_id="r10")[1] == {"decision": "deny"}
    assert call(state, op="audit", request_id="r10")[1]["decision"] == "deny"


def test_protected_read_proof_verifies_with_recipient_secret(state):
    public_key, secret_key = ml_kem_768.generate_keypair()
    challenge = "fresh-challenge-1"
    code, reply = call(state, op="protected_read", actor="maya", asset="brief", challenge=challenge,
                       public_key=base64.b64encode(public_key).decode())
    assert code == 0 and reply["decision"] == "allow"
    shared = ml_kem_768.decrypt(secret_key, base64.b64decode(reply["ciphertext"]))
    expected = hmac.new(shared, (challenge + "demo note").encode(), hashlib.sha256).hexdigest()
    assert hmac.compare_digest(reply["proof"], expected)
    assert "demo note" not in json.dumps(reply)


@pytest.mark.parametrize("actor,asset,key_bytes", [("omar", "brief", 1184), ("dana", "memo", 1184),
                                                   ("maya", "brief", 32)])
def test_protected_read_denies_without_disclosure(state, actor, asset, key_bytes):
    code, reply = call(state, op="protected_read", actor=actor, asset=asset, challenge="c",
                       public_key=base64.b64encode(os.urandom(key_bytes)).decode())
    assert (code, reply) == (0, {"decision": "deny"})


def test_protected_read_denied_after_revocation(state):
    call(state, op="revoke", actor="maya")
    public_key, _ = ml_kem_768.generate_keypair()
    reply = call(state, op="protected_read", actor="maya", asset="brief", challenge="c",
                 public_key=base64.b64encode(public_key).decode())[1]
    assert reply == {"decision": "deny"}


def test_audit_log_is_signed_and_tamper_evident(state):
    call(state, op="read", actor="maya", asset="brief", request_id="r20")
    assert call(state, op="verify_audit")[1]["verified"] is True
    records = read_log(state)
    records[-1]["body"]["decision"] = "deny"
    write_log(state, records)
    code, reply = call(state, op="verify_audit")
    assert code == 0 and "error" in reply and "verified" not in reply


def test_user_text_cannot_forge_a_second_event(state):
    before = len(read_log(state))
    quoted = 'x","decision":"allow","actor":"omar'
    multiline = 'x"}\n{"op":"read","actor":"omar","decision":"allow'
    call(state, op="read", actor=quoted, asset="plan", request_id="r30")
    call(state, op="read", actor=multiline, asset="plan", request_id="r31")
    records = read_log(state)
    events = [record["body"] for record in records[before:] if record["body"]["op"] == "read"]
    first, second = events
    assert len(events) == 2
    assert (first["actor"], first["decision"]) == (quoted, "deny")
    # Control characters are rejected outright, so no actor is recorded for that request.
    assert (second["actor"], second["decision"], second["reason"]) == (None, "deny", "malformed request")
    assert call(state, op="verify_audit")[1]["verified"] is True


def test_malformed_requests_fail_closed(state, tmp_path_factory):
    assert call(state, op="read", actor=["maya"], asset="brief", request_id="r40")[1] == {"decision": "deny"}
    code, reply = call(state, op="nope")
    assert code == 0 and reply == {"decision": "deny", "error": "unknown op"}
    empty = tmp_path_factory.mktemp("empty")
    assert call(empty, op="read", actor="maya", asset="brief", request_id="r1")[1] == {"decision": "deny"}


def test_setup_resets_previous_state(state):
    call(state, op="revoke", actor="maya")
    call(state, op="setup", owners={"brief": "maya"}, contents={"brief": "v2"}, disabled=[], key_material=MARKER)
    assert call(state, op="read", actor="maya", asset="brief", request_id="r50")[1]["body"] == "v2"


def _resign_with_new_key(state, change):
    """Attacker with write access: edit history, then re-sign it all under a fresh key."""
    from trustverify.adapter import DOMAIN, ZERO, _record_hash
    from trustverify.encoding import b64, canonical
    records = read_log(state)
    public_key, secret_key = ml_dsa_65.generate_keypair()
    previous, decisions = ZERO, {}
    for record in records:
        change(record["body"])
        record["body"]["previous"] = previous
        record["signature"] = b64(ml_dsa_65.sign(secret_key, DOMAIN + canonical(record["body"])))
        previous = _record_hash(record)
        if record["body"].get("request_id"):
            decisions[record["body"]["request_id"]] = record["body"]["decision"]
    write_log(state, records, audit_public=b64(public_key), decisions=decisions)


def test_pinned_fingerprint_detects_a_resigned_log(state):
    call(state, op="read", actor="maya", asset="brief", request_id="r60")
    pinned = (state / "pinned.txt").read_text()
    assert call(state, op="verify_audit", audit_key_sha256=pinned)[1]["anchored"] is True

    def flip(body):
        if body.get("request_id") == "r60":
            body["decision"] = "deny"
    _resign_with_new_key(state, flip)
    # The protected public key rejects substitution even before an operator supplies a pin.
    assert "error" in call(state, op="audit", request_id="r60")[1]
    assert "error" in call(state, op="verify_audit")[1]
    code, reply = call(state, op="verify_audit", audit_key_sha256=pinned)
    assert code == 0 and "protected public key" in reply["error"]


def test_pinned_checkpoint_detects_rewritten_or_truncated_history(state):
    call(state, op="read", actor="maya", asset="brief", request_id="r70")
    checkpoint = call(state, op="verify_audit")[1]
    pin = {"seq": checkpoint["seq"], "head": checkpoint["head"]}
    call(state, op="read", actor="omar", asset="plan", request_id="r71")
    assert call(state, op="verify_audit", checkpoint=pin)[1]["verified"] is True
    write_log(state, read_log(state)[:1])
    code, reply = call(state, op="verify_audit", checkpoint=pin)
    assert code == 0 and "error" in reply


def test_tampered_body_is_never_served(state):
    path = state / "adapter-state.json"
    document = json.loads(path.read_bytes())
    document["contents"]["brief"] = "attacker text"
    path.write_text(json.dumps(document))
    # Untagged edit: the state tag fails and every read fails closed.
    reply = call(state, op="read", actor="maya", asset="brief", request_id="r79")[1]
    assert reply["decision"] == "deny" and "body" not in reply
    # Re-tagged edit (attacker also holds the key directory): the signed content hash still fails.
    write_state(state, document)
    assert call(state, op="read", actor="maya", asset="brief", request_id="r80")[1] == {"decision": "deny"}
    public_key, _ = ml_kem_768.generate_keypair()
    assert call(state, op="protected_read", actor="maya", asset="brief", challenge="c",
                public_key=base64.b64encode(public_key).decode())[1] == {"decision": "deny"}


def test_modified_body_and_cached_hash_are_rejected_before_read(state):
    path = state / "adapter-state.json"
    document = json.loads(path.read_bytes())
    document["contents"]["brief"] = "attacker text"
    document["setup_record"]["body"]["contents_sha256"]["brief"] = hashlib.sha256(b"attacker text").hexdigest()
    write_state(state, document)
    public_key, _ = ml_kem_768.generate_keypair()
    for request in [dict(op="read", actor="maya", asset="brief", request_id="changed-hash"),
                    dict(op="protected_read", actor="maya", asset="brief", challenge="c",
                         public_key=base64.b64encode(public_key).decode())]:
        code, reply = call(state, **request)
        assert code == 0 and "setup signature" in reply["error"] and "body" not in reply


def test_legacy_adapter_public_key_is_bound_to_protected_private_key(state):
    public = state / "keys" / "adapter-audit.pub"
    public.unlink()
    assert call(state, op="read", actor="maya", asset="brief", request_id="upgrade")[1]["body"] == "demo note"
    assert public.exists()
    public.unlink()
    _resign_with_new_key(state, lambda body: None)
    code, reply = call(state, op="read", actor="maya", asset="brief", request_id="forged-upgrade")
    assert code == 0 and "protected signing key" in reply["error"]
    assert not public.exists()


def test_crashed_unacknowledged_tail_is_dropped_and_log_stays_valid(state):
    call(state, op="read", actor="maya", asset="brief", request_id="r90")
    with (state / "adapter-audit.jsonl").open("ab") as stream:
        stream.write(b'{"torn": tru')  # a process died mid-append, before saving state
    assert call(state, op="read", actor="omar", asset="plan", request_id="r91")[1]["decision"] == "allow"
    assert call(state, op="verify_audit", audit_key_sha256=(state / "pinned.txt").read_text())[1]["verified"]


def test_state_document_stays_small_as_the_log_grows(state):
    before = (state / "adapter-state.json").stat().st_size
    for n in range(40):
        call(state, op="read", actor="maya", asset="brief", request_id=f"g{n}")
    # Only the request_id -> decision index grows (tens of bytes per request), not the signatures.
    assert (state / "adapter-state.json").stat().st_size - before < 40 * 64
    assert (state / "adapter-audit.jsonl").stat().st_size > 40 * 4000


def test_probing_raises_signed_alerts(state):
    call(state, op="read", actor="maya", asset="plan", request_id="r100")
    call(state, op="read", actor="maya", asset="brief", request_id="r101")
    call(state, op="read", actor="maya", asset="brief", request_id="r101")
    call(state, op="revoke", actor="maya")
    call(state, op="read", actor="maya", asset="brief", request_id="r102")
    reply = call(state, op="alerts")[1]
    rules = [a["rule"] for a in reply["alerts"]]
    assert rules == ["cross_owner_access", "request_id_replay", "revoked_actor_access"]
    assert call(state, op="audit", request_id="r101")[1]["decision"] == "allow"
    events = [r["body"] for r in read_log(state) if r["body"]["op"] == "alert"]
    assert [e["rule"] for e in events] == rules and call(state, op="verify_audit")[1]["verified"] is True
    # Every alert names the identity, services, supporting events, rule and explanation.
    for alert in reply["alerts"]:
        assert alert["identity"] == "maya" and alert["services"] == ["protected-resource"]
        assert alert["events"] and alert["seq"] in alert["events"] and alert["explanation"]
        assert alert["operation"] == "read" and alert["attack_technique"].startswith("T1")
    cross = reply["alerts"][0]
    assert cross["asset"] == "plan" and cross["related_seq"] in cross["events"]
    decision = next(r["body"] for r in read_log(state) if r["body"]["seq"] == cross["related_seq"])
    assert decision["request_id"] == "r100" and decision["decision"] == "deny"


def test_protected_read_request_id_is_audited(state):
    public_key, _ = ml_kem_768.generate_keypair()
    key = base64.b64encode(public_key).decode()
    assert call(state, op="protected_read", actor="maya", asset="brief", challenge="c", public_key=key,
                request_id="p1")[1]["decision"] == "allow"
    assert call(state, op="audit", request_id="p1")[1] == {"request_id": "p1", "decision": "allow", "recorded": True}


def test_every_request_exits_zero_with_one_json_object(state):
    env = {**os.environ, "TRACK4_STATE_DIR": str(state)}
    for payload in (b"", b"not json", b"[]", b'{"op":"read"}', b'{"op":"read","x":NaN}', b"\xff"):
        done = subprocess.run([sys.executable, "-B", str(ENTRY)], input=payload, capture_output=True,
                              cwd=ROOT, env=env, timeout=20)
        reply = json.loads(done.stdout)
        assert done.returncode == 0 and reply["decision"] == "deny" and "body" not in reply


def test_planted_shared_temp_directory_is_refused(tmp_path):
    env = {k: v for k, v in os.environ.items() if k != "TRACK4_STATE_DIR"}
    env["TMPDIR"] = str(tmp_path)
    planted = tmp_path / "trustverify-track4"
    planted.mkdir()
    planted.chmod(0o777)
    done = subprocess.run([sys.executable, "-B", str(ENTRY)], capture_output=True, cwd=ROOT, env=env, timeout=20,
                          input=json.dumps({"op": "setup", "owners": {}, "contents": {}, "disabled": []}).encode())
    assert json.loads(done.stdout)["ready"] is False and not any(planted.iterdir())


def legacy_state(state):
    call(state, op="read", actor="maya", asset="brief", request_id="before-upgrade")
    call(state, op="revoke", actor="maya")
    path = state / "adapter-state.json"
    document = json.loads(path.read_bytes())
    document.pop("mac")
    document.pop("alerts", None)
    (state / "keys" / "adapter-state.key").unlink()
    path.write_text(json.dumps(document))
    return document


@pytest.mark.parametrize("first", [{"op": "verify_audit"}, {"op": "audit", "request_id": "before-upgrade"},
                                   {"op": "alerts"}, {"op": "read"}])
def test_legacy_migration_commits_even_for_read_only_or_invalid_operations(state, first):
    before = legacy_state(state)
    code, reply = call(state, **first)
    assert code == 0
    if first == {"op": "read"}:
        assert reply["decision"] == "deny" and "error" in reply
    else:
        assert "error" not in reply
        assert json.loads((state / "adapter-state.json").read_bytes())["head"] == before["head"]
    assert "mac" in json.loads((state / "adapter-state.json").read_bytes())
    assert not (state / "keys" / "adapter-state.migration").exists()
    assert call(state, op="read", actor="omar", asset="plan", request_id="after-upgrade")[1]["body"] == "peer body"
    assert call(state, op="read", actor="maya", asset="brief", request_id="revoked-after-upgrade")[1] == {"decision": "deny"}
    assert call(state, op="verify_audit", audit_key_sha256=(state / "pinned.txt").read_text())[1]["verified"]


def crash_migration(state, phase):
    from trustverify import adapter
    original = adapter.atomic_write

    def interrupted(path, data, *args, **kwargs):
        original(path, data, *args, **kwargs)
        if Path(path).name == phase:
            os._exit(77)

    adapter.atomic_write = interrupted
    adapter.dispatch({"op": "verify_audit"}, state)


@pytest.mark.parametrize("phase", ["adapter-state.migration", "adapter-state.key", "adapter-state.json"])
def test_real_process_crash_during_mac_migration_recovers(state, phase):
    before = legacy_state(state)
    process = multiprocessing.get_context("fork").Process(target=crash_migration, args=(state, phase))
    process.start()
    process.join(10)
    assert not process.is_alive() and process.exitcode == 77
    assert call(state, op="verify_audit")[1]["verified"]
    migrated = json.loads((state / "adapter-state.json").read_bytes())
    assert {k: v for k, v in migrated.items() if k != "mac"} == before
    assert not (state / "keys" / "adapter-state.migration").exists()
    assert call(state, op="read", actor="omar", asset="plan", request_id="peer-after-crash")[1]["body"] == "peer body"
    assert call(state, op="read", actor="maya", asset="brief", request_id="revoked-after-crash")[1] == {"decision": "deny"}


def test_interrupted_migration_cannot_retag_modified_legacy_permissions(state):
    legacy_state(state)
    original = (state / "adapter-state.json").read_bytes()
    process = multiprocessing.get_context("fork").Process(
        target=crash_migration, args=(state, "adapter-state.key"))
    process.start()
    process.join(10)
    assert not process.is_alive() and process.exitcode == 77
    changed = json.loads(original)
    changed["revoked"] = []
    (state / "adapter-state.json").write_text(json.dumps(changed))
    reply = call(state, op="read", actor="maya", asset="brief", request_id="forged-recovery")[1]
    assert reply["decision"] == "deny" and "error" in reply and "body" not in reply
    (state / "adapter-state.json").write_bytes(original)
    assert call(state, op="verify_audit")[1]["verified"]


def test_stripped_tag_is_not_treated_as_legacy_state(state):
    path = state / "adapter-state.json"
    document = json.loads(path.read_bytes())
    document.pop("mac")
    path.write_text(json.dumps(document))
    before = path.read_bytes()
    reply = call(state, op="read", actor="maya", asset="brief", request_id="stripped-tag")[1]
    assert reply["decision"] == "deny" and "error" in reply
    assert path.read_bytes() == before


def test_legacy_log_must_verify_before_migration_publishes_key(state):
    legacy_state(state)
    path = state / "adapter-audit.jsonl"
    records = read_log(state)
    signature = records[-1]["signature"]
    records[-1]["signature"] = ("A" if signature[0] != "A" else "B") + signature[1:]
    from trustverify.encoding import canonical
    path.write_bytes(b"".join(canonical(record) + b"\n" for record in records))
    reply = call(state, op="read", actor="omar", asset="plan", request_id="bad-history")[1]
    assert reply["decision"] == "deny" and "error" in reply
    assert not (state / "keys" / "adapter-state.key").exists()
    assert not (state / "keys" / "adapter-state.migration").exists()


def test_early_validation_failures_are_signed_alerts_without_overwriting_decisions(state):
    call(state, op="read", actor="maya", asset="brief", request_id="original")
    env = {**os.environ, "TRACK4_STATE_DIR": str(state)}
    payloads = [b'{"op":"read"}', b'{"op":"read","request_id":[]}',
                b'{"op":"unsupported","actor":"maya","request_id":"original"}',
                b'not-json', b'\xff', b'[]', b'{"op":"read","x":NaN}']
    for payload in payloads:
        done = subprocess.run([sys.executable, "-B", str(ENTRY)], input=payload, capture_output=True,
                              cwd=ROOT, env=env, timeout=20)
        assert done.returncode == 0 and json.loads(done.stdout)["decision"] == "deny"
    operator_view = call(state, op="alerts")[1]
    assert len(operator_view["alerts"]) == len(payloads)
    assert {a["rule"] for a in operator_view["alerts"]} == {"malformed_request"}
    records = read_log(state)
    decisions = {r["body"]["seq"]: r["body"] for r in records if r["body"]["op"] == "invalid_request"}
    assert len(decisions) == len(payloads)
    assert all(a["related_seq"] in decisions for a in operator_view["alerts"])
    assert any(d["requested_op"] == "unsupported" and d["actor"] == "maya" for d in decisions.values())
    assert call(state, op="audit", request_id="original")[1]["decision"] == "allow"
    assert call(state, op="verify_audit")[1]["verified"]
    assert call(state, op="read", actor="omar", asset="plan", request_id="after-probes")[1]["body"] == "peer body"


def test_failed_integrity_checks_never_append_reporting_events(state):
    path = state / "adapter-state.json"
    original = path.read_bytes()
    document = json.loads(path.read_bytes())
    document["revoked"] = ["maya"]
    path.write_text(json.dumps(document))
    before = (state / "adapter-audit.jsonl").read_bytes()
    assert call(state, op="read", actor="maya", asset="brief", request_id="corrupt-state")[1]["decision"] == "deny"
    assert (state / "adapter-audit.jsonl").read_bytes() == before
    path.write_bytes(original)
    records = read_log(state)
    signature = records[-1]["signature"]
    records[-1]["signature"] = ("A" if signature[0] != "A" else "B") + signature[1:]
    from trustverify.encoding import canonical
    log = state / "adapter-audit.jsonl"
    log.write_bytes(b"".join(canonical(record) + b"\n" for record in records))
    before = log.read_bytes()
    assert call(state, op="read")[1]["decision"] == "deny"
    assert log.read_bytes() == before
