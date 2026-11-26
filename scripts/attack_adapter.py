"""Self-assessment: attack track4_service.py the way an automated assessor would.

Runs each request in a fresh process, exactly like the grader, against a throwaway state
directory. Needs only Python 3.12 and pqcrypto. Exit status 0 means every probe held.

    python scripts/attack_adapter.py [--output reports/adapter_attack.json]
"""

import argparse
import base64
import concurrent.futures
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "track4_service.py"


class Harness:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.env = {**os.environ, "TRACK4_STATE_DIR": str(directory), "TMPDIR": str(directory)}

    def raw(self, payload):
        process = subprocess.run([sys.executable, "-B", str(ENTRY)], input=payload, cwd=ROOT, env=self.env,
                                 capture_output=True, timeout=20)
        return process.returncode, process.stdout, process.stderr

    def call(self, **request):
        code, out, err = self.raw(json.dumps(request).encode())
        return code, json.loads(out) if out.strip() else None, out + err


def run():
    results = []

    def probe(name, passed, detail=""):
        results.append({"probe": name, "held": bool(passed), "detail": detail})

    with tempfile.TemporaryDirectory(prefix="tv-attack-") as directory:
        h = Harness(directory)
        maya, peer, gone = "maya", "peer", "disabled-user"
        body, peer_body, marker = (secrets.token_hex(24) for _ in range(3))
        code, ready, _ = h.call(op="setup", owners={"brief": maya, "plan": peer}, contents={"brief": body, "plan": peer_body},
                                disabled=[gone], key_material=marker)
        probe("setup succeeds", code == 0 and ready.get("ready") is True)
        pinned = ready.get("audit_key_sha256")
        outputs = []

        def read(actor, asset, rid=None):
            rid = rid or secrets.token_hex(8)
            code, reply, raw = h.call(op="read", actor=actor, asset=asset, request_id=rid)
            outputs.append(raw)
            return code, reply, rid

        # 1. Malformed input never crashes the process and never discloses content.
        malformed = [b"", b"not json", b"[]", b"null", b'"read"', b"{", "﻿{}".encode(),
                     json.dumps({"op": "read"}).encode(),
                     json.dumps({"op": "read", "actor": maya, "asset": "brief"}).encode(),
                     json.dumps({"op": "read", "actor": maya, "asset": "brief", "request_id": 7}).encode(),
                     json.dumps({"op": "read", "actor": [maya], "asset": "brief", "request_id": "m1"}).encode(),
                     json.dumps({"op": "read", "actor": maya, "asset": {"x": 1}, "request_id": "m2"}).encode(),
                     json.dumps({"op": "read", "actor": "x" * 100_000, "asset": "brief", "request_id": "m3"}).encode(),
                     json.dumps({"op": "read", "actor": maya + "\n", "asset": "brief", "request_id": "m4"}).encode(),
                     json.dumps({"op": "audit"}).encode(), json.dumps({"op": "revoke"}).encode(),
                     json.dumps({"op": "nope"}).encode(), json.dumps({"op": "protected_read"}).encode(),
                     b'{"op":"read","actor":"maya","asset":"brief","request_id":"m5","x":NaN}',
                     b"\xff\xfe\x00"]
        bad = []
        for payload in malformed:
            code, out, err = h.raw(payload)
            outputs.append(out + err)
            try:
                reply = json.loads(out)
            except ValueError:
                reply = None
            if code != 0 or not isinstance(reply, dict) or body.encode() in out:
                bad.append(payload[:40].decode("utf-8", "replace"))
        _, observed, _ = h.call(op="alerts")
        malformed_alerts = [a for a in observed.get("alerts", []) if a.get("rule") == "malformed_request"]
        probe("malformed requests exit 0, disclose no content and raise signed alerts",
              not bad and len(malformed_alerts) == len(malformed),
              "; ".join(bad) or f"{len(malformed_alerts)}/{len(malformed)} malformed alerts")

        # 2. Identity confusion: only the exact owner string is allowed.
        allowed = read(maya, "brief")[1]
        probe("owner read allowed", allowed == {"decision": "allow", "body": body})
        spoofs = ["MAYA", " maya", "maya ", "maya​", "mаya", "", "*", peer, gone]
        leaked = [s for s in spoofs if read(s, "brief")[1].get("decision") != "deny"]
        probe("look-alike and other identities denied", not leaked, repr(leaked))
        probe("unknown asset denied", read(maya, "missing")[1] == {"decision": "deny"})

        # 3. Request-ID replay cannot rewrite the audit trail or bypass revocation.
        _, _, rid = read(maya, "brief")
        h.call(op="revoke", actor=maya)
        _, replay, _ = read(maya, "brief", rid)
        code, recorded, _ = h.call(op="audit", request_id=rid)
        probe("replayed request_id after revocation denied", replay == {"decision": "deny"})
        probe("replay does not change the recorded decision", recorded.get("decision") == "allow")
        _, after, rid2 = read(maya, "brief")
        _, audit2, _ = h.call(op="audit", request_id=rid2)
        probe("revoked owner denied and audited", after == {"decision": "deny"} and audit2.get("decision") == "deny")
        probe("peer unaffected by revocation", read(peer, "plan")[1].get("body") == peer_body)
        h.call(op="revoke", actor=maya)
        probe("repeat revoke keeps the actor revoked", read(maya, "brief")[1] == {"decision": "deny"})

        # 4. Log injection: hostile text stays inside one event's fields.
        injected = 'eve","decision":"allow","actor":"maya'
        _, _, rid3 = read(injected, "plan")
        _, verify, _ = h.call(op="verify_audit", audit_key_sha256=pinned)
        events = [json.loads(line)["body"] for line in (Path(directory) / "adapter-audit.jsonl").read_bytes().splitlines()]
        hit = [e for e in events if e.get("request_id") == rid3]
        probe("injected text cannot forge a second event or change the actor",
              len(hit) == 1 and hit[0]["actor"] == injected and hit[0]["decision"] == "deny" and verify.get("verified") is True)

        # 5. protected_read: KEM interoperability, policy and input validation.
        try:
            from pqcrypto.kem import ml_kem_768
            public, secret = ml_kem_768.generate_keypair()
            key = base64.b64encode(public).decode()
            challenge = secrets.token_hex(16)
            _, ok, _ = h.call(op="protected_read", actor=peer, asset="plan", challenge=challenge, public_key=key)
            shared = ml_kem_768.decrypt(secret, base64.b64decode(ok["ciphertext"]))
            expected = hmac.new(shared, (challenge + peer_body).encode(), hashlib.sha256).hexdigest()
            probe("protected_read proof verifies with the recipient's ML-KEM secret", ok.get("proof") == expected
                  and peer_body not in json.dumps(ok))
            denied = [h.call(op="protected_read", actor=a, asset=s, challenge=c, public_key=k)[1]
                      for a, s, c, k in [(maya, "brief", challenge, key), (peer, "brief", challenge, key),
                                         (peer, "plan", challenge, key[:-4]), (peer, "plan", "", key),
                                         (peer, "plan", challenge, key + "="), (peer, "plan", challenge, "A" * 10)]]
            probe("protected_read denies revoked, non-owner and malformed keys",
                  all(d.get("decision") == "deny" and "ciphertext" not in d for d in denied))
        except ImportError:
            probe("protected_read checks", False, "pqcrypto missing")

        # 6. Concurrency: parallel processes keep one consistent chain.
        with concurrent.futures.ThreadPoolExecutor(8) as pool:
            list(pool.map(lambda i: read(peer, "plan", f"par-{i}"), range(16)))
        _, verify, _ = h.call(op="verify_audit", audit_key_sha256=pinned)
        audits = [h.call(op="audit", request_id=f"par-{i}")[1].get("decision") for i in range(16)]
        probe("parallel requests keep a verifiable chain", verify.get("verified") is True and set(audits) == {"allow"})

        # 7. Tampering with state on disk is detected and fails closed.
        state_path = Path(directory) / "adapter-state.json"
        original = state_path.read_bytes()
        state = json.loads(original)
        state["revoked"] = []
        state["owners"]["plan"] = maya
        state_path.write_bytes(json.dumps(state).encode())
        code, tampered, raw = h.call(op="read", actor=maya, asset="plan", request_id="tamper-1")
        probe("edited state (cleared revocation, changed owner) fails closed",
              code == 0 and tampered.get("decision") == "deny" and "body" not in tampered and peer_body.encode() not in raw)
        state_path.write_bytes(original)
        log = Path(directory) / "adapter-audit.jsonl"
        lines = log.read_bytes().splitlines(keepends=True)
        log.write_bytes(b"".join(lines[:-3]))
        code, cut, _ = h.call(op="read", actor=peer, asset="plan", request_id="tamper-2")
        probe("truncated audit log fails closed", code == 0 and cut.get("decision") == "deny" and "body" not in cut)
        log.write_bytes(b"".join(lines))

        # 8. Detection: probing shows up as signed alert events.
        _, alerts, _ = h.call(op="alerts")
        rules = {a.get("rule") for a in (alerts or {}).get("alerts", [])}
        probe("probing raised alerts", {"cross_owner_access", "revoked_actor_access", "request_id_replay"} <= rules,
              ", ".join(sorted(r for r in rules if r)))

        probe("synthetic key material never printed", not any(marker.encode() in o for o in outputs))

        # 9. Shared temp directory: a pre-planted, other-writable directory is refused.
        with tempfile.TemporaryDirectory() as tmp:
            planted = Path(tmp) / "trustverify-track4"
            planted.mkdir()
            os.chmod(planted, 0o777)
            env = {k: v for k, v in os.environ.items() if k != "TRACK4_STATE_DIR"}
            env["TMPDIR"] = tmp
            process = subprocess.run([sys.executable, "-B", str(ENTRY)], cwd=ROOT, env=env, capture_output=True,
                                     input=json.dumps({"op": "setup", "owners": {}, "contents": {}, "disabled": []}).encode())
            reply = json.loads(process.stdout or b"null") or {}
            mode = planted.stat().st_mode & 0o777
            probe("world-writable pre-planted state directory is not trusted",
                  reply.get("ready") is not True or mode == 0o700, f"mode {oct(mode)}")
        with tempfile.TemporaryDirectory() as tmp:
            env = {k: v for k, v in os.environ.items() if k != "TRACK4_STATE_DIR"}
            env["TMPDIR"] = tmp
            link = Path(tmp) / "elsewhere"
            link.mkdir(mode=0o700)
            (Path(tmp) / "trustverify-track4").symlink_to(link, target_is_directory=True)
            process = subprocess.run([sys.executable, "-B", str(ENTRY)], cwd=ROOT, env=env, capture_output=True,
                                     input=json.dumps({"op": "setup", "owners": {}, "contents": {}, "disabled": []}).encode())
            reply = json.loads(process.stdout or b"null") or {}
            probe("symlinked state directory is refused", reply.get("ready") is not True and not any(link.iterdir()))
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output")
    args = parser.parse_args()
    results = run()
    for r in results:
        print(f"{'HELD' if r['held'] else 'FAIL'}  {r['probe']}" + (f"  ({r['detail']})" if r["detail"] and not r["held"] else ""))
    summary = {"probes": len(results), "held": sum(r["held"] for r in results), "results": results}
    if args.output:
        Path(args.output).write_text(json.dumps(summary, indent=2) + "\n")
    return 0 if summary["held"] == summary["probes"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
