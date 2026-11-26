"""Interactive lab: drives the real prototype so people can try their own scenarios.

Everything runs against a throwaway sandbox: three real loopback HTTP node processes over
one authority, fresh synthetic identities, and a separate grader-adapter state directory.
Nothing here is on the grading path; ``track4_service.py`` never imports it.

Every action returns ``{"ok", "summary", "detail"}``. A denial is often the expected,
secure outcome, so ``ok`` means "the action ran", and ``outcome`` says what the system did.
"""

import base64
import contextlib
import copy
import hashlib
import hmac
import json
import multiprocessing
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from cryptography.exceptions import InvalidSignature

from .authority import NODES, Authority, Denied, verify_log
from .client import Client, Identity
from .crypto import b64, canonical, public, unb64
from .demo import _crash_rotation, nodes
from .detector import analyze
from .protocol import Receiver, encrypt, recover_packets
from .watch import Watcher

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "track4_service.py"
ATTACKS = ROOT / "scripts" / "attack_adapter.py"
SEED_USERS = {"alice": list(NODES.values()), "bob": list(NODES.values()), "carol": ["frontend"]}
SERVICE_NODE = {service: node for node, service in NODES.items()}
MAX_PAYLOAD = 1024 * 1024


class LabError(ValueError):
    """A request to the lab itself was invalid (unknown user, bad option)."""


def _name(value, field="name"):
    if not isinstance(value, str) or not value.isascii() or not value.isalnum() or not 1 <= len(value) <= 32:
        raise LabError(f"{field} must be 1-32 letters or digits")
    return value.lower()


def _service(value):
    if value not in SERVICE_NODE:
        raise LabError("service must be one of " + ", ".join(SERVICE_NODE))
    return value


def _node(value):
    if value not in NODES:
        raise LabError("node must be one of " + ", ".join(NODES))
    return value


class Lab:
    def __init__(self, root=None):
        self.base = Path(root) if root else Path(tempfile.mkdtemp(prefix="trustverify-lab-"))
        self.lock = threading.RLock()
        self.stack = None
        self.generation = 0
        self.reset()

    # ----- lifecycle -------------------------------------------------------------------

    def reset(self):
        with self.lock:
            self.close()
            self.generation += 1
            self.root = self.base / f"session-{self.generation}"
            self.root.mkdir(parents=True, mode=0o700)
            self.history = []
            self.admin = Identity.generate("operator-device")
            self.officer = Identity.generate("officer-device")
            self.authority = Authority.initialize(
                self.root / "authority", self.root / "operator", public(self.admin.key),
                [("security-officer", self.officer.device, public(self.officer.key))])
            self.stack = contextlib.ExitStack()
            self.remotes = self.stack.enter_context(nodes(self.authority))
            self.operator = Client(self.remotes["node-a"], self.admin, self.authority.trust)
            self.approver = Client(self.remotes["node-b"], self.officer, self.authority.trust)
            self.users = {}
            self.watcher = Watcher(self.authority, self.approver, self.root / "live-alerts.jsonl")
            self.adapter_dir = self.root / "adapter"
            self.adapter_dir.mkdir(mode=0o700)
            self.adapter_pin = None
            for owner, services in SEED_USERS.items():
                self._enroll(owner)
                for service in services:
                    self._grant(owner, service)
            self._adapter_seed()
            return self._result(True, "Fresh sandbox: three nodes running, alice, bob and carol enrolled.",
                                "reset", {"directory": str(self.root)})

    def close(self):
        with self.lock:
            if self.stack is not None:
                self.stack.close()
                self.stack = None

    def shutdown(self):
        self.close()
        shutil.rmtree(self.base, ignore_errors=True)

    # ----- helpers ---------------------------------------------------------------------

    def _result(self, ok, summary, action, detail=None, outcome=None):
        entry = {"ok": ok, "action": action, "summary": summary, "outcome": outcome or ("done" if ok else "error"),
                 "detail": detail or {}, "at": time.time()}
        self.history.append({k: entry[k] for k in ("action", "summary", "outcome", "at")})
        self.history = self.history[-100:]
        return entry

    def _user(self, owner):
        owner = _name(owner, "user")
        if owner not in self.users:
            raise LabError(f"unknown user {owner}; enroll them first")
        return self.users[owner]

    def _client(self, owner, node="node-a", identity=None):
        user = self._user(owner)
        return Client(self.remotes[_node(node)], identity or user["identity"], self.authority.trust)

    def _enroll(self, owner):
        user = self.users.get(owner)
        count = user["devices"] + 1 if user else 1
        identity = Identity.generate(f"{owner}-device-{count}")
        self.operator.call("enroll", **identity.enrollment(owner))
        self.users[owner] = {"identity": identity, "retired": [], "devices": count,
                             "revoked": user["revoked"] if user else []}
        return identity

    def _grant(self, owner, service):
        approval = self.approver.call("approve", owner=owner, service=service)["approval"]
        return self.operator.call("grant", owner=owner, service=service, approval=approval)

    @staticmethod
    def _denied(callback):
        try:
            return None, callback()
        except Denied as exc:
            return {"status": exc.status, "reason": str(exc)}, None
        except ValueError as exc:
            return {"status": None, "reason": str(exc)}, None

    # ----- views -----------------------------------------------------------------------

    def state(self):
        with self.lock:
            users = []
            for owner, user in sorted(self.users.items()):
                identity = user["identity"]
                users.append({"name": owner, "device": identity.device, "version": identity.version,
                              "retired_versions": [i.version for i in user["retired"]],
                              "revoked_devices": user["revoked"]})
            records = self.authority.export_log()["records"]
            permissions = {}
            for record in records:
                body = record["body"]
                if body["outcome"] != "allowed" or body["action"] not in {"grant", "remove_permission"}:
                    continue
                details = body.get("details", {})
                owner, service = details.get("owner"), details.get("target_service")
                if owner and service:
                    permissions.setdefault(owner, set())
                    (permissions[owner].add if body["action"] == "grant" else permissions[owner].discard)(service)
            for entry in users:
                entry["permissions"] = sorted(permissions.get(entry["name"], ()))
            events = [{key: record["body"].get(key) for key in
                       ("seq", "observed_at", "node", "service", "actor", "device", "action", "outcome")}
                      | {"reason": record["body"].get("details", {}).get("reason")}
                      for record in records[-40:]]
            return {"nodes": [{"node": node, "service": service, "url": self.remotes[node].url}
                              for node, service in NODES.items()],
                    "users": users, "services": list(SERVICE_NODE), "events": events[::-1],
                    "event_count": len(records), "history": self.history[::-1][:30],
                    "adapter": self._adapter_overview(),
                    "attack_suite_available": ATTACKS.exists() and ENTRY.exists()}

    # ----- identity and access ---------------------------------------------------------

    def enroll(self, user):
        with self.lock:
            owner = _name(user, "user")
            fresh = owner not in self.users
            identity = self._enroll(owner)
            if fresh:
                self._grant(owner, "frontend")
            return self._result(True, f"Enrolled {identity.device} for {owner}" +
                                (" with approved frontend access." if fresh else " (re-enrolment, new device key)."),
                                "enroll", {"device": identity.device})

    def grant(self, user, service, mode="approved"):
        with self.lock:
            owner, service = _name(user, "user"), _service(service)
            self._user(owner)
            if mode == "approved":
                self._grant(owner, service)
                return self._result(True, f"{service} granted to {owner} with a security-officer approval.", "grant",
                                    outcome="allowed")
            if mode == "self_approved":
                approval = self.operator.call("approve", owner=owner, service=service)["approval"]
                denied, _ = self._denied(lambda: self.operator.call("grant", owner=owner, service=service,
                                                                     approval=approval))
                return self._result(True, "Grant refused: the two-person rule blocks an admin approving their own grant."
                                    if denied else "Self-approved grant was accepted (unexpected).", "grant",
                                    {"denial": denied}, "denied" if denied else "allowed")
            if mode == "unapproved":
                self.operator.call("grant", owner=owner, service=service)
                return self._result(True, f"{service} granted to {owner} with no approval. Run the detector or live "
                                    "watch to see it flagged and contained.", "grant", outcome="allowed")
            raise LabError("mode must be approved, self_approved or unapproved")

    def access(self, user, node="node-a", note="", key="current"):
        with self.lock:
            user_data = self._user(user)
            identity = user_data["identity"]
            if key == "retired":
                if not user_data["retired"]:
                    raise LabError("this user has no retired key yet; rotate first")
                identity = user_data["retired"][-1]
            elif key == "revoked":
                if not user_data.get("revoked_identity"):
                    raise LabError("this user has no revoked device yet; revoke first")
                identity = user_data["revoked_identity"]
            if not isinstance(note, str) or len(note) > 2048:
                raise LabError("note must be text, at most 2048 characters")
            started = time.perf_counter()
            denied, reply = self._denied(lambda: self._client(user, node, identity).call("access", note=note))
            elapsed = round((time.perf_counter() - started) * 1000, 1)
            record = self.authority.export_log()["records"][-1]["body"]
            detail = {"node": node, "service": NODES[node], "device": identity.device, "version": identity.version,
                      "latency_ms": elapsed, "recorded_event": {k: record.get(k) for k in
                                                                ("seq", "actor", "action", "outcome", "details")}}
            if denied:
                return self._result(True, f"{NODES[node]} denied {identity.device} v{identity.version}: "
                                    f"{denied['reason']}", "access", detail | {"denial": denied}, "denied")
            return self._result(True, f"{NODES[node]} allowed {reply['actor']} in {elapsed} ms.", "access",
                                detail, "allowed")

    def rotate(self, user):
        with self.lock:
            from .crypto import new_identity
            data = self._user(user)
            old = data["identity"]
            key = new_identity()
            reply = self._client(user, "node-a").call("rotate", **old.rotation(key))
            data["retired"].append(old)
            data["identity"] = Identity(old.device, key, reply["version"])
            probes = {}
            for node in NODES:
                denied, _ = self._denied(lambda node=node: self._client(user, node, old).call("access"))
                probes[node] = "rejected old key" if denied else "ACCEPTED old key"
            return self._result(True, f"{old.device} rotated to v{reply['version']}; every node now rejects v{old.version}.",
                                "rotate", {"old_key_on_each_node": probes, "grace_period_seconds": 0})

    def revoke(self, user):
        with self.lock:
            data = self._user(user)
            identity = data["identity"]
            started = time.perf_counter()
            self.operator.call("revoke", device=identity.device)
            committed = time.perf_counter()
            enforced = {}
            for node in NODES:
                denied, _ = self._denied(lambda node=node: self._client(user, node, identity).call("access"))
                enforced[node] = {"rejected": bool(denied),
                                  "ms_after_commit": round((time.perf_counter() - committed) * 1000, 1)}
            data["revoked"].append(identity.device)
            data["revoked_identity"] = identity
            others = {}
            for owner in self.users:
                if owner != _name(user) and self.users[owner]["identity"].device not in self.users[owner]["revoked"]:
                    denied, _ = self._denied(lambda owner=owner: self._client(owner, "node-a").call("access"))
                    others[owner] = "still has access" if not denied else denied["reason"]
            slowest = max(v["ms_after_commit"] for v in enforced.values())
            return self._result(True, f"{identity.device} revoked; last node enforced it {slowest} ms after commit "
                                f"(request to commit {round((committed - started) * 1000, 1)} ms). Re-enrol to restore "
                                "the owner.", "revoke", {"per_node": enforced, "other_users": others})

    def replay(self, user):
        with self.lock:
            client = self._client(user, "node-b")
            envelope = client.envelope("access", {})
            client.api.request(envelope)
            denied, _ = self._denied(lambda: client.api.request(envelope))
            return self._result(True, "Replayed signed request rejected: " + denied["reason"] if denied
                                else "Replay was accepted (unexpected).", "replay", {"denial": denied},
                                "denied" if denied else "allowed")

    # ----- protected messages and files ------------------------------------------------

    def send(self, sender, recipient, text="", payload_b64=None, filename=None, drop=0, reorder=False,
             tamper="none"):
        with self.lock:
            source, target = self._user(sender), self._user(recipient)
            if payload_b64:
                plaintext = unb64(payload_b64)
            else:
                if not isinstance(text, str) or not text:
                    raise LabError("enter a message or choose a file")
                plaintext = text.encode("utf-8")
            if len(plaintext) > MAX_PAYLOAD:
                raise LabError("payload must be at most 1 MiB")
            if type(drop) is not int or not 0 <= drop <= 8:
                raise LabError("drop must be 0-8 fragments")
            sid, rid = source["identity"], target["identity"]
            sender_client = self._client(sender, "node-a")
            receiver_client = self._client(recipient, "node-b")
            receiver = Receiver(self.root / f"inbox-{_name(recipient)}", rid.device, rid.version, rid.key)
            steps = []
            try:
                recipient_public = sender_client.directory(rid.device)["public"]
                sender_public = receiver_client.directory(sid.device)["public"]
                offer = receiver.offer(sid.device, sid.version, sender_public)
                steps.append(f"{rid.device} signed a one-use offer with fresh ML-KEM-768 + X25519 keys")
                started = time.perf_counter()
                manifest, packets = encrypt(sid.key, offer, recipient_public, plaintext)
                steps.append(f"{sid.device} encrypted {len(plaintext):,} bytes with hybrid HPKE into "
                             f"{len(packets)} fragment(s) and signed the manifest "
                             f"({round((time.perf_counter() - started) * 1000, 1)} ms)")
                if tamper == "recipient":
                    changed = copy.deepcopy(manifest)
                    changed["offer"]["binding"]["recipient_device"] = "mallory-device"
                    denied, _ = self._denied(lambda: receiver.receive(changed, packets))
                    return self._result(True, "Receiver rejected the message whose recipient binding was changed: "
                                        + (denied or {}).get("reason", "accepted (unexpected)"), "send",
                                        {"steps": steps}, "denied" if denied else "allowed")
                transfer = sender_client.call("start", manifest=manifest)["transfer"]
                for index, data in packets:
                    api = self.remotes[list(NODES)[index % 3]]
                    Client(api, sid, self.authority.trust).call("put_chunk", transfer=transfer, index=index, body=b64(data))
                sender_client.call("finish", transfer=transfer)
                steps.append(f"fragments uploaded across all three nodes (transfer {transfer[:8]}...)")
                downloaded = receiver_client.call("fetch", transfer=transfer)

                def fetch(index):
                    api = self.remotes[list(NODES)[index % 3]]
                    return unb64(Client(api, rid, self.authority.trust).call("read_chunk", transfer=transfer,
                                                                           index=index)["body"])

                if tamper == "incomplete":
                    partial = [(i, fetch(i)) for i in range(manifest["chunks"])][:-1]
                    denied, _ = self._denied(lambda: receiver.receive(downloaded, partial))
                    return self._result(True, "Incomplete message discarded, nothing delivered: "
                                        + (denied or {}).get("reason", "delivered (unexpected)"), "send",
                                        {"steps": steps}, "denied" if denied else "allowed")
                dropped = set(range(min(drop, manifest["chunks"])))
                incoming = recover_packets(fetch, manifest["chunks"], drop=dropped, reverse=bool(reorder))
                if dropped or reorder:
                    steps.append(f"transport dropped {len(dropped)} fragment(s)" + (" and reversed order" if reorder else "")
                                 + "; receiver re-fetched and reassembled")
                if tamper == "corrupt":
                    index, data = incoming[0]
                    incoming[0] = (index, bytes([data[0] ^ 1]) + data[1:])
                    denied, _ = self._denied(lambda: receiver.receive(downloaded, incoming))
                    return self._result(True, "Corrupted fragment detected, message discarded: "
                                        + (denied or {}).get("reason", "delivered (unexpected)"), "send",
                                        {"steps": steps}, "denied" if denied else "allowed")
                delivered = receiver.receive(downloaded, incoming)
                steps.append("receiver verified the signed manifest and ciphertext hash, decrypted, and stored it "
                             "under its AES-256-GCM inbox key; the ephemeral secret was discarded")
                duplicate, _ = self._denied(lambda: receiver.receive(downloaded, incoming))
                steps.append("delivering the same message again: " + (duplicate or {}).get("reason", "accepted (unexpected)"))
                preview = delivered.decode("utf-8", "replace") if not payload_b64 else None
                return self._result(True, f"{rid.device} received {len(delivered):,} authenticated bytes from "
                                    f"{sid.device}.", "send", {
                                        "steps": steps, "sha256": hashlib.sha256(delivered).hexdigest(),
                                        "matches_sent": delivered == plaintext, "text": preview,
                                        "filename": filename, "ciphertext_bytes": manifest["ciphertext_bytes"]},
                                    "allowed")
            except Denied as exc:
                return self._result(True, f"Transfer denied by the authority: {exc}", "send",
                                    {"steps": steps, "status": exc.status}, "denied")
            finally:
                receiver.close()

    # ----- recovery and integrity ------------------------------------------------------

    def crash(self, user, phase="rotation_committed"):
        with self.lock:
            from .crypto import new_identity
            if phase not in {"rotation_staged", "rotation_committed"}:
                raise LabError("phase must be rotation_staged or rotation_committed")
            data = self._user(user)
            old = data["identity"]
            key = new_identity()
            child = multiprocessing.get_context("fork").Process(
                target=_crash_rotation, args=(self.authority.directory, self.authority.operator, old, key, phase))
            child.start()
            child.join(15)
            if child.is_alive():
                child.kill()
                child.join()
                raise LabError("crash simulation timed out")
            recovered = self.authority.recover()
            version = self.authority.directory_entry(old.device)["entry"]["version"]
            if version != old.version:
                data["retired"].append(old)
                data["identity"] = Identity(old.device, key, version)
            denied, _ = self._denied(lambda: self._client(user, "node-c").call("access"))
            revoked_still = {}
            for owner, entry in self.users.items():
                if entry.get("revoked_identity"):
                    d, _ = self._denied(lambda owner=owner, entry=entry:
                                        self._client(owner, "node-a", entry["revoked_identity"]).call("access"))
                    revoked_still[entry["revoked_identity"].device] = "still revoked" if d else "ACCEPTED"
            where = "before" if phase == "rotation_staged" else "after"
            return self._result(True, f"Rotation process killed {where} commit (exit {child.exitcode}); recovery kept "
                                f"v{version} for {old.device}, which {'works' if not denied else 'is denied'}.",
                                "crash", {"recovered": recovered, "consistent_version": version,
                                          "revoked_devices": revoked_still}, "recovered")

    def backup(self, corrupt=False):
        with self.lock:
            path = self.root / f"backup-{int(time.time() * 1000)}.bin"
            self.authority.backup(path)
            if corrupt:
                damaged = bytearray(path.read_bytes())
                damaged[len(damaged) // 2] ^= 1
                path.write_bytes(bytes(damaged))
            denied, reply = self._denied(lambda: self.authority.restore(path))
            if corrupt:
                return self._result(True, "Damaged backup rejected; nothing restored: " + (denied or {}).get(
                    "reason", "restored (unexpected)"), "backup", {"denial": denied}, "denied" if denied else "allowed")
            self.authority.recover()
            return self._result(True, "Backup verified and restored." if not denied else
                                f"Restore refused: {denied['reason']}", "backup", {"restore": reply},
                                "allowed" if not denied else "denied")

    def verify_log(self, tamper="none"):
        with self.lock:
            exported = self.authority.export_log()
            records = copy.deepcopy(exported["records"])
            retained = json.loads((self.authority.operator / "checkpoint.json").read_bytes())
            note = "untouched export"
            if tamper == "edit":
                target = next(r for r in records if r["body"]["outcome"] == "denied") if any(
                    r["body"]["outcome"] == "denied" for r in records) else records[-1]
                target["body"]["outcome"] = "allowed"
                note = f"changed event {target['body']['seq']} from denied to allowed"
            elif tamper == "actor":
                records[-1]["body"]["actor"] = "operator"
                note = f"changed the actor of event {records[-1]['body']['seq']} to operator"
            elif tamper == "truncate":
                records = records[:-3]
                note = "dropped the last three events"
            elif tamper == "reorder":
                records[-1], records[-2] = records[-2], records[-1]
                note = "swapped the last two events"
            elif tamper != "none":
                raise LabError("tamper must be none, edit, actor, truncate or reorder")
            try:
                head = verify_log(records, self.authority.trust, retained)
                return self._result(True, f"Log verified: {len(records)} signed events chain to the retained "
                                    f"checkpoint ({note}).", "verify", {"head": head}, "verified")
            except (ValueError, KeyError, InvalidSignature) as exc:
                return self._result(True, f"Verification failed as it should ({note}): "
                                    f"{exc or 'signature does not match the event'}", "verify",
                                    {"tamper": tamper}, "rejected")

    # ----- detection -------------------------------------------------------------------

    def detect(self):
        with self.lock:
            exported = self.authority.export_log()
            verify_log(exported["records"], self.authority.trust, exported["checkpoint"])
            result = analyze([r["body"] for r in exported["records"]])
            return self._result(True, f"Detector found {len(result['alerts'])} alert(s) in {len(exported['records'])} "
                                "verified events.", "detect", {"alerts": result["alerts"],
                                                                "notices": result.get("notices", [])[:20]})

    def watch(self):
        with self.lock:
            new = self.watcher.poll()
            contained = [a for a in new if a["response"].get("status") == "applied"]
            return self._result(True, f"Live watch: {len(new)} new alert(s), {len(contained)} contained automatically.",
                                "watch", {"alerts": new})

    # ----- grader adapter --------------------------------------------------------------

    def _adapter_call(self, request):
        env = {**os.environ, "TRACK4_STATE_DIR": str(self.adapter_dir), "TMPDIR": str(self.adapter_dir)}
        payload = request if isinstance(request, bytes) else json.dumps(request).encode()
        started = time.perf_counter()
        done = subprocess.run([sys.executable, "-B", str(ENTRY)], input=payload, capture_output=True,
                              cwd=ROOT, env=env, timeout=30)
        elapsed = round((time.perf_counter() - started) * 1000, 1)
        try:
            reply = json.loads(done.stdout)
        except ValueError:
            reply = {"raw_stdout": done.stdout.decode("utf-8", "replace")[:2000]}
        return {"exit_code": done.returncode, "reply": reply, "stderr": done.stderr.decode("utf-8", "replace")[:2000],
                "ms": elapsed}

    def _adapter_seed(self):
        result = self._adapter_call({"op": "setup", "owners": {"brief": "maya", "plan": "omar", "memo": "lena"},
                                     "contents": {"brief": "Maya's protected brief", "plan": "Omar's launch plan",
                                                  "memo": "Lena's memo"},
                                     "disabled": ["lena"], "key_material": "synthetic-lab-only"})
        self.adapter_pin = result["reply"].get("audit_key_sha256")

    def _adapter_overview(self):
        path = self.adapter_dir / "adapter-state.json"
        if not path.exists():
            return {"ready": False}
        state = json.loads(path.read_bytes())
        return {"ready": True, "owners": state.get("owners", {}), "disabled": state.get("disabled", []),
                "revoked": state.get("revoked", []), "events": state.get("seq"), "pin": self.adapter_pin}

    def adapter(self, request):
        with self.lock:
            if isinstance(request, str):
                payload = request.encode("utf-8")
            elif isinstance(request, dict):
                payload = json.dumps(request).encode()
            else:
                raise LabError("request must be a JSON object or raw text")
            if len(payload) > 2 * 1024 * 1024:
                raise LabError("request too large for the lab")
            result = self._adapter_call(payload)
            try:
                op = json.loads(payload).get("op")
            except (ValueError, AttributeError):
                op = None
            if op == "setup" and result["reply"].get("ready"):
                self.adapter_pin = result["reply"].get("audit_key_sha256")
            reply = result["reply"]
            outcome = reply.get("decision") or ("ready" if reply.get("ready") else "error" if "error" in reply else "done")
            return self._result(True, f"Adapter {op or 'request'} -> exit {result['exit_code']}, "
                                f"{json.dumps(reply)[:160]}", "adapter", result, outcome)

    def adapter_protected_read(self, actor, asset):
        with self.lock:
            from pqcrypto.kem import ml_kem_768
            public_key, secret_key = ml_kem_768.generate_keypair()
            challenge = base64.b16encode(os.urandom(16)).decode().lower()
            result = self._adapter_call({"op": "protected_read", "actor": actor, "asset": asset, "challenge": challenge,
                                         "public_key": base64.b64encode(public_key).decode()})
            reply = result["reply"]
            if reply.get("decision") != "allow":
                return self._result(True, f"protected_read denied for {actor} / {asset}.", "protected_read", result,
                                    "denied")
            shared = ml_kem_768.decrypt(secret_key, base64.b64decode(reply["ciphertext"]))
            owners = json.loads((self.adapter_dir / "adapter-state.json").read_bytes())
            body = owners["contents"].get(asset, "")
            expected = hmac.new(shared, (challenge + body).encode(), hashlib.sha256).hexdigest()
            return self._result(True, "protected_read allowed; the lab decapsulated the ML-KEM-768 ciphertext with its "
                                "secret key and the HMAC proof " + ("matches." if expected == reply["proof"] else
                                                                     "DOES NOT match."),
                                "protected_read", result | {"proof_verified": expected == reply["proof"],
                                                            "ciphertext_bytes": len(base64.b64decode(reply["ciphertext"]))},
                                "allowed")

    def adapter_tamper(self, kind):
        with self.lock:
            path = self.adapter_dir / "adapter-state.json"
            log = self.adapter_dir / "adapter-audit.jsonl"
            if kind == "clear_revocations":
                state = json.loads(path.read_bytes())
                state["revoked"], state["owners"]["plan"] = [], "maya"
                path.write_text(json.dumps(state))
                note = "cleared every revocation and made maya the owner of plan, directly on disk"
            elif kind == "truncate_log":
                lines = log.read_bytes().splitlines(keepends=True)
                log.write_bytes(b"".join(lines[:-1]))
                note = "cut the last line off the audit log"
            else:
                raise LabError("kind must be clear_revocations or truncate_log")
            probe = self._adapter_call({"op": "read", "actor": "maya", "asset": "plan", "request_id": os.urandom(6).hex()})
            return self._result(True, f"Tampered with adapter files ({note}). Next read: {json.dumps(probe['reply'])}. "
                                "Reset the sandbox to continue.", "adapter_tamper", probe,
                                probe["reply"].get("decision", "error"))

    def adapter_attacks(self):
        with self.lock:
            if not ATTACKS.exists():
                raise LabError("scripts/attack_adapter.py is not available in this install")
            output = self.root / "attack.json"
            done = subprocess.run([sys.executable, str(ATTACKS), "--output", str(output)], capture_output=True,
                                  cwd=ROOT, timeout=300)
            report = json.loads(output.read_bytes()) if output.exists() else {"probes": 0, "held": 0, "results": []}
            return self._result(True, f"{report['held']} of {report['probes']} assessor-style attacks held.",
                                "attacks", report, "held" if done.returncode == 0 else "failed")
