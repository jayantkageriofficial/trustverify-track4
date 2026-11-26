"""Track 4 adapter v1 application: owner-bound reads, revocation and signed audit.

Runs on Python 3.12 with only the standard library and ``pqcrypto==0.4.0``,
which is exactly what the offline judging runtime provides. It never imports
``cryptography``.

Policy, in order, for ``read`` and ``protected_read``:
1. the actor must be a well-formed identifier,
2. the actor must not be disabled at setup or revoked later,
3. the asset must exist and be owned by that actor.
Anything else is denied without disclosing content.

Every decision is appended to a hash-chained audit log whose records are signed
with a per-setup ML-DSA-65 key. State is written atomically (temp file, fsync,
rename) under an exclusive lock before the reply is printed, and carries an
HMAC-SHA-256 tag so an edited state file (a cleared revocation, a changed owner)
fails closed instead of being honoured.

Detection: denials that look like probing (another owner's asset, a revoked or
disabled actor, a reused request ID, a malformed request) also append a signed
``alert`` event. ``{"op":"alerts"}`` returns them for the operator.
"""

import contextlib
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import tempfile
import time
import uuid
from pathlib import Path

from pqcrypto.kem import ml_kem_768
from pqcrypto.sign import ml_dsa_65

from .encoding import atomic_write, b64, canonical, unb64

FORMAT = "trustverify/adapter/v1"
DOMAIN = b"trustverify/adapter/v1/audit\x00"
ZERO = "0" * 64
ML_KEM_768_PUBLIC_BYTES = 1184
MAX_ID = 256
MAX_CHALLENGE = 4096
MAX_ENTRIES = 10_000
MAX_BODY = 1024 * 1024
MAX_ALERTS = 200
# Identifiers are opaque to the adapter; reject only control characters and oversize values.
IDENTIFIER = re.compile(r"[^\x00-\x1f\x7f]{1,%d}\Z" % MAX_ID)


class RequestError(ValueError):
    """Malformed request. Message never contains request values."""


def state_directory():
    configured = os.environ.get("TRACK4_STATE_DIR")
    if configured:
        # Supplied by the operator or checker: trusted as given.
        base = Path(configured)
        base.mkdir(parents=True, exist_ok=True, mode=0o700)
        return base
    # The shared temp directory is writable by other local users, so a directory planted
    # there in advance (a symlink, someone else's, or group/world-writable) is refused.
    base = Path(tempfile.gettempdir()) / "trustverify-track4"
    with contextlib.suppress(FileExistsError):
        base.mkdir(mode=0o700)
    info = os.lstat(base)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        raise RequestError("untrusted state directory")
    return base


def _identifier(value, field):
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise RequestError(f"invalid {field}")
    return value


def _record_hash(record):
    return hashlib.sha256(canonical(record)).hexdigest()


class Store:
    """Small state document (replaced atomically) plus an append-only audit log.

    Each request appends one signed line to ``adapter-audit.jsonl`` and rewrites only the
    small state document, so per-request cost no longer grows with the size of the log.
    ``audit_bytes`` in the state marks the committed end of the log: a line appended by a
    process that crashed before saving the state is an unacknowledged tail and is dropped.
    """

    def __init__(self, directory):
        self.directory = Path(directory)
        self.path = self.directory / "adapter-state.json"
        self.audit_path = self.directory / "adapter-audit.jsonl"
        # The signing key lives in its own 0700 directory, apart from the state it signs.
        self.key_path = self.directory / "keys" / "adapter-audit.key"
        self.public_path = self.key_path.with_suffix(".pub")
        self.mac_path = self.directory / "keys" / "adapter-state.key"
        self.migration_path = self.directory / "keys" / "adapter-state.migration"

    @contextlib.contextmanager
    def locked(self):
        fd = os.open(self.directory / "adapter.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "rb") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(stream, fcntl.LOCK_UN)

    def load(self):
        if not self.path.exists():
            return None
        try:
            state = json.loads(self.path.read_bytes())
            legacy = "mac" not in state
            tag = state.pop("mac", None)
            migration = json.loads(self.migration_path.read_bytes()) if self.migration_path.exists() else None
            if legacy:
                digest = hashlib.sha256(canonical(state)).hexdigest()
                if migration is None:
                    if self.mac_path.exists():
                        raise ValueError("tag missing from protected state")
                    key = secrets.token_bytes(32)
                    migration = {"key": b64(key), "state_sha256": digest}
                else:
                    if not hmac.compare_digest(migration["state_sha256"], digest):
                        raise ValueError("legacy state differs from pending migration")
                    key = unb64(migration["key"])
                    if len(key) != 32 or (self.mac_path.exists()
                                         and not hmac.compare_digest(key, self.mac_path.read_bytes())):
                        raise ValueError("migration key mismatch")
            else:
                expected = hmac.new(self.mac_path.read_bytes(), canonical(state), hashlib.sha256).hexdigest()
                if not isinstance(tag, str) or not hmac.compare_digest(tag, expected):
                    raise ValueError("state tag mismatch")
        except (ValueError, KeyError, TypeError, AttributeError, OSError):
            raise RequestError("state unreadable; integrity failure") from None
        if state.get("format") != FORMAT:
            raise RequestError("unsupported state format")
        public_key = unb64(state["audit_public"])
        if not self.public_path.exists():
            # Upgrade older state only after proving the public key matches the protected private key.
            probe = DOMAIN + b"key-binding\x00" + os.urandom(32)
            if not ml_dsa_65.verify(public_key, probe, ml_dsa_65.sign(self.signing_key(), probe)):
                raise RequestError("audit key does not match the protected signing key")
            atomic_write(self.public_path, public_key)
        if not hmac.compare_digest(public_key, self.public_path.read_bytes()):
            raise RequestError("audit key does not match the protected public key")
        setup = state["setup_record"]
        body = setup["body"]
        if (body["seq"] != 1 or body["previous"] != ZERO or body["instance"] != state["instance"]
                or body["op"] != "setup" or not ml_dsa_65.verify(
                    public_key, DOMAIN + canonical(body), unb64(setup["signature"]))):
            raise RequestError("setup signature verification failed")
        size = self.audit_path.stat().st_size if self.audit_path.exists() else 0
        if size < state["audit_bytes"]:
            raise RequestError("audit log shorter than committed state; integrity failure")
        if size > state["audit_bytes"]:
            os.truncate(self.audit_path, state["audit_bytes"])
        if legacy:
            verify_audit(self, state)
            # The protected intent authorizes recovery of this exact state if publication is interrupted.
            atomic_write(self.migration_path, canonical(migration))
            if not self.mac_path.exists():
                atomic_write(self.mac_path, key)
            self.save(state)
        if self.migration_path.exists():
            self.migration_path.unlink()
            fd = os.open(self.migration_path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        return state

    def save(self, state):
        tag = hmac.new(self.mac_path.read_bytes(), canonical(state), hashlib.sha256).hexdigest()
        atomic_write(self.path, canonical({**state, "mac": tag}))

    def reset_audit(self):
        atomic_write(self.audit_path, b"")

    def append(self, record):
        line = canonical(record) + b"\n"
        fd = os.open(self.audit_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "ab") as stream:
            stream.write(line)
            stream.flush()
            os.fsync(stream.fileno())
        return len(line)

    def records(self, state):
        with self.audit_path.open("rb") as stream:
            data = stream.read(state["audit_bytes"])
        return [json.loads(line) for line in data.splitlines()]

    def signing_key(self):
        return self.key_path.read_bytes()


def _append(store, state, event):
    body = {"seq": state["seq"] + 1, "previous": state["head"],
            "instance": state["instance"], "at": time.time(), **event}
    signature = ml_dsa_65.sign(store.signing_key(), DOMAIN + canonical(body))
    record = {"body": body, "signature": b64(signature)}
    state["audit_bytes"] += store.append(record)
    state["seq"], state["head"] = body["seq"], _record_hash(record)
    if body["seq"] == 1:
        state["setup_record"] = record
    if body.get("request_id") is not None:
        state["decisions"][body["request_id"]] = body["decision"]
    return body["seq"]


ALERT_RULES = {
    "not the asset owner": ("cross_owner_access", "a valid identity asked for an asset it does not own"),
    "actor revoked": ("revoked_actor_access", "a revoked identity is still presenting requests"),
    "actor disabled": ("disabled_actor_access", "a disabled identity attempted access"),
    "malformed request": ("malformed_request", "a request failed validation; possible fuzzing or injection"),
    "request_id replay": ("request_id_replay", "a request ID was reused; replay of an earlier decision"),
}


def _alert(store, state, reason, related_seq, actor, asset, request_id=None):
    """Append a signed alert for a suspicious denial. Fields are fixed strings or opaque IDs."""
    if reason not in ALERT_RULES:
        return
    rule, explanation = ALERT_RULES[reason]
    seq = _append(store, state, {"op": "alert", "rule": rule, "actor": actor, "asset": asset, "request_id": None,
                                 "subject_request_id": request_id, "related_seq": related_seq,
                                 "decision": "alert", "reason": explanation})
    summary = {"seq": seq, "rule": rule, "actor": actor, "asset": asset, "related_seq": related_seq,
               "subject_request_id": request_id}
    state["alerts"] = (state.get("alerts", []) + [summary])[-MAX_ALERTS:]


def key_fingerprint(public_key_b64):
    return hashlib.sha256(unb64(public_key_b64)).hexdigest()


def verify_audit(store, state, pinned_key_sha256=None, checkpoint=None):
    """Check sequence, hash chain and every ML-DSA-65 signature.

    The public key is stored next to the log, so on its own this only proves internal
    consistency. Operators pin the fingerprint returned by ``setup`` (and optionally a
    checkpoint ``{"seq", "head"}`` from an earlier verification) to detect a log that was
    rewritten and re-signed under a substituted key.
    """
    if pinned_key_sha256 is not None and not hmac.compare_digest(
            str(pinned_key_sha256), key_fingerprint(state["audit_public"])):
        raise RequestError("audit key does not match the pinned fingerprint")
    if checkpoint is not None and (not isinstance(checkpoint, dict) or type(checkpoint.get("seq")) is not int
                                   or not isinstance(checkpoint.get("head"), str)):
        raise RequestError("invalid checkpoint")
    public_key = unb64(state["audit_public"])
    records = store.records(state)
    if not records or records[0] != state["setup_record"]:
        raise RequestError("setup record does not match the audit log")
    previous = ZERO
    for count, record in enumerate(records, 1):
        body = record["body"]
        if body["seq"] != count or body["previous"] != previous or body["instance"] != state["instance"]:
            raise RequestError(f"audit chain failure at event {count}")
        if not ml_dsa_65.verify(public_key, DOMAIN + canonical(body), unb64(record["signature"])):
            raise RequestError(f"audit signature failure at event {count}")
        previous = _record_hash(record)
        if checkpoint is not None and count == checkpoint["seq"] and previous != checkpoint["head"]:
            raise RequestError("audit history differs from the pinned checkpoint")
    if previous != state["head"]:
        raise RequestError("audit head mismatch")
    if checkpoint is not None and checkpoint["seq"] > len(records):
        raise RequestError("audit truncated before the pinned checkpoint")
    return {"verified": True, "anchored": pinned_key_sha256 is not None, "events": len(records),
            "seq": len(records), "head": previous}


def _content_intact(state, asset):
    """Compare the stored body with the SHA-256 committed in the signed setup record."""
    expected = state["setup_record"]["body"]["contents_sha256"].get(asset)
    actual = hashlib.sha256(state["contents"][asset].encode("utf-8")).hexdigest()
    return expected is not None and hmac.compare_digest(expected, actual)


def _decide(state, actor, asset):
    """Return (decision, reason). Reasons are fixed strings, never request data."""
    if actor in state["revoked"]:
        return "deny", "actor revoked"
    if actor in state["disabled"]:
        return "deny", "actor disabled"
    if state["owners"].get(asset) != actor or asset not in state["contents"]:
        return "deny", "not the asset owner"
    if not _content_intact(state, asset):
        return "deny", "content integrity failure"
    return "allow", "owner"


def setup(store, request):
    owners, contents = request.get("owners"), request.get("contents")
    disabled = request.get("disabled", [])
    if not isinstance(owners, dict) or not isinstance(contents, dict) or not isinstance(disabled, list):
        raise RequestError("setup needs owners, contents and disabled")
    if len(owners) > MAX_ENTRIES or len(contents) > MAX_ENTRIES or len(disabled) > MAX_ENTRIES:
        raise RequestError("setup exceeds sandbox limits")
    for asset, actor in owners.items():
        _identifier(asset, "asset")
        _identifier(actor, "owner")
    for asset, body in contents.items():
        _identifier(asset, "asset")
        if not isinstance(body, str) or len(body.encode("utf-8")) > MAX_BODY:
            raise RequestError("content must be text, at most 1 MiB")
    for actor in disabled:
        _identifier(actor, "disabled actor")
    # key_material is synthetic and sensitive: it is accepted but never stored or echoed.
    public_key, secret_key = ml_dsa_65.generate_keypair()
    atomic_write(store.key_path, secret_key)
    atomic_write(store.public_path, public_key)
    atomic_write(store.mac_path, secrets.token_bytes(32))
    state = {"format": FORMAT, "instance": uuid.uuid4().hex, "audit_public": b64(public_key),
             "owners": owners, "contents": contents, "disabled": sorted(set(disabled)),
             "revoked": [], "decisions": {}, "alerts": [], "seq": 0, "head": ZERO, "audit_bytes": 0}
    store.reset_audit()
    _append(store, state, {"op": "setup", "actor": None, "asset": None, "request_id": None,
                           "decision": "allow", "reason": "initialized",
                           "assets": len(owners), "disabled": len(state["disabled"]),
                           "contents_sha256": {asset: hashlib.sha256(body.encode("utf-8")).hexdigest()
                                               for asset, body in contents.items()}})
    store.save(state)
    # Not secret: the operator pins this fingerprint to verify the audit log later.
    return {"ready": True, "audit_key_sha256": key_fingerprint(state["audit_public"])}


def read(store, state, request):
    request_id = _identifier(request.get("request_id"), "request_id")
    if _replayed(store, state, request, request_id):
        return {"decision": "deny"}
    try:
        actor = _identifier(request.get("actor"), "actor")
        asset = _identifier(request.get("asset"), "asset")
        decision, reason = _decide(state, actor, asset)
    except RequestError:
        actor, asset, decision, reason = None, None, "deny", "malformed request"
    seq = _append(store, state, {"op": "read", "actor": actor, "asset": asset, "request_id": request_id,
                                 "decision": decision, "reason": reason})
    if decision != "allow":
        _alert(store, state, reason, seq, actor, asset, request_id)
    store.save(state)
    if decision == "allow":
        return {"decision": "allow", "body": state["contents"][asset]}
    return {"decision": "deny"}


def _replayed(store, state, request, request_id):
    """A reused request ID never overwrites the recorded decision; it is denied and alerted."""
    if request_id not in state["decisions"]:
        return False
    actor = request.get("actor") if isinstance(request.get("actor"), str) and IDENTIFIER.fullmatch(request["actor"]) else None
    asset = request.get("asset") if isinstance(request.get("asset"), str) and IDENTIFIER.fullmatch(request["asset"]) else None
    _alert(store, state, "request_id replay", None, actor, asset, request_id)
    store.save(state)
    return True


def alerts(state):
    return {"alerts": state.get("alerts", []), "count": len(state.get("alerts", []))}


def revoke(store, state, request):
    actor = _identifier(request.get("actor"), "actor")
    already = actor in state["revoked"]
    if not already:
        state["revoked"].append(actor)
    _append(store, state, {"op": "revoke", "actor": actor, "asset": None, "request_id": None,
                           "decision": "allow", "reason": "already revoked" if already else "revoked"})
    store.save(state)
    return {"revoked": True}


def audit(state, request):
    request_id = _identifier(request.get("request_id"), "request_id")
    decision = state["decisions"].get(request_id)
    if decision is None:
        # Unknown requests were never allowed; report that without inventing a record.
        return {"request_id": request_id, "decision": "deny", "recorded": False}
    return {"request_id": request_id, "decision": decision, "recorded": True}


def protected_read(store, state, request):
    challenge = request.get("challenge")
    # request_id is optional here; when supplied it is recorded so ``audit`` can answer for it.
    request_id = request.get("request_id")
    if request_id is not None:
        request_id = _identifier(request_id, "request_id")
        if _replayed(store, state, request, request_id):
            return {"decision": "deny"}
    try:
        actor = _identifier(request.get("actor"), "actor")
        asset = _identifier(request.get("asset"), "asset")
        if not isinstance(challenge, str) or not 0 < len(challenge) <= MAX_CHALLENGE:
            raise RequestError("invalid challenge")
        public_key = unb64(request.get("public_key"))
        if len(public_key) != ML_KEM_768_PUBLIC_BYTES:
            raise RequestError("public_key must be a raw ML-KEM-768 key")
        decision, reason = _decide(state, actor, asset)
    except (RequestError, ValueError):
        actor, asset, decision, reason = None, None, "deny", "malformed request"
    seq = _append(store, state, {"op": "protected_read", "actor": actor, "asset": asset, "request_id": request_id,
                                 "decision": decision, "reason": reason,
                                 "challenge_sha256": hashlib.sha256(challenge.encode("utf-8")).hexdigest()
                                 if isinstance(challenge, str) else None})
    if decision != "allow":
        _alert(store, state, reason, seq, actor, asset, request_id)
    store.save(state)
    if decision != "allow":
        return {"decision": "deny"}
    ciphertext, shared_secret = ml_kem_768.encrypt(public_key)
    proof = hmac.new(shared_secret, (challenge + state["contents"][asset]).encode("utf-8"),
                     hashlib.sha256).hexdigest()
    del shared_secret
    return {"decision": "allow", "ciphertext": b64(ciphertext), "proof": proof}


def error_reply(request, message):
    """Fail-closed reply for a request that could not be processed: always a JSON object,
    never protected content, and a deny decision where the operation has one."""
    op = request.get("op") if isinstance(request, dict) else None
    if op == "setup":
        return {"ready": False, "error": message}
    if op == "audit":
        rid = request.get("request_id")
        return {"request_id": rid if isinstance(rid, str) and IDENTIFIER.fullmatch(rid) else None,
                "decision": "deny", "recorded": False, "error": message}
    if op == "revoke":
        return {"revoked": False, "error": message}
    return {"decision": "deny", "error": message}


def record_malformed(request, directory=None):
    """Log sanitized validation failures only against verified existing state and history."""
    try:
        store = Store(directory or state_directory())
        fields = request if isinstance(request, dict) else {}
        ids = {}
        for name in ("actor", "asset", "request_id", "op"):
            value = fields.get(name)
            ids[name] = value if isinstance(value, str) and IDENTIFIER.fullmatch(value) else None
        with store.locked():
            state = store.load()
            if state is None:
                return False
            verify_audit(store, state)
            seq = _append(store, state, {"op": "invalid_request", "requested_op": ids["op"],
                                         "actor": ids["actor"], "asset": ids["asset"], "request_id": None,
                                         "subject_request_id": ids["request_id"],
                                         "decision": "deny", "reason": "malformed request"})
            _alert(store, state, "malformed request", seq, ids["actor"], ids["asset"], ids["request_id"])
            store.save(state)
        return True
    except Exception:  # noqa: BLE001 - reporting must never change the fail-closed reply
        return False


def dispatch(request, directory=None):
    if not isinstance(request, dict):
        raise RequestError("request must be a JSON object")
    store = Store(directory or state_directory())
    op = request.get("op")
    with store.locked():
        if op == "setup":
            return setup(store, request)
        state = store.load()
        if state is None:
            if op in {"read", "protected_read"}:
                return {"decision": "deny"}
            if op == "audit":
                return {"request_id": request.get("request_id"), "decision": "deny", "recorded": False}
            raise RequestError("setup required")
        if op == "read":
            return read(store, state, request)
        if op == "revoke":
            return revoke(store, state, request)
        if op == "audit":
            return audit(state, request)
        if op == "protected_read":
            return protected_read(store, state, request)
        if op == "alerts":
            return alerts(state)
        if op == "verify_audit":
            return verify_audit(store, state, request.get("audit_key_sha256"), request.get("checkpoint"))
    raise RequestError("unknown op")
