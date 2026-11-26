# TrustVerify — Track 4: Trust, but verify

Public source: [jayantkageriofficial/trustverify-track4](https://github.com/jayantkageriofficial/trustverify-track4).

A working organizer-sandbox prototype that connects **post-quantum encrypted transfers, device/key lifecycle controls, verifiable access decisions and contextual detection**. No AI/ML components, hard-coded secrets or custom cryptographic primitives.

**USP:** every sensitive transfer has an explainable authorization decision, an explicit key version and a verifiable audit trail, including through rotation, revocation and recovery.

This repository implements three independent HTTP enforcement processes backed by **one local transactional authority**. It does not implement three replicated key stores or distributed consensus. All endpoints bind to `127.0.0.1`; use only synthetic identities and files in the assigned sandbox.

Clients refuse HTTP redirects so a mock service cannot redirect requests outside its configured endpoint.

## Quick start

| Goal | Commands |
|---|---|
| Check the grader adapter (judging runtime: Python 3.12 + pqcrypto only) | `pip install 'pqcrypto==0.4.0'` then `python ../Track-4-Toolkit/validate.py --entry track4_service.py` |
| Install and test everything | `pip install '.[messaging,dev]'` then `python -m pytest -q` |
| Run the three-node protected workflow | `python -m trustverify demo --directory runtime/first-demo` |
| Watch the live log and contain alerts | `python -m trustverify watch --state ... --operator ... --identity ...` (see [Detection and evaluation](#detection-and-evaluation)) |
| Detector on toolkit practice data | `python -m trustverify practice --toolkit ../Track-4-Toolkit/practice` |
| Measure adapter overhead | `python scripts/bench_adapter.py --output reports/adapter_bench.json` |
| Measure signed HTTP request latency | `python scripts/bench_nodes.py --output reports/node_bench.json` |
| Attack the adapter like an assessor | `python scripts/attack_adapter.py --output reports/adapter_attack.json` |

Every section below expands one of these rows.

## Grader adapter (judging runtime)

[track4_service.py](track4_service.py) is the toolkit's adapter v1 entry point. It reads one JSON request from stdin, writes one JSON reply to stdout and exits. It needs **only Python 3.12 and `pqcrypto==0.4.0`**, the exact offline judging runtime; it never imports `cryptography`. The application logic is in [trustverify/adapter.py](trustverify/adapter.py).

| Operation | Behaviour |
|---|---|
| `setup` | Stores owners, contents and disabled actors; generates a fresh ML-DSA-65 audit key and commits a SHA-256 of every body in the signed setup record. `key_material` is never stored, printed or logged. Returns `{"ready":true,"audit_key_sha256":...}`; the fingerprint is public and is what operators pin. |
| `read` | Allows only the asset's owner when not disabled or revoked, and only if the stored body still matches its signed SHA-256; returns the exact body. Every other case returns `{"decision":"deny"}` with no content. A reused `request_id` is denied and never overwrites the first record. |
| `revoke` | Permanently revokes the actor; other actors keep access. |
| `audit` | Returns the recorded `request_id` and `decision`. |
| `protected_read` | Same policy, then ML-KEM-768 encapsulation to the supplied raw public key (1184 bytes required) and `proof = HMAC-SHA-256(shared_secret, challenge + body)`. The shared secret never leaves the process. |
| `alerts` | Extra operator view: signed alert events raised by suspicious denials (see below). |
| `verify_audit` | Extra operator check: sequence, hash chain and every ML-DSA-65 signature. Pass `audit_key_sha256` (from `setup`) and optionally a `checkpoint` `{"seq","head"}` from an earlier run to detect a log rewritten and re-signed under a substituted key, or truncated. Replies with `anchored: true` only when pinned. |

State lives in `TRACK4_STATE_DIR`, or `<system temp>/trustverify-track4` when unset, and is written atomically (exclusive lock, temp file, fsync, rename) before the reply is printed. The audit signing key and its public verification key are kept in a separate `keys/` directory (0700). Each load verifies the cached setup signature against that protected public key before trusting any body hash. When upgrading an older adapter state without the public-key file, the service first proves that the cached public key matches the protected private key by signing and verifying a fresh random probe. **At-rest confidentiality of adapter bodies relies on file permissions (0600 files, 0700 directory):** the judging runtime offers no vetted symmetric cipher (pqcrypto has none and `cryptography` is absent), and we do not build one ourselves. Integrity is protected by the verified signed body hashes. The full prototype does encrypt at rest (AES-256-GCM inbox and backups). [threat-model.json](threat-model.json) declares `protected-resource` / `identity-check`, which is what the adapter enforces.

**Fail-closed replies.** Every request ends with exit status 0 and exactly one JSON object, so a fuzzed or hostile request can never crash the worker or produce mixed output. Requests that cannot be processed get a deny-shaped reply with a fixed error string: `{"decision":"deny","error":...}` for reads and unknown input, `{"ready":false,...}` for `setup`, and `{"request_id":...,"decision":"deny","recorded":false,...}` for `audit`. Non-UTF-8, non-object, `NaN`/`Infinity` and oversized (over 64 MiB) input are all rejected this way.

**Tamper-evident state.** The state document carries an HMAC-SHA-256 tag under a random key kept in `keys/`. An edited state file (a cleared revocation, a changed owner, a replaced body) fails the tag check and every read is denied. Access to the MAC key alone does not bypass the independently verified setup signature and body hashes; signing-key and pinned-root compromise remain outside the threat model. A log shorter than the committed state also fails closed. Trusted legacy state is upgraded during load, including `audit`, `verify_audit` and `alerts`: setup and audit signatures are checked, and a private `keys/adapter-state.migration` record binds the new key to the exact legacy-state digest before publication. Interrupted migration resumes that snapshot; the recovery record is durably removed before dispatch. An untagged state with an existing MAC key and no matching recovery record is refused, so stripping a tag cannot force an upgrade.

**Shared temp directory.** When `TRACK4_STATE_DIR` is unset, `<system temp>/trustverify-track4` is created 0700 and refused if it already exists as a symlink, belongs to another user, or is group/world-writable, so a directory planted by another local user cannot capture or redirect state. Lock files and audit-log appends use `O_NOFOLLOW`.

**Detection and response.** Denials that look like probing append a signed `alert` event next to the decision it explains: `cross_owner_access` (a valid identity asks for an asset it does not own), `revoked_actor_access`, `disabled_actor_access`, `request_id_replay` (a reused request ID, which is denied without changing the recorded decision) and `malformed_request`. Early validation failures, including missing request IDs, unknown operations, invalid JSON and invalid UTF-8, create sanitized `invalid_request` decisions and linked malformed-request alerts when existing state and its full audit chain verify. Unparseable identities remain anonymous; raw input and protected bodies are never logged. These records do not replace the request-ID decision index. Failed integrity checks leave the unverified log untouched. `{"op":"alerts"}` returns the most recent 200 for the operator; the full set stays in the verifiable log. The response is the denial itself plus the alert; the adapter does not lock identities out automatically, because adapter v1 callers expect a legitimate owner's later reads to keep working.

**Self-assessment.** [scripts/attack_adapter.py](scripts/attack_adapter.py) runs 20 assessor-style probes, each in a fresh process like the grader: malformed and hostile input, look-alike identities, request-ID replay after revocation, log injection, `protected_read` key and challenge validation, parallel requests, on-disk state and log tampering, alerting, key-material leakage and a planted shared temp directory. All 20 hold; see [reports/adapter_attack.json](reports/adapter_attack.json). Before this hardening, 6 of them failed.

Check it against the toolkit's validator with only the judging dependencies:

```sh
python3.12 -m venv /tmp/judge && /tmp/judge/bin/pip install 'pqcrypto==0.4.0' 'pytest==9.2.0'
git clone https://github.com/ScalerOpenSourceLabs/Track-4-Toolkit ../Track-4-Toolkit
/tmp/judge/bin/python ../Track-4-Toolkit/validate.py --entry track4_service.py
/tmp/judge/bin/python -m pytest -q tests/test_adapter.py tests/test_practice.py
/tmp/judge/bin/python scripts/attack_adapter.py
```

The adapter is a reduced policy surface (asset ownership, disable and revoke). **It trusts the caller-supplied `actor`**: adapter v1 passes identities as plain strings from the trusted grader worker, so the identity check is "is this actor the owner, and not disabled or revoked", not authentication of the caller. Likewise `setup` is unauthenticated by contract and replaces all state, including revocations. Authenticated identities (ML-DSA-signed, challenge-bound requests) are in the full prototype. Rotation, multi-node enforcement, messaging and recovery are demonstrated by the full prototype below.

## Clean-machine setup

Requires Linux, Python 3.12 or newer, and Internet access during dependency installation. The full prototype uses the optional `messaging` extra (`cryptography`); the grader adapter above does not. The crash tests use Linux `fork` and the authority uses POSIX file locking. No database server, PQ library build, API key or account is required. Cryptography wheels include their OpenSSL backend on supported platforms.

From the repository root:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install '.[messaging,dev]'
python -m pytest -q
python -m trustverify demo --directory runtime/first-demo
```

The demo directory must be new. Choose another directory for a second run; prior keys and evidence are never overwritten. The demo launches all three services, makes real signed HTTP requests, runs assertions and stops the processes. A failed check exits nonzero.

Alternatively, with [uv](https://docs.astral.sh/uv/):

```sh
uv sync --extra messaging --extra dev --locked
uv run --extra messaging --extra dev --locked pytest -q
uv run --extra messaging --locked trustverify demo --directory runtime/first-demo
```

Base dependency: `pqcrypto==0.4.0` (adapter, detector, practice evaluation). `messaging` extra: `cryptography==50.0.2` (HPKE transfers, AES-GCM backups, the three-node prototype). Development/document dependencies: `pytest==9.2.0`, `reportlab==5.1.2`. The exact transitive resolution is in [uv.lock](uv.lock). Algorithm and library attribution is in [THIRD_PARTY.md](THIRD_PARTY.md).

[GitHub Actions verification](https://github.com/jayantkageriofficial/trustverify-track4/actions) has two jobs. `adapter` installs only `pqcrypto` and `pytest`, confirms `cryptography` is absent, and runs the adapter tests, the toolkit validator and the practice-data detector. `verify` installs the project on a fresh Linux runner, runs all tests and the three-process demo, verifies its audit export, regenerates the PDF, and builds/tests/runs the Docker image without external runtime networking. See [.github/workflows/verify.yml](.github/workflows/verify.yml).

## Run and inspect the evidence

The demo produces:

| File | Purpose |
|---|---|
| `runtime/first-demo/report.json` | Asserted checklist outcomes and measured overhead/revocation observations |
| `runtime/first-demo/audit-export.json` | Signed, hash-linked events with original authenticated actors |
| `runtime/first-demo/alerts.json` | Identity, services, event IDs and explanations for alerts on the real demo log |
| `runtime/first-demo/operator/trust.json` | Pinned audit public key and cluster identity |
| `runtime/first-demo/operator/checkpoint.json` | Separately retained signed log checkpoint |
| `runtime/first-demo/keys.backup` | Encrypted, authenticated authority/key backup |
| `runtime/first-demo/identities/` | Fresh synthetic endpoint signing keys; never publish |
| `runtime/first-demo/inbox-bob/` | Local encrypted recipient inbox and its separate storage key; never publish |

Verify using the independently retained trust and checkpoint files, rather than trusting a public key supplied inside an exported log:

```sh
python -m trustverify verify \
  --log runtime/first-demo/audit-export.json \
  --trust runtime/first-demo/operator/trust.json \
  --checkpoint runtime/first-demo/operator/checkpoint.json

python -m trustverify detect \
  --log runtime/first-demo/audit-export.json \
  --trust runtime/first-demo/operator/trust.json \
  --checkpoint runtime/first-demo/operator/checkpoint.json

python -m trustverify evaluate --output reports/detector.json
```

`runtime/`, private keys, backups, local databases and virtual environments are excluded from Git and Docker build contexts. Only the non-secret measurement summaries belong in `reports/`.

## Architecture and trust boundaries

```text
Sender endpoint                         Recipient endpoint
ML-DSA signing key                      ML-DSA signing key
                                        one-use hybrid KEM private key
       signed offer + hybrid HPKE ciphertext
                       |
                       v
   node-a/frontend   node-b/billing   node-c/secrets
             three loopback HTTP processes
                       |
     shared SQLite authority + cross-process lock
     device registry / permissions / revocation tombstones
     admitted transfers / ciphertext fragments / signed audit
                       |
     separate operator trust root, checkpoint and recovery key
                       |
       verified log export -> explainable detector
```

The endpoints hold encryption secrets. Service nodes see encrypted payloads, public keys, signed manifests and access metadata. The local demo orchestrator simulates both endpoints; separate machines and a production E2EE client UI are outside this prototype.

### Cryptography and authenticated requests

- **Identity:** library ML-DSA-65 signatures, with separate application-purpose prefixes for requests, recipient offers, manifests, audit records and checkpoints.
- **Encryption:** the library's HPKE `MLKEM768_X25519`/X-Wing hybrid KEM, HKDF-SHA256 and AES-256-GCM. ML-KEM-768 is standardized in FIPS 203; ML-DSA-65 in FIPS 204. The PQ/hybrid HPKE integration is a draft extension; the application protocol is not Signal, Noise, or an independently audited standard.
- **Recipient binding:** a recipient signs a fresh offer binding the protocol, session ID, both device identities and key versions, and its ephemeral KEM public keys. The sender verifies that offer and signs the ciphertext manifest. The entire binding is HPKE `info`. Changing recipient information fails verification/decryption.
- **Request authentication:** the authority issues a stateless 30-second random challenge signed with the existing library ML-DSA audit key under a separate `challenge` purpose. The token binds the node, optional device, cluster, expiry and current challenge epoch. Issuance allocates no nonce rows and never evicts outstanding tokens, including when an anonymous caller names another device. Only authenticated requests consume tokens; their random IDs are retained transactionally until expiry to reject duplicates, including across node restarts. Restoring a backup changes the separately retained `operator/challenge-epoch` so restoring the replay cache cannot reactivate old requests. Recovery and restore migrate legacy nonce tables; upgrades invalidate older outstanding challenges while preserving committed keys, permissions and data. Directory lookups require an authenticated request. ML-DSA authenticates the complete node/action/device/version/challenge/data envelope. Cross-node and duplicate requests fail. A challenge nonce is distinct from a library-managed encryption nonce.
- **Authorization:** registered ownership, current key state, administrator role and service permission are checked by the authority. **Two-person rule:** a privilege grant that cites an approval must be performed by a different administrator than the one who issued it, and no administrator can approve their own access. `init` therefore creates two administrator identities (`operator` and `security-officer`). Transfer continuation additionally checks both participants' revocation and current service permissions.
- **Forward secrecy:** recipient KEM secrets are created per session, held only in endpoint memory, and dropped after success/failure. They are never backed up. Long-term signing keys alone do not decrypt prior completed sessions. Python does not guarantee physical zeroization of freed memory; process-memory compromise is excluded.
- **Completed inbox:** plaintext is committed only after full authentication and is encrypted locally under a separate random AES-256 storage key. That storage key is not derived from the identity key and is not sent to the authority.

### Rotation, revocation and recovery policy

**Rotation cutoff is the authority transaction commit. New-request grace period: zero.** Devices rotate their signing credential with proof of possession of the replacement. All nodes re-read authoritative state rather than accepting cached permissions. A previously admitted transfer can continue with its original credential for **120 seconds from admission**, provided both participants remain unrevoked and permitted. This is an explicit continuation exception, not permission to admit new work with a retired key. Keep the old signing key locally while finishing such a transfer.

The final cutoff for **all** old-key use is no later than 120 seconds after rotation: every pre-existing transfer grant expires by then, usually earlier. The rotation response reports that upper-bound deadline. Retired material cannot be reused for enrolment or another rotation.

**Revocation overrides continuation.** Every request/fragment checks current device state. All key versions of the lost device receive permanent revocation tombstones. An operator can enrol a new device for the same owner; permissions belong to the owner, so unrelated users retain access. The replacement does not inherit the lost device's local inbox storage key.

**Consistent recovery:** lifecycle changes, access outcomes and their audit event commit in one SQLite transaction. Fault injection kills an actual process before rotation commit and after commit but before checkpoint publication. Recovery validates the pinned signature chain, retained checkpoint and current state digest. It rolls back an incomplete change or accepts a fully committed valid tail. Revoked keys remain revoked.

**Authority outages fail closed.** Admission and continuation stop if the shared authority is unavailable. Clock offsets supplied in access logs cannot influence authorization. Authorization uses transaction order and the trusted authority host's expiry clock; that host's clock and filesystem are trusted.

### Backup and audit integrity

Backups contain a consistent SQLite snapshot (public registry, revocations, ciphertext and audit history) plus the audit signing key, encrypted/authenticated with AES-256-GCM under `operator/recovery.key`. The recovery key and signed freshness checkpoint stay outside the authority directory. Private endpoint identity keys and ephemeral secrets are not in this backup.

Restore authenticates the complete backup before using its key material, verifies the pinned signing key, full log chain, current state digest and SQLite integrity, and requires the snapshot head to match a signed checkpoint. Every checkpoint is also appended to `operator/checkpoints.jsonl`. A backup matching the latest checkpoint restores directly. **An older authentic backup is refused unless the operator passes `--accept-rollback`**, and only if its head matches a retained signed checkpoint; the restore then records the rollback (events lost) as a signed audit event. Signed `operator/revocations.json` retains revoked devices and minimum committed key versions outside backup storage. Revocations are re-applied; **a backup that predates any retained key rotation is refused even with `--accept-rollback`**. Use a newer backup rather than reactivating an old key. When upgrading existing state, run `recover` once while the intact authority is available to retain its rotation floors.

Restore prepares revocations and the restore event in memory, then records a signed `operator/restore-intent.json` before replacing the database. After interruption, `recover` validates the intent and either retains the previous committed state or finishes publishing the prepared restore checkpoint. It also repairs a missing or torn checkpoint-history entry. Stop services before restoring. Backups larger than 64 MiB are outside the sandbox limit.

Every audit record is canonically serialized, individually ML-DSA signed and linked to the preceding record. Its actor comes from verified credentials. User text remains nested in `details`; newlines cannot introduce another event. A separate signed checkpoint exposes deletion of an acknowledged log suffix. Historical public verification does not depend on rotated device keys because the audit key has a separate lifetime.

The cross-process lock spans transaction commit and atomic checkpoint publication. A crash may leave an unacknowledged committed tail, which recovery validates and adopts. Truncation of an uncheckpointed, unacknowledged tail is not detectable independently. Audit-key rotation is not implemented; compromise of that key is outside the retained-history guarantee.

## Detection and evaluation

Rules detect:

1. Administrator privilege grants without a validated, owner/service-matching, unexpired, single-use approval.
2. Use of revoked devices or transfer peers.
3. Observed consecutive service transitions outside the approved `frontend <-> billing` workflow, within 60 seconds and without a recent approved grant for that destination service.
4. Grants whose approval was issued by the granting administrator (`self_approved_grant`). The authority already rejects these; the rule is defense in depth for imported or legacy logs.

Requests that fail authentication do not each write a signed audit record. They are summarised as one signed `unauthenticated_rejections` event per 100 failures or 60 seconds, and each HTTP node throttles them with a token bucket (burst 20, 10 per second, HTTP 429). Requests that authenticate never draw from that bucket.

Alerts identify the beneficiary identity, acting identity, services, supporting immutable event IDs, rule and explanation. A currently valid credential can still trigger a service-transition alert. Approved administration is context, not a blanket exclusion for all administrators. This is a small workflow-specific detector, not a general UEBA system.

**Timing bounds (one range for both detectors, defined in [trustverify/constants.py](trustverify/constants.py)):** trusted source offsets up to **±120 seconds**, corrected event arrival lateness up to **30 seconds**, and at most **1 second** of negative corrected delay. A watermark buffer orders events within that range. Untrusted offsets, equal ambiguous timestamps and out-of-range events produce timing notices; ambiguous events cannot establish a definite service path. Non-temporal revocation/privilege checks still run. Offset estimates must come from a trusted collector, never arbitrary client fields. Authority-native events already use the authority clock.

For an identity with uncertain ordering, path alerts are conservatively withheld for that entire analysis batch. Timing notices list the affected identities; an uncertain permission change also marks its beneficiary. This avoids asserting a path across missing ordering information, at the cost of reduced path coverage for that batch. Other identities and non-temporal rules remain active. Every trusted collector arrival advances the watermark, including arrivals with unsupported source clocks.

`evaluate` and `detect` are offline commands; their end-of-input flush advances the simulated collector clock by 30 seconds, and the reported time-to-alert includes buffering and that flush.

**Live detection and response.** `trustverify watch` polls the authority log, verifies it against the pinned trust root and retained checkpoint, runs the same rules, and appends each new alert (with its detection latency) to a JSON-lines file. With a responder administrator identity it contains the alert through an ordinary signed, audited request: an unapproved or self-approved grant has that permission removed, and an unexpected service transition loses access to the destination service. The authority verifies the triggering record hash and checks for later permission changes inside the removal transaction; resolved or re-approved access is skipped. Handled alerts are atomically retained under `operator/watcher-<mode-hash>.json`, separately for alert-only mode and each responder device. Keys use signed-record hashes, so reused sequence numbers after rollback remain distinct. Failed responses are retried on later polls or restart. Run one watcher per responder identity. Revoked-credential use needs no action because the authority already denied it. Responses are audit events, so they can be reviewed and reversed. In the demo, an unapproved grant is detected and contained about 0.1 s after it is logged.

```sh
python -m trustverify watch --state runtime/manual/authority --operator runtime/manual/operator \
  --identity runtime/manual/identities/security-officer --output runtime/manual/live-alerts.jsonl
```

[fixtures/labelled_logs.json](fixtures/labelled_logs.json) has **1,162 labelled events: 1,092 benign and 70 malicious**. It includes approved administration, routine frontend/billing traffic, unapproved grants, valid-credential lateral movement, revoked use, skew and reordered arrival. Labels are never read by detection rules. Tests additionally use two different randomized arrival/offset seeds.

Event-level evaluation counts each trigger event once; supporting context events are not predictions. F1 includes missed attacks. False alerts per 1,000 benign events use the complete benign-event denominator. Median alert latency is computed for detected malicious events from corrected occurrence time to simulated emission; missed events are reported separately.

Three results, reported separately because they measure different things:

| Data | Events (positive) | F1 | Median time to alert | False alerts / 1,000 benign | Report |
|---|---|---|---|---|---|
| Rule-aligned synthetic fixture | 1,162 (70) | 1.00 | 51 s | 0 | [reports/detector.json](reports/detector.json) |
| Held-out synthetic set, written after the rules | 320 (46) | 0.78 | 172 s | 14.6 | [reports/heldout.json](reports/heldout.json) |
| Toolkit practice data (public, 22 events) | 22 (5) | 1.00 | 59.2 s | 0 | [reports/practice.json](reports/practice.json) |
| Toolkit practice data, learned baseline only (no policy file) | 22 (5) | 0.83 | 59.2 s | 117.6 | [reports/practice-learned.json](reports/practice-learned.json) |

The rule-aligned fixture was generated alongside the rules, so its 1.0 shows the rules work as designed, not that they generalise. The held-out set ([scripts/make_fixture.py](scripts/make_fixture.py) `make_heldout_events`) uses shuffled neutral identities and includes cases the rules are known to miss: insider access along the approved `frontend -> billing` edge, slow lateral movement beyond the 60-second path window, and first direct use after a self-approved grant (14 misses). Its 4 false alerts are benign uses of an approval after its 300-second window. Its median latency is high because sparse traffic delays the offline watermark; a timer-driven collector would emit after the 30-second lateness bound.

The practice data uses its own format, so [trustverify/practice.py](trustverify/practice.py) applies equivalent rules to it: role changes without a matching approval (subject, role, exclusive validity window, a different approver, and an approval event received by the time of the role-change receipt), activity in the same identity/session after such a change, and two or more service edges outside the role policy ([trustverify/service_policy.json](trustverify/service_policy.json)) in one identity/session/flow. A single unexpected edge is a notice, not an alert; denials of scope removed by a recent revocation are expected. An edge also counts as expected once at least two distinct identities with that role have used it successfully, so roles missing from the policy start strict and relax on observed benign use; `--no-policy` runs on that learned baseline alone, as it would on logs from unknown services (2 false alerts on the practice data, both the very first events of the stream). Correlation buffers corrected event times for 30 seconds, preserving original receipt evidence. Supported source offsets are ±120 seconds and corrected delay is -1 to 30 seconds (shared with the main detector in [trustverify/constants.py](trustverify/constants.py)); unsupported timing or equal corrected timestamps for one identity are flagged as order-uncertain and withhold temporal alerts for that identity. Out-of-order arrival and corrected clock offsets are reported as notices. Sparse arrivals and the final 30-second flush contribute to the reported 59.2-second median latency. **The policy file and these rules were written with the 22 practice events in view**, so the 1.0 there is a functional check, as the toolkit itself says, not an accuracy measurement.

```sh
python -m trustverify practice --toolkit ../Track-4-Toolkit/practice --output reports/practice.json
python -m trustverify evaluate --input fixtures/heldout_logs.json --output reports/heldout.json
```

## Performance and overhead

Adapter, measured as the grader runs it (a fresh process per request, so interpreter start-up is included) with [scripts/bench_adapter.py](scripts/bench_adapter.py) on Python 3.12.3, x86_64. See [reports/adapter_bench.json](reports/adapter_bench.json).

| Operation | Median | p95 |
|---|---|---|
| `setup` (1,000 assets) | 55.5 ms | |
| `read` (500 requests) | 44.3 ms | 59.4 ms |
| `protected_read` (ML-KEM-768 + HMAC) | 45.0 ms | 50.1 ms |
| `audit` | 39.5 ms | 52.6 ms |
| `verify_audit` (551 events, every signature) | 171.6 ms | |

Read latency stays flat as the log grows (first 10%: 42.7 ms, last 10%: 45.1 ms), because each request appends one line to `adapter-audit.jsonl` and rewrites only the small state document. Storage overhead is about 4,850 bytes per audit event, almost all of it the ML-DSA-65 signature.

Mock-service nodes, measured with [scripts/bench_nodes.py](scripts/bench_nodes.py) ([reports/node_bench.json](reports/node_bench.json)): a full signed request (fetch challenge, ML-DSA-65 sign and verify, permission check, signed audit commit) takes a median of 12.5 ms (p95 17.5 ms); eight concurrent clients sustain about 86 requests per second against one node; an unauthenticated denial costs 6.8 ms. Each node serves connections on separate threads with at most 64 in flight (JSON 503 beyond that), a 5-second socket timeout, no Python version banner and `X-Content-Type-Options: nosniff`. The client receives a normal `Denied` with status 503 at capacity and can retry after connections close; a stalled client below the cap does not serialize other connections.

Full prototype, from [reports/demo.json](reports/demo.json): encrypt and sign a 96 KiB transfer in 2.2 ms (ciphertext 99,440 bytes for 98,304 bytes of plaintext, signed manifest 10,841 bytes); receive, decrypt and commit in 3.7 ms; revocation request to last observed node rejection 98 ms; live detection and containment 0.11 s after the event is logged. The authority rehashes its whole state on every request, which favours verifiability over scale.

## Objective-to-evidence checklist

| Track 4 objective | Implementation / evidence |
|---|---|
| Key rotation | Zero admission grace; all-node rejection; admitted transfer finishes (`test_rotation_cutoff_all_nodes_and_transfer_continuity`) |
| Revocation / device loss | All-node rejection; measured observation upper bounds; re-enrolment; other user retains access |
| Crash recovery | Real process termination at both commit boundaries; pinned log/state recovery; revoked key stays revoked |
| Backup integrity | Bit-flipped backup rejected; fresh restore succeeds; explicit older restore preserves revocations and refuses key-version regression; real process crashes at restore boundaries recover; unknown history rejected; missing key/database recovered |
| Log integrity | Newline/forged-actor injection, modified actor, deleted record and truncated suffix tests; public verification CLI |
| Routine / suspicious activity | Two-person approval enforced by the authority; self-approved grant rule; F1, alert latency and false alerts on rule-aligned, held-out and toolkit practice data |
| Lateral movement | Valid credentials on unexpected observed service paths; supporting event IDs and rule explanation |
| Clock differences | ±120 s offset / 30 s lateness; reorder buffer; uncertain-order notices |
| Replay / recipient binding | Durable completed-message IDs; consumed request challenges; changed recipient and other identity rejected |
| Forward secrecy | One-use ephemeral recipient secrets excluded from backups; identity key cannot decrypt a completed recording |
| Loss / reordering | Numbered bounded ciphertext fragments; selective retry; full manifest/hash/signature/AEAD validation; no partial delivery |
| Session resumption | **Unsupported.** Interrupted sessions require a fresh signed offer; session ID alone is never a bearer credential |

See [tests/](tests/), [reports/demo.json](reports/demo.json), [THREAT_MODEL.md](THREAT_MODEL.md) and [DEMO.md](DEMO.md).

## Keep the mock services running

```sh
python -m trustverify init --directory runtime/manual
python -m trustverify serve --state runtime/manual/authority --operator runtime/manual/operator --node node-a --port 8101
```

In two other terminals, run the same command with `node-b --port 8102` and `node-c --port 8103`. Stop with Ctrl-C. The init command creates two administrator signing identities, `operator` and `security-officer`, so grants can carry a second-person approval; no default password exists.

For a signed operator access request:

```sh
python -m trustverify call --url http://127.0.0.1:8101 --node node-a \
  --identity runtime/manual/identities/operator \
  --trust runtime/manual/operator/trust.json --action access --data '{"note":"approved test"}'

python -m trustverify rotate --url http://127.0.0.1:8101 --node node-a \
  --identity runtime/manual/identities/operator --trust runtime/manual/operator/trust.json
```

`call --data @file.json` accepts a JSON object from a file. A device's `Identity.enrollment(owner)` helper creates its proof of possession. `Client.call("enroll", **proof)` is operator-only. The full protected file workflow is available through `protocol.Receiver`, `protocol.encrypt` and the documented `start`, `put_chunk`, `finish`, `fetch`, `read_chunk` actions in [demo.py](trustverify/demo.py).

`rotate` writes the candidate key before requesting the transaction. If transport fails, it retains the candidate. Reconcile the signed directory version with the saved `vN.pem` before retrying; do not delete the candidate or assume the request failed.

For offline backup/restore, stop service processes first:

```sh
python -m trustverify backup --state runtime/manual/authority --operator runtime/manual/operator --output runtime/manual/latest.backup
python -m trustverify restore --state runtime/manual/authority --operator runtime/manual/operator --input runtime/manual/latest.backup
# For an older verified backup add --accept-rollback; revocations made since are re-applied.
python -m trustverify recover --state runtime/manual/authority --operator runtime/manual/operator
```

Export a fresh audit log after additional requests. An old export intentionally fails verification against a newer independently retained checkpoint.

## Container option

```sh
docker build -t trustverify .
docker run --rm --network none trustverify
docker run --rm --network none trustverify python -m pytest -q -p no:cacheprovider
```

The container launches only loopback services and runs as an unprivileged user. Docker is optional; the Python setup and subprocess integration tests are the primary checked path.

## Submission artifacts and limits

- Two-page brief: [docs/project-brief.pdf](docs/project-brief.pdf). Page two is the one-page threat model.
- Five-minute walkthrough script: [DEMO.md](DEMO.md).
- Public repository/video URLs: [submission.json](submission.json). **The video URL is not filled in yet; add it before final submission.**
- Regenerate the PDF: `python scripts/build_brief.py`. Fill the URL fields in `submission.json` when available; populated URLs become clickable PDF links.

Known limits: "revocation across nodes" means three HTTP processes reading one shared SQLite authority, so measured revocation times are observation bounds, not replication latency. The two-person rule assumes the two administrator identities belong to different people. The audit signing key sits beside the authority database; the operator-side checkpoint and tombstones are what expose tampering. Trusted single-host control plane and OS, loopback HTTP without TLS, central availability dependency, 1 MiB message limit, 120-second admission grants, offline workflow-specific detection, no audit-key rotation, no session resumption, no post-compromise healing and no claim of independently audited or production-secure application protocol. Revocation cannot erase plaintext or keys already copied by a recipient. Whole-state hashing favors auditability over throughput and needs redesign for large stores.

Publish only source/public evidence, and supply the required public five-minute recording before final submission.
