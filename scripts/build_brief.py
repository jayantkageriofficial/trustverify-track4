"""Generate exactly two pages: overview/results and a one-page threat model."""

import json
import re
from pathlib import Path
from urllib.parse import urlparse
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (HRFlowable, PageBreak, Paragraph, Preformatted,
                               SimpleDocTemplate, Spacer)

ROOT = Path(__file__).resolve().parents[1]


def main():
    submission = json.loads((ROOT / "submission.json").read_text())
    result = json.loads((ROOT / "reports" / "detector.json").read_text())
    heldout = json.loads((ROOT / "reports" / "heldout.json").read_text())
    practice = json.loads((ROOT / "reports" / "practice.json").read_text())["evaluation"]
    demo = json.loads((ROOT / "reports" / "demo.json").read_text())
    tests = (ROOT / "reports" / "tests.txt").read_text()
    passed = re.search(r"(\d+) passed", tests)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Body", fontName="Helvetica", fontSize=9,
                              leading=12, spaceAfter=7, alignment=TA_LEFT))
    styles.add(ParagraphStyle(name="SmallText", fontName="Helvetica", fontSize=8,
                              leading=10, spaceAfter=5))
    styles["Title"].fontSize = 23
    styles["Title"].leading = 27
    styles["Heading2"].fontSize = 11
    styles["Heading2"].leading = 14
    styles["Heading2"].spaceBefore = 7
    story = []

    def p(text, style="Body"):
        story.append(Paragraph(text, styles[style]))

    def heading(text):
        p(text, "Heading2")

    def link(label, value):
        if value:
            parsed = urlparse(value)
            if parsed.scheme != "https" or not parsed.hostname:
                raise ValueError(f"{label} must be a public HTTPS URL")
            p(f'<b>{label}:</b> <link href="{escape(value, {chr(34): "&quot;"})}" color="#12617b">{escape(value)}</link>', "SmallText")
        else:
            p(f"<b>{label}:</b> __________________________________________", "SmallText")

    p("TrustVerify", "Title")
    p("Track 4 · Trust, but verify · Organizer sandbox prototype", "SmallText")
    story.append(HRFlowable(width="100%", color=colors.HexColor("#12617b")))
    story.append(Spacer(1, 4 * mm))
    p("<b>USP:</b> Every sensitive transfer has an explainable authorization decision, an explicit key version and a verifiable audit trail through rotation, revocation and recovery.")
    heading("System architecture and protected workflow")
    story.append(Preformatted(
        "Sender endpoint -- signed offer / hybrid HPKE --> Recipient endpoint\n"
        "                        | encrypted fragments\n"
        "        node-a/frontend | node-b/billing | node-c/secrets\n"
        "                        |\n"
        "   Shared transactional authority: registry, ACLs, tombstones, audit\n"
        "                        |\n"
        "   Separate operator trust root / checkpoint / recovery key\n"
        "                        |\n"
        "            Verified events -> explainable rule detector",
        ParagraphStyle(name="Diagram", fontName="Courier", fontSize=7.5, leading=10)))
    p("Three real loopback HTTP processes consult one SQLite authority. The demo orchestrates two logical endpoints; only endpoints hold plaintext and ephemeral decryption secrets. This is a central authority, not a replicated key-management cluster.")
    p("<b>Grader adapter:</b> root <font face='Courier'>track4_service.py</font> runs on Python 3.12 + pqcrypto only and passes the toolkit validator. Owner-bound reads, permanent revocation, a signed ML-DSA-65 hash-chained audit per request ID, and <font face='Courier'>protected_read</font> via ML-KEM-768 encapsulation plus HMAC-SHA-256 proof. Every request exits cleanly with one JSON object; malformed input, an edited (HMAC-tagged) state file or a cut log fail closed as deny. Probing and early validation failures append signed alerts only to verified history. Legacy MAC upgrades recover interrupted publication, including read-only checks.")
    p("<b>Cryptography:</b> library ML-DSA-65 identities; library HPKE with ML-KEM-768/X25519 hybrid KEM, HKDF-SHA256 and AES-256-GCM. Signed one-use recipient offers bind both device identities, key versions and the protocol. The binding is HPKE context; the sender signs the ciphertext manifest. No custom cryptographic primitives or AI/ML components.")
    heading("Lifecycle, integrity and delivery policy")
    p("<b>Rotation:</b> cutoff at transaction commit; zero new-admission grace. An admitted transfer can finish under its original key for 120 seconds, unless revocation or permission loss overrides it. <b>Revocation:</b> every request rechecks both peers; owner re-enrolment uses a new device key. <b>Recovery:</b> atomic lifecycle/audit commits; actual process crashes tested on both sides of rotation commit.")
    p("<b>Backup:</b> authenticated snapshot and audit key, checked against a retained checkpoint. Explicit older restore re-applies revocations and refuses key-version regression. Signed restore intent recovers interrupted replacement; restore epochs prevent request replay. <b>Two-person rule:</b> a grant cannot use an approval issued by the same administrator. Unauthenticated failures are summarised and throttled. <b>Audit:</b> signed hash chain, verified body hashes, server-derived actor and structured user fields. <b>Delivery:</b> bounded fragment retry/reordering, full authentication before release, durable replay records. No session resumption; interrupted sessions require a fresh offer.")
    heading("Measured evidence and repeatable setup")
    observed = demo["performance"]["revocation_request_to_last_observed_rejection_ms"]
    bench = json.loads((ROOT / "reports" / "adapter_bench.json").read_text())
    node_bench = json.loads((ROOT / "reports" / "node_bench.json").read_text())
    attack = json.loads((ROOT / "reports" / "adapter_attack.json").read_text())
    p(f"<b>{passed.group(1) if passed else 'See reports/tests.txt'} tests passed.</b> Three-process demo covers transfer continuity, cutoff, all-node revocation, re-enrolment, crash recovery, backup damage and real-log alerts. Request-to-last observed revocation rejection: <b>{observed:.1f} ms</b> on this machine; sequential monotonic probes give an observation upper bound, not replication latency. Adapter, one process per request: read median {bench['read']['median_ms']} ms (p95 {bench['read']['p95_ms']}), protected_read {bench['protected_read']['median_ms']} ms, flat as the log grows; about {bench['audit_bytes_per_event']:,} bytes per signed audit event. Signed HTTP request (challenge, ML-DSA verify, ACL, signed audit commit): median {node_bench['signed_request']['median_ms']} ms, {node_bench['concurrent']['requests_per_second']} req/s with {node_bench['concurrent']['workers']} clients. Self-assessment: {attack['held']}/{attack['probes']} assessor-style adapter attacks held (scripts/attack_adapter.py).")
    p(f"<b>Detection</b> (F1 / median alert latency / false alerts per 1,000 benign). Rule-aligned synthetic, {result['events']:,} events: <b>{result['f1']:.2f} / {result['median_time_to_alert_seconds']:.0f} s / {result['false_alerts_per_1000_benign_events']:.1f}</b>. Held-out synthetic written after the rules, {heldout['events']} events with known blind spots: <b>{heldout['f1']:.2f} / {heldout['median_time_to_alert_seconds']:.0f} s / {heldout['false_alerts_per_1000_benign_events']:.1f}</b>. Toolkit practice data, {practice['events']} events: <b>{practice['f1']:.2f} / {practice['median_time_to_alert_seconds']:.1f} s / {practice['false_alerts_per_1000_benign_events']:.1f}</b>, a functional check only since its policy was written with those events in view.")
    story.append(Preformatted("python -m pip install '.[messaging,dev]'\npython -m pytest -q\npython -m trustverify demo --directory runtime/demo",
                             ParagraphStyle(name="Commands", fontName="Courier", fontSize=8, leading=11)))
    link("Public repository", submission["public_repository_url"])
    link("Five-minute demo video", submission["demo_video_url"])

    story.append(PageBreak())
    p("Threat model", "Title")
    p("One page · TrustVerify · Track 4", "SmallText")
    story.append(HRFlowable(width="100%", color=colors.HexColor("#12617b")))
    heading("Assets and scope")
    p("Organizer-owned mock services, test identities and synthetic files only. Protect plaintext, identity and ephemeral keys, the endpoint inbox key, ownership/permissions, revoked-key tombstones, committed key versions, backups, and original actor/action/event boundaries. Public keys and necessary access metadata are not confidential.")
    heading("Attackers and disruptions")
    p("Malicious enrolled user; holder of a stolen/revoked test credential; client replaying or altering signed requests, recipient metadata or fragments; log-text injection; changes to exported audit records or backup bytes without trusted keys. Faults: device loss, interrupted rotation, unavailable authority, corrupted backup, fragment loss/reordering and offset/out-of-order source clocks.")
    heading("Trust boundaries and assumptions")
    p("Endpoint plaintext and ephemeral keys stay outside relay storage. Signed requests cross into the authoritative registry and ACL checks. Caller text cannot set authenticated actor or approval status. Enrolment and the two administrator identities (distinct people) are authorized out of band. Verification pins separately retained trust/checkpoints; it does not trust roots bundled with a log. Recovery bytes become usable only after complete authentication, freshness and state checks.")
    p("Trust the OS, endpoint process memory while active, authority host clock, operator bootstrap, application and cryptographic library. The single-host demo uses one OS account: separate directories are logical boundaries, not hardware isolation. Recovery key and latest signed checkpoint must survive outside authority failure storage. Source-clock offset metadata must come from a trusted collector.")
    heading("Controls and fail-safe outcomes")
    p("Library PQ signatures and hybrid HPKE; one-use recipient secrets; purpose-bound signatures; stateless library-signed, node-bound challenges and a durable one-use cache; permission/revocation checks for every fragment; atomic lifecycle/audit updates; permanent tombstones; authenticated fresh backups; signed audit/checkpoint verification; bounded delivery and replay records. Later identity-key exposure alone does not decrypt completed sessions; ephemeral secrets are not backed up.")
    p("Authority failure denies admission and continuation. A lost device stays revoked after new-device enrolment. Previously committed protected inbox data uses a separate storage key. Invalid or incomplete messages never produce partial delivery. An older backup restores only with logged, explicit rollback; external revocation tombstones are re-applied.")
    heading("Detection and timing limits")
    p("Rules explain unapproved and self-approved grants, revoked use and unusual observed service transitions using identity, approval context and supporting event IDs. Trusted offsets up to +/-120 seconds and corrected arrival lateness up to 30 seconds are supported. Uncertain ordering produces a notice and withholds path alerts for affected identities for the batch; privilege/revocation checks continue. Known misses: approved-edge insider access, lateral moves slower than 60 s. Live watch persists handled-record hashes and conditionally removes permissions, preserving re-approved access. No ML: the baseline only counts identities per edge. Simulated metrics are not production guarantees.")
    heading("Excluded threats and residual risk")
    p("No protection against privileged host compromise, a malicious trusted operator, active endpoint-memory compromise, compromised library, stolen recovery/checkpoint roots, or plaintext/keys already copied by an authorized recipient. No guaranteed memory zeroization. Rolling back every freshness reference defeats rollback detection. An unacknowledged/uncheckpointed crash tail cannot be independently proven complete.")
    p("Cross-node revocation is one shared SQLite authority, not replication. The audit key sits beside the database; external checkpoints expose tampering. The adapter trusts the caller-supplied actor and unauthenticated setup, as adapter v1 defines them. No replicated authority, production TLS deployment, session resumption, post-compromise healing, audit-key rotation or independent protocol audit. Messages are bounded to 1 MiB and admitted transfers to 120 seconds. Whole-state hashing favors verifiability over scale. ML-KEM/ML-DSA are standardized algorithms; the PQ/hybrid HPKE integration is a draft extension and this application is not a FIPS-validated module.")
    p("<b>Evidence:</b> README.md (setup, objective mapping), tests/, reports/ (demo, detector, heldout, practice), THIRD_PARTY.md. No runtime private keys or databases are published.", "SmallText")

    destination = ROOT / "docs" / "project-brief.pdf"
    destination.parent.mkdir(exist_ok=True)

    def footer(canvas, doc):
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#54616c"))
        canvas.drawString(17 * mm, 12 * mm, "TrustVerify | organizer sandbox | source and limitations documented")
        canvas.drawRightString(193 * mm, 12 * mm, str(doc.page))

    document = SimpleDocTemplate(str(destination), pagesize=(210 * mm, 297 * mm),
                                 rightMargin=17 * mm, leftMargin=17 * mm,
                                 topMargin=14 * mm, bottomMargin=19 * mm,
                                 title="TrustVerify - Track 4 Project Brief and Threat Model",
                                 author="TrustVerify contributors", invariant=1)
    document.build(story, onFirstPage=footer, onLaterPages=footer)
    if document.page != 2:
        raise ValueError(f"project brief must be two pages; generated {document.page}")
    print(destination)


if __name__ == "__main__":
    main()
