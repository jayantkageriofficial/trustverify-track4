"""Explainable rules for the Track 4 toolkit's practice event format (events.csv + approvals.json).

Standard library only. Labels are read solely by ``score``; ``analyze`` never sees them.

Rules
- ``unapproved_role_change``: a successful role change with no matching, valid approval
  (same subject and role, inside the exclusive validity window, approved by someone else,
  and approved by an event the collector has already received).
- ``activity_after_unapproved_role_change``: later allowed activity by the same identity in
  the same session within ``REVIEW_WINDOW`` seconds of a flagged role change.
- ``lateral_movement_sequence``: two or more service edges outside the role's policy in the
  same identity, session and correlation flow within ``SEQUENCE_WINDOW`` seconds. A single unexpected
  edge is reported as a notice, not an alert.
Timing
- Corrected event time = source time minus the stated source clock offset.
- Arrival order is kept as received. An event whose corrected time precedes one already
  received produces an ``out_of_order_arrival`` notice; a nonzero offset produces a
  ``clock_offset_corrected`` notice. The supported range is shared with the main detector
  (``trustverify.constants``): offsets up to 120 s and corrected delay in [-1 s, 30 s].
- Correlation uses corrected event time through a ``MAX_LATENESS`` reorder buffer. Timing
  outside the supported range, or two events of one identity with equal corrected
  timestamps, flags the order as uncertain and withholds temporal alerts for that identity.
Baseline
- An edge is expected if the role policy lists it, or if it has already been observed as
  allowed for that role by at least ``BASELINE_MIN_IDENTITIES`` distinct identities. Roles
  missing from the policy therefore start strict and relax only on observed benign use.
"""

import csv
import heapq
import json
import statistics
from datetime import datetime
from pathlib import Path

from .constants import ATTACK_TECHNIQUES, MAX_CLOCK_OFFSET, MAX_LATENESS, MAX_NEGATIVE_SKEW

REVIEW_WINDOW = 600
SEQUENCE_WINDOW = 300
BASELINE_MIN_IDENTITIES = 2
POST_REVOCATION_WINDOW = 3600
POSITIVE_LABELS = {"unexpected_role_change", "review_after_role_change", "lateral_movement_candidate"}
DEFAULT_POLICY = Path(__file__).resolve().parent / "service_policy.json"


def _time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def load_events(path):
    with open(path, newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    events, seen = [], set()
    for position, row in enumerate(rows):
        if row["event_id"] in seen:
            raise ValueError("duplicate event_id")
        seen.add(row["event_id"])
        offset = int(row["source_clock_offset_ms"] or 0) / 1000
        events.append({**row, "position": position, "source_at": _time(row["event_time_utc"]),
                       "received_at": _time(row["received_time_utc"]), "offset_seconds": offset,
                       "corrected_at": _time(row["event_time_utc"]) - offset})
    return events


def load_approvals(path):
    changes = json.loads(Path(path).read_bytes())["changes"]
    return {change["approval_id"]: change for change in changes}


def load_policy(path=DEFAULT_POLICY):
    raw = json.loads(Path(path).read_bytes())
    return {role: {tuple(edge) for edge in edges} for role, edges in raw["role_edges"].items()}


def analyze(events, approvals, policy, learn=True):
    alerts, notices = [], []
    learned = {}                # (role, edge) -> identities observed using it successfully
    approved_seen = {}          # approval_id -> approval event
    flagged_sessions = {}       # (actor, session) -> (role-change event, corrected time)
    unexpected = {}             # (actor, session, correlation) -> [events]
    queue, uncertain, seen_times = [], set(), set()
    latest_corrected = None
    latest_arrival = float("-inf")

    def alert(rule, event, evidence, explanation, services, alert_at):
        alerts.append({"rule": rule, "identity": event["actor"], "services": services,
                       "events": evidence, "trigger": event["event_id"],
                       "alert_at": alert_at, "explanation": explanation,
                       "attack_technique": ATTACK_TECHNIQUES[rule]})

    def scope_allows(event, at):
        change = approvals.get(event["approval_id"]) if event["approval_id"] else None
        return bool(change and change["operation"] == "grant_role" and change["subject"] == event["actor"]
                    and change["role"] == event["role_before"] and event["target_service"] in change.get("scope", [])
                    and _time(change["valid_from_utc"]) <= at < _time(change["valid_until_utc"]))

    def denied_after_revocation(event, at):
        # A denial of scope the identity just lost is the expected effect of the revocation.
        if event["outcome"] != "deny":
            return False
        for change in approvals.values():
            if change["operation"] != "revoke_role" or change["subject"] != event["actor"]:
                continue
            effective = _time(change["effective_at_utc"])
            granted = [c for c in approvals.values() if c["operation"] == "grant_role"
                       and c["subject"] == event["actor"] and c["role"] == change["role"]]
            if 0 <= at - effective <= POST_REVOCATION_WINDOW and any(
                    event["target_service"] in c.get("scope", []) for c in granted):
                return True
        return False

    def process(event, alert_at):
        at = event["corrected_at"]
        session = (event["actor"], event["session_id"])
        action, success = event["action"], event["outcome"] in {"success", "allow"}
        if action == "approve_role_change" and success and event["approval_id"]:
            approved_seen[event["approval_id"]] = event
        if action == "role_change" and success and event["role_after"] != event["role_before"]:
            change = approvals.get(event["approval_id"]) if event["approval_id"] else None
            approval = approved_seen.get(event["approval_id"])
            matched = bool(change and change["operation"] == "grant_role" and change["subject"] == event["actor"]
                           and change["role"] == event["role_after"] and change["approved_by"] != event["actor"]
                           and _time(change["valid_from_utc"]) <= at < _time(change["valid_until_utc"])
                           and approval and approval["actor"] == change["approved_by"]
                           and approval["received_at"] <= event["received_at"])
            if not matched:
                flagged_sessions[session] = (event, at)
                alert("unapproved_role_change", event, [event["event_id"]],
                      f"{event['role_before']} -> {event['role_after']} with no matching approval "
                      "(subject, role, validity window and a different approver).", [event["target_service"]], alert_at)
            return
        if event["actor"] in uncertain:
            return
        flagged = flagged_sessions.get(session)
        if flagged and success and 0 <= at - flagged[1] <= REVIEW_WINDOW:
            alert("activity_after_unapproved_role_change", event, [flagged[0]["event_id"], event["event_id"]],
                  "Allowed activity in the same session after an unapproved role change.",
                  [event["source_service"], event["target_service"]], alert_at)
            return
        edge = (event["source_service"], event["target_service"])
        role = event["role_before"]
        observed = learned.setdefault((role, edge), set())
        baseline = learn and len(observed) >= BASELINE_MIN_IDENTITIES
        if success:
            observed.add(event["actor"])
        if edge in policy.get(role, set()) or baseline or scope_allows(event, at) or denied_after_revocation(event, at):
            return
        key = (*session, event["correlation_id"])
        group = [e for e in unexpected.get(key, []) if 0 <= at - e["corrected_at"] <= SEQUENCE_WINDOW]
        group.append(event)
        unexpected[key] = group
        if len(group) == 1:
            notices.append({"event_id": event["event_id"], "notice": "isolated_unexpected_edge",
                            "edge": list(edge), "explanation": "one unexpected edge alone is not a movement sequence"})
            return
        path = [group[0]["source_service"]] + [e["target_service"] for e in group]
        outcomes = sorted({e["outcome"] for e in group})
        alert("lateral_movement_sequence", event, [e["event_id"] for e in group],
              f"{len(group)} edges outside the {event['role_before']} policy in one session and flow: "
              f"{' -> '.join(path)} (outcomes: {', '.join(outcomes)}). Candidate only; denials do not show access.",
              path, alert_at)

    for position, event in enumerate(events):  # receipt order, retained in the source evidence
        arrival, at = event["received_at"], event["corrected_at"]
        if arrival < latest_arrival:
            raise ValueError("input must follow collector arrival order")
        latest_arrival = arrival
        delay = arrival - at
        if event["offset_seconds"]:
            notices.append({"event_id": event["event_id"], "notice": "clock_offset_corrected",
                            "offset_seconds": event["offset_seconds"], "corrected_delay_seconds": round(delay, 3)})
        stamp = (event["actor"], at)
        if not -MAX_NEGATIVE_SKEW <= delay <= MAX_LATENESS or abs(event["offset_seconds"]) > MAX_CLOCK_OFFSET:
            reason = "outside supported clock/arrival range"
        elif stamp in seen_times:
            reason = "equal corrected timestamps for one identity; order unknown"
        else:
            reason = None
        if reason:
            uncertain.add(event["actor"])
            notices.append({"event_id": event["event_id"], "notice": "event_order_uncertain", "reason": reason,
                            "corrected_delay_seconds": round(delay, 3),
                            "explanation": "temporal alerts withheld for this identity"})
        seen_times.add(stamp)
        if latest_corrected is not None and at < latest_corrected:
            notices.append({"event_id": event["event_id"], "notice": "out_of_order_arrival",
                            "explanation": "source evidence keeps receipt order; correlation uses corrected event time"})
        latest_corrected = at if latest_corrected is None else max(latest_corrected, at)
        heapq.heappush(queue, (at, position, event))
        while queue and queue[0][0] <= arrival - MAX_LATENESS:
            _, _, ready = heapq.heappop(queue)
            process(ready, arrival)
    flush_at = latest_arrival + MAX_LATENESS
    while queue:
        _, _, ready = heapq.heappop(queue)
        process(ready, flush_at)
    alerts = [a for a in alerts if a["rule"] == "unapproved_role_change" or a["identity"] not in uncertain]
    return {"alerts": alerts, "notices": notices,
            "timing": {"max_clock_offset_seconds": MAX_CLOCK_OFFSET, "max_corrected_delay_seconds": MAX_LATENESS,
                       "max_negative_skew_seconds": MAX_NEGATIVE_SKEW, "offline_final_flush_seconds": MAX_LATENESS,
                       "sequence_window_seconds": SEQUENCE_WINDOW, "review_window_seconds": REVIEW_WINDOW}}


def score(events, result, labels_path):
    with open(labels_path, newline="", encoding="utf-8") as stream:
        labels = {row["event_id"]: row["label"] for row in csv.DictReader(stream)}
    by_id = {e["event_id"]: e for e in events}
    positive = {eid for eid, label in labels.items() if label in POSITIVE_LABELS}
    first_alert = {}
    for a in result["alerts"]:
        for eid in a["events"]:
            first_alert[eid] = min(first_alert.get(eid, a["alert_at"]), a["alert_at"])
    predicted = set(first_alert)
    tp, fp, fn = len(predicted & positive), len(predicted - positive), len(positive - predicted)
    benign = len(labels) - len(positive)
    latencies = [first_alert[eid] - by_id[eid]["corrected_at"] for eid in predicted & positive]
    rows = [{"event_id": eid, "label": labels[eid], "flagged": eid in predicted,
             "rules": sorted({a["rule"] for a in result["alerts"] if eid in a["events"]})}
            for eid in (e["event_id"] for e in events)]
    return {"events": len(labels), "positive_events": len(positive), "benign_events": benign,
            "true_positives": tp, "false_positives": fp, "false_negatives": fn,
            "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0.0,
            "median_time_to_alert_seconds": statistics.median(latencies) if latencies else None,
            "false_alerts_per_1000_benign_events": fp * 1000 / benign if benign else None,
            "positive_labels": sorted(POSITIVE_LABELS),
            "caveat": "22 public practice events: a functional check only, not evidence of detection accuracy",
            "per_event": rows}


def run(directory, policy_path=DEFAULT_POLICY, use_policy=True):
    """``use_policy=False`` runs on the learned baseline alone, as for logs from unknown services."""
    directory = Path(directory)
    events = load_events(directory / "events.csv")
    policy = load_policy(policy_path) if use_policy else {}
    result = analyze(events, load_approvals(directory / "approvals.json"), policy)
    result["policy"] = "configured + learned baseline" if use_policy else "learned baseline only"
    if (directory / "labels.csv").exists():
        result["evaluation"] = score(events, result, directory / "labels.csv")
    return result
