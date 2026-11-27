"""Explainable rules over verified records; no AI/ML or learned model."""

import heapq
import math
import statistics

from .constants import ATTACK_TECHNIQUES, MAX_CLOCK_OFFSET, MAX_LATENESS, MAX_NEGATIVE_SKEW

PATH_WINDOW = 60
APPROVED_EDGES = {("frontend", "billing"), ("billing", "frontend")}


def analyze(events):
    alerts, notices, queue = [], [], []
    previous, approved_until = {}, {}
    latest_arrival = -math.inf
    seen = set()
    uncertain_identities = set()

    def timing_notice(event, reason):
        identities = {event["actor"]}
        if event.get("outcome") == "allowed" and event["action"] in {"grant", "remove_permission"}:
            identities.add(event["details"]["owner"])
        uncertain_identities.update(identities)
        notices.append({"event_id": event["id"], "identity": event["actor"],
                        "reason": reason, "path_alerts_suppressed_for_batch": sorted(identities)})

    def emit(event, rule, identities, services, evidence, explanation, alert_at):
        alerts.append({"event_id": event["id"], "identity": identities,
                       "acting_identity": event["actor"], "services": services,
                       "events": evidence, "rule": rule, "explanation": explanation,
                       "attack_technique": ATTACK_TECHNIQUES[rule], "alert_at": alert_at})

    def process(event, occurred, alert_at, temporal=True):
        action, details = event["action"], event.get("details", {})
        if event.get("outcome") == "allowed" and action == "grant":
            owner, service = details["owner"], details["target_service"]
            if details.get("approved") is True and details.get("approved_by") == event["actor"]:
                # Defense in depth: the authority enforces the two-person rule, but a log that
                # shows the granting admin as its own approver is still suspicious.
                approved_until.pop((owner, service), None)
                emit(event, "self_approved_grant", owner, [service], [event["id"]],
                     "Administrator granted access using an approval they issued themselves.", alert_at)
            elif details.get("approved") is True:
                if temporal:
                    approved_until[(owner, service)] = occurred + 300
                else:
                    approved_until.pop((owner, service), None)
            else:
                approved_until.pop((owner, service), None)
                emit(event, "unapproved_privilege_grant", owner, [service], [event["id"]],
                     "Administrator granted service access without a validated, matching approval.", alert_at)
        if event.get("outcome") == "allowed" and action == "remove_permission":
            approved_until.pop((details["owner"], details["target_service"]), None)
        if event.get("outcome") == "denied" and "revoked" in details.get("reason", ""):
            emit(event, "revoked_credential_use", event["actor"], [event["service"]], [event["id"]],
                 "The authority rejected a credential or transfer peer already revoked.", alert_at)
        if not temporal or action != "access" or event.get("outcome") != "allowed":
            return
        actor, service = event["actor"], event["service"]
        before = previous.get(actor)
        if before:
            old_time, old_service, old_id = before
            edge = (old_service, service)
            if 0 < occurred - old_time <= PATH_WINDOW and old_service != service and edge not in APPROVED_EDGES:
                if approved_until.get((actor, service), -math.inf) < occurred:
                    emit(event, "unexpected_service_transition", actor, list(edge), [old_id, event["id"]],
                         f"Observed {old_service} -> {service} within {PATH_WINDOW}s; transition is outside the approved workflow and has no current approved service grant.", alert_at)
            elif occurred == old_time and old_service != service:
                timing_notice(event, "equal corrected timestamps; service order uncertain")
                previous.pop(actor, None)
                return
        previous[actor] = (occurred, service, event["id"])

    for position, raw in enumerate(events):
        event = dict(raw)
        event["id"] = raw.get("id", raw.get("seq"))
        if event["id"] is None or event["id"] in seen:
            raise ValueError("events need unique immutable IDs")
        seen.add(event["id"])
        arrival = event["observed_at"]
        if type(arrival) not in (int, float) or not math.isfinite(arrival):
            raise ValueError("invalid collector timestamp")
        if arrival < latest_arrival:
            raise ValueError("input must follow trusted collector arrival order")
        latest_arrival = arrival
        source = event.get("source_at", arrival)
        offset = event.get("clock_offset", 0)
        if (type(source) not in (int, float) or not math.isfinite(source) or
                type(offset) not in (int, float) or not math.isfinite(offset)):
            raise ValueError("invalid source clock information")
        occurred = source - offset
        reason = None
        if "source_at" in event and event.get("clock_offset_trusted") is not True:
            reason = "clock offset untrusted; event order uncertain"
        elif abs(offset) > MAX_CLOCK_OFFSET or not -MAX_NEGATIVE_SKEW <= arrival - occurred <= MAX_LATENESS:
            reason = "outside supported clock/arrival range; event order uncertain"
        if reason:
            timing_notice(event, reason)
            process(event, arrival, arrival, temporal=False)
        else:
            heapq.heappush(queue, (occurred, position, event))
        while queue and queue[0][0] <= arrival - MAX_LATENESS:
            occurred, _, ready = heapq.heappop(queue)
            process(ready, occurred, arrival)
    flush_at = latest_arrival + MAX_LATENESS if events else 0
    while queue:
        occurred, _, ready = heapq.heappop(queue)
        process(ready, occurred, flush_at)
    # Unbounded ordering uncertainty cannot justify a definite path for that identity.
    alerts = [a for a in alerts if a["rule"] != "unexpected_service_transition"
              or a["identity"] not in uncertain_identities]
    return {"alerts": alerts, "timing_notices": notices,
            "timing": {"max_clock_offset_seconds": MAX_CLOCK_OFFSET,
                       "max_arrival_lateness_seconds": MAX_LATENESS,
                       "path_window_seconds": PATH_WINDOW,
                       "offline_final_flush_seconds": MAX_LATENESS}}


def evaluate(events):
    if not events or any(type(e.get("malicious")) is not bool for e in events):
        raise ValueError("evaluation requires explicit boolean labels for every event")
    result = analyze(events)
    by_id = {e.get("id", e.get("seq")): e for e in events}
    malicious = {key for key, event in by_id.items() if event["malicious"]}
    predicted = {a["event_id"] for a in result["alerts"]}
    tp, fp, fn = len(predicted & malicious), len(predicted - malicious), len(malicious - predicted)
    benign = len(events) - len(malicious)
    latencies = []
    for event_id in predicted & malicious:
        event = by_id[event_id]
        occurred = event.get("source_at", event["observed_at"]) - event.get("clock_offset", 0)
        latencies.append(min(a["alert_at"] for a in result["alerts"] if a["event_id"] == event_id) - occurred)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {"events": len(events), "benign_events": benign, "malicious_events": len(malicious),
            "true_positives": tp, "false_positives": fp, "false_negatives": fn,
            "precision": precision, "recall": recall,
            "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0.0,
            "median_time_to_alert_seconds": statistics.median(latencies) if latencies else None,
            "false_alerts_per_1000_benign_events": fp * 1000 / benign if benign else None,
            "measurement": "event-level trigger IDs; simulated collector/watermark time; missed attacks counted in recall",
            "timing_notices": len(result["timing_notices"])}
