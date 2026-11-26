"""Latency and throughput of signed, authorized requests through the three HTTP nodes.

Each request is a full round trip: fetch a challenge, sign the envelope with ML-DSA-65,
authenticate, check permission, append a signed audit event and commit. Loopback only.

    python scripts/bench_nodes.py --output reports/node_bench.json
"""

import argparse
import concurrent.futures
import json
import platform
import statistics
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from trustverify.authority import Authority  # noqa: E402
from trustverify.client import Client, Identity, Local  # noqa: E402
from trustverify.crypto import public  # noqa: E402
from trustverify.demo import nodes  # noqa: E402


def percentile(values, fraction):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(fraction * len(ordered)))]


def run(samples=200, workers=8):
    with tempfile.TemporaryDirectory(prefix="tv-bench-") as directory:
        directory = Path(directory)
        admin, second = Identity.generate("operator-device"), Identity.generate("officer-device")
        authority = Authority.initialize(directory / "authority", directory / "operator", public(admin.key),
                                         [("security-officer", second.device, public(second.key))])
        operator = Client(Local(authority), admin, authority.trust)
        officer = Client(Local(authority), second, authority.trust)
        users = []
        for index in range(workers):
            identity = Identity.generate(f"user-{index}-device")
            operator.call("enroll", **identity.enrollment(f"user{index}"))
            approval = officer.call("approve", owner=f"user{index}", service="frontend")["approval"]
            operator.call("grant", owner=f"user{index}", service="frontend", approval=approval)
            users.append(identity)
        with nodes(authority) as remotes:
            client = Client(remotes["node-a"], users[0], authority.trust)
            client.call("access")
            latencies = []
            for _ in range(samples):
                started = time.perf_counter()
                client.call("access")
                latencies.append((time.perf_counter() - started) * 1000)

            def burst(identity, count=samples // workers):
                worker = Client(remotes["node-a"], identity, authority.trust)
                for _ in range(count):
                    worker.call("access")
                return count

            started = time.perf_counter()
            with concurrent.futures.ThreadPoolExecutor(workers) as pool:
                completed = sum(pool.map(burst, users))
            elapsed = time.perf_counter() - started
            stranger = Client(remotes["node-a"], Identity.generate("stranger-device"), authority.trust)
            denials = []
            for _ in range(20):
                started = time.perf_counter()
                try:
                    stranger.call("access")
                except Exception:  # noqa: BLE001 - denial is the expected outcome
                    pass
                denials.append((time.perf_counter() - started) * 1000)
        exported = authority.export_log()
        return {
            "environment": {"python": platform.python_version(), "machine": platform.machine(),
                            "note": "loopback HTTP, one shared SQLite authority, full challenge-sign-verify-audit round trip"},
            "signed_request": {"median_ms": round(statistics.median(latencies), 2),
                               "p95_ms": round(percentile(latencies, 0.95), 2), "samples": samples},
            "concurrent": {"workers": workers, "requests": completed,
                           "requests_per_second": round(completed / elapsed, 1)},
            "unauthenticated_denial": {"median_ms": round(statistics.median(denials), 2), "samples": len(denials)},
            "audit_events": len(exported["records"]),
        }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output")
    parser.add_argument("--samples", type=int, default=200)
    args = parser.parse_args()
    report = run(args.samples)
    text = json.dumps(report, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(text)
    print(text, end="")


if __name__ == "__main__":
    main()
