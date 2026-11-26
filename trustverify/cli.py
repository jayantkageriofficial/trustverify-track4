import argparse
import json
import sqlite3
import sys
from pathlib import Path

from .constants import NODES
from .detector import analyze, evaluate
from .encoding import atomic_write, canonical

# Commands that need the optional `messaging` extra import it lazily, so `evaluate` and
# `practice` run in the judging runtime (Python 3.12 + pqcrypto only).
LIGHT_COMMANDS = {"evaluate", "practice"}


def load_json(path):
    return json.loads(Path(path).read_bytes())


def parser():
    root = argparse.ArgumentParser(description="TrustVerify: local Track 4 organizer sandbox prototype")
    commands = root.add_subparsers(dest="command", required=True)
    demo = commands.add_parser("demo", help="run the complete three-process protected workflow")
    demo.add_argument("--directory", required=True, help="new output directory; never overwrites a prior demo")
    demo.add_argument("--fixture", default="fixtures/labelled_logs.json")
    init = commands.add_parser("init", help="create fresh authority and operator credentials")
    init.add_argument("--directory", required=True)
    identity = commands.add_parser("identity", help="generate a synthetic device signing key")
    identity.add_argument("--device", required=True)
    identity.add_argument("--directory", required=True)
    for name in ("serve", "backup", "restore", "export", "recover"):
        sub = commands.add_parser(name)
        sub.add_argument("--state", required=True)
        sub.add_argument("--operator", required=True)
        if name == "serve":
            sub.add_argument("--node", choices=list(NODES), required=True)
            sub.add_argument("--port", type=int, required=True)
        if name in {"backup", "export"}:
            sub.add_argument("--output", required=True)
        if name == "restore":
            sub.add_argument("--input", required=True)
            sub.add_argument("--accept-rollback", action="store_true",
                             help="restore a verified backup older than the latest checkpoint")
    for name in ("call", "rotate"):
        sub = commands.add_parser(name)
        sub.add_argument("--url", required=True)
        sub.add_argument("--node", choices=list(NODES), required=True)
        sub.add_argument("--identity", required=True)
        sub.add_argument("--trust", required=True)
        if name == "call":
            sub.add_argument("--action", required=True)
            sub.add_argument("--data", default="{}", help="JSON object, or @path to JSON")
    for name in ("verify", "detect"):
        sub = commands.add_parser(name)
        sub.add_argument("--log", required=True)
        sub.add_argument("--trust", required=True, help="independently pinned operator/trust.json")
        sub.add_argument("--checkpoint", required=True, help="independently retained operator/checkpoint.json")
        sub.add_argument("--output")
    live = commands.add_parser("watch", help="live detection over the verified log, with automatic containment")
    live.add_argument("--state", required=True)
    live.add_argument("--operator", required=True)
    live.add_argument("--identity", help="responder administrator identity directory (omit with --no-respond)")
    live.add_argument("--node", choices=list(NODES), default="node-a")
    live.add_argument("--interval", type=float, default=1.0)
    live.add_argument("--once", action="store_true", help="poll once and exit")
    live.add_argument("--no-respond", action="store_true", help="alert only; take no containment action")
    live.add_argument("--output", default=None, help="append alerts as JSON lines")
    lab = commands.add_parser("ui", help="interactive local lab in the browser (127.0.0.1 only)")
    lab.add_argument("--port", type=int, default=8765, help="local port (0 picks a free one)")
    lab.add_argument("--no-browser", action="store_true", help="print the URL instead of opening a browser")
    evaluation = commands.add_parser("evaluate")
    evaluation.add_argument("--input", default="fixtures/labelled_logs.json")
    evaluation.add_argument("--output")
    practice = commands.add_parser("practice", help="run the detector on the toolkit's practice events")
    practice.add_argument("--toolkit", required=True, help="toolkit practice/ directory (events.csv, approvals.json, labels.csv)")
    practice.add_argument("--policy", help="service policy JSON (default: trustverify/service_policy.json)")
    practice.add_argument("--no-policy", action="store_true",
                          help="ignore the configured policy and use only the learned baseline")
    practice.add_argument("--output")
    return root


class _NoSignatureError(Exception):
    pass


def main(argv=None):
    args = parser().parse_args(argv)
    InvalidSignature, Denied = _NoSignatureError, _NoSignatureError
    if args.command not in LIGHT_COMMANDS:
        from cryptography.exceptions import InvalidSignature
        from .authority import Authority, Denied, verify_log
        from .client import Client, Identity, Remote
        from .crypto import new_identity, private_bytes, public
    try:
        if args.command == "demo":
            from .demo import run
            result = run(args.directory, args.fixture, progress=lambda message: print(message, file=sys.stderr))
        elif args.command == "init":
            directory = Path(args.directory)
            directory.mkdir(parents=True, exist_ok=False, mode=0o700)
            admin, officer = Identity.generate("operator-device"), Identity.generate("officer-device")
            admin.save(directory / "identities" / "operator")
            officer.save(directory / "identities" / "security-officer")
            authority = Authority.initialize(directory / "authority", directory / "operator", public(admin.key),
                                             [("security-officer", officer.device, public(officer.key))])
            result = {"state": str(authority.directory), "operator": str(authority.operator),
                      "admin_identity": str(directory / "identities" / "operator"),
                      "approver_identity": str(directory / "identities" / "security-officer")}
        elif args.command == "identity":
            directory = Path(args.directory)
            if directory.exists():
                raise ValueError("identity directory already exists")
            identity = Identity.generate(args.device)
            identity.save(directory)
            result = {"device": identity.device, "public": public(identity.key)}
        elif args.command == "ui":
            from .ui import run as run_ui
            return run_ui(args.port, open_browser=not args.no_browser)
        elif args.command == "serve":
            from .server import serve
            serve(args.state, args.operator, args.node, args.port)
            return 0
        elif args.command in {"backup", "restore", "export", "recover"}:
            authority = Authority(args.state, args.operator, recovery_only=args.command == "restore")
            if args.command == "backup":
                result = authority.backup(args.output)
            elif args.command == "restore":
                result = authority.restore(args.input, accept_rollback=args.accept_rollback)
            elif args.command == "recover":
                result = authority.recover()
            else:
                exported = authority.export_log()
                atomic_write(args.output, canonical(exported))
                result = {"output": args.output, "events": len(exported["records"])}
        elif args.command in {"call", "rotate"}:
            identity = Identity.load(args.identity)
            client = Client(Remote(args.url, args.node), identity, load_json(args.trust))
            if args.command == "call":
                data = load_json(args.data[1:]) if args.data.startswith("@") else json.loads(args.data)
                if not isinstance(data, dict):
                    raise ValueError("data must be a JSON object")
                result = client.call(args.action, **data)
            else:
                key = new_identity()
                candidate = Path(args.identity) / f"v{identity.version + 1}.pem"
                if candidate.exists():
                    raise ValueError("rotation candidate already exists; reconcile directory version before retrying")
                atomic_write(candidate, private_bytes(key))
                # Preserve the candidate if the request outcome is uncertain after a transport failure.
                result = client.call("rotate", **identity.rotation(key))
                Identity(identity.device, key, result["version"]).save(args.identity)
        elif args.command in {"verify", "detect"}:
            exported, trust, checkpoint = load_json(args.log), load_json(args.trust), load_json(args.checkpoint)
            head = verify_log(exported["records"], trust, checkpoint)
            result = {"verified": True, "head": head}
            if args.command == "detect":
                result.update(analyze([r["body"] for r in exported["records"]]))
            if args.output:
                atomic_write(args.output, canonical(result))
        elif args.command == "watch":
            from .client import Local
            from .watch import Watcher
            authority = Authority(args.state, args.operator)
            responder = None
            if not args.no_respond:
                if not args.identity:
                    raise ValueError("--identity is required unless --no-respond is given")
                responder = Client(Local(authority, args.node), Identity.load(args.identity), authority.trust)
            alerts = Watcher(authority, responder, args.output).run(
                args.interval, args.once, progress=lambda line: print(line, file=sys.stderr, flush=True))
            result = {"alerts": len(alerts)}
        elif args.command == "practice":
            from .practice import DEFAULT_POLICY, run
            result = run(args.toolkit, args.policy or DEFAULT_POLICY, use_policy=not args.no_policy)
            if args.output:
                atomic_write(args.output, canonical(result))
        elif args.command == "evaluate":
            result = evaluate(load_json(args.input))
            if args.output:
                atomic_write(args.output, canonical(result))
        print(json.dumps(result, indent=2, allow_nan=False))
        return 0
    except (Denied, InvalidSignature, ValueError, TypeError, KeyError, OSError, sqlite3.Error) as exc:
        print(json.dumps({"error": str(exc) or type(exc).__name__}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
