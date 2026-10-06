from __future__ import annotations

from pathlib import Path
from typing import Any
import argparse
import json
import sys

from .errors import LedgerError
from .ledger import LedgerStore
from .model import Cursor, ID_PREFIXES, new_id
from .render import write_projections


def _json_arg(value: str) -> Any:
    if value == "-":
        return json.load(sys.stdin)
    path = Path(value)
    if path.is_file():
        return json.loads(path.read_text(encoding="utf-8"))
    return json.loads(value)


def _print(value: Any) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="squawk-box", description="Append-only build continuity ledger")
    sub = p.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="initialize a ledger directory")
    init.add_argument("root")
    init.add_argument("--build-id", required=True)
    init.add_argument("--allowed-root", action="append", default=[])
    init.add_argument("--writer-isolation", choices=["os_separated", "cooperative_same_uid"], default="cooperative_same_uid")

    ids = sub.add_parser("new-id", help="generate a typed entity ID")
    ids.add_argument("kind", choices=sorted(ID_PREFIXES))

    payload = sub.add_parser("payload-put", help="store detached payload bytes")
    payload.add_argument("root")
    payload.add_argument("path", help="file path or - for stdin bytes")
    payload.add_argument("--media-type", default="application/octet-stream")

    submit = sub.add_parser("submit", help="validate and append one event submission")
    submit.add_argument("root")
    submit.add_argument("--reporter-type", required=True, choices=["manager", "human", "donsquad", "agentRun", "tool"])
    submit.add_argument("--reporter-id", required=True, help="identity bound by the intake channel, not the submitted JSON")
    submit.add_argument("--submission-id", required=True)
    submit.add_argument("--body", required=True, help="JSON literal, file path, or -")

    replay = sub.add_parser("replay", help="rebuild deterministic current state")
    replay.add_argument("root")
    replay.add_argument("--as-of")

    render = sub.add_parser("render", help="regenerate current state, briefs and self-contained HTML")
    render.add_argument("root")
    render.add_argument("--as-of")

    repair = sub.add_parser("repair-quarantine", help="append an exceptional human-authorized replay quarantine")
    repair.add_argument("root")
    repair.add_argument("--segment", type=int)
    repair.add_argument("--line", type=int)
    repair.add_argument("--event-id")
    repair.add_argument("--reason", required=True)
    repair.add_argument("--authorized-by", required=True)

    revoke = sub.add_parser("repair-revoke", help="revoke a prior quarantine")
    revoke.add_argument("root")
    revoke.add_argument("--repair-id", required=True)
    revoke.add_argument("--reason", required=True)
    revoke.add_argument("--authorized-by", required=True)

    purge = sub.add_parser("payload-purge", help="purge captured payload bytes and append purge history")
    purge.add_argument("root")
    purge.add_argument("digest")
    purge.add_argument("--reason", required=True)
    purge.add_argument("--secret-class")
    purge.add_argument("--authorized-by", required=True)
    purge.add_argument("--submission-id", required=True)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "new-id":
            print(new_id(args.kind))
            return 0
        store = LedgerStore(args.root)
        if args.command == "init":
            _print(store.initialize(build_id=args.build_id, allowed_roots=args.allowed_root, writer_isolation=args.writer_isolation))
        elif args.command == "payload-put":
            data = sys.stdin.buffer.read() if args.path == "-" else Path(args.path).read_bytes()
            _print(store.put_payload(data, media_type=args.media_type))
        elif args.command == "submit":
            body = _json_arg(args.body)
            _print(store.submit(reporter_type=args.reporter_type, reporter_id=args.reporter_id, submission_id=args.submission_id, body=body))
        elif args.command == "replay":
            _print(store.replay(as_of=args.as_of))
        elif args.command == "render":
            paths = write_projections(store, as_of=args.as_of)
            _print({k: str(v) for k, v in paths.items()})
        elif args.command == "repair-quarantine":
            cursor = None
            if args.segment is not None or args.line is not None:
                if args.segment is None or args.line is None:
                    raise LedgerError("--segment and --line must be supplied together")
                cursor = Cursor(args.segment, args.line)
            _print(store.record_repair(action="QUARANTINE", cursor=cursor, event_id=args.event_id, reason=args.reason, authorized_by=args.authorized_by))
        elif args.command == "repair-revoke":
            _print(store.record_repair(action="REVOKE_QUARANTINE", cursor=None, event_id=None, reason=args.reason, authorized_by=args.authorized_by, target_repair_id=args.repair_id))
        elif args.command == "payload-purge":
            _print(store.purge_payload(args.digest, reason=args.reason, secret_class=args.secret_class, authorized_by=args.authorized_by, submission_id=args.submission_id))
        return 0
    except LedgerError as exc:
        print(f"squawk-box: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
