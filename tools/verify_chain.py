"""Verify hash-chained engagement logs — SOC tamper-evidence CLI.

Walks one or more engagement-log files (or a directory of them) and
reports the integrity status of each. Exits 0 if every chain is clean,
non-zero if any chain is broken — the same exit-code contract
`tools/restore.py` uses, so it slots into a nightly cron without
extra wrapping.

Usage:
    # one file
    python tools/verify_chain.py state-docker/logs/host/12345_abc.json

    # one directory (default: walk state-docker/logs/)
    python tools/verify_chain.py state-docker/logs/

    # JSON output for scraping into a monitoring pipeline
    python tools/verify_chain.py --json state-docker/logs/

    # be strict about legacy logs (refuse them with non-zero exit)
    python tools/verify_chain.py --no-allow-legacy state-docker/logs/

Exit codes:
     0  every chain verified
     1  at least one chain broken
     2  bad arguments (file not found, etc.)

Designed to drop into cron:

    0 4 * * * /opt/plenith/.venv/bin/python \\
              /opt/plenith/tools/verify_chain.py \\
              /opt/plenith/state-docker/logs/ >> /var/log/plenith/chain.log 2>&1
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow running this script directly: `python tools/verify_chain.py ...`
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from plenith.audit_chain import verify_session   # noqa: E402

EXIT_OK = 0
EXIT_BROKEN = 1
EXIT_BAD_ARGS = 2

def _walk_files(target: Path):
    """Yield .json paths under `target`. If `target` is a file, yield
    just that file. We skip files starting with `.` (e.g. partial
    writes during a process that crashed mid-flush)."""
    if target.is_file():
        yield target
        return
    if not target.exists():
        return
    for p in sorted(target.rglob("*.json")):
        if p.name.startswith("."):
            continue
        yield p

def _verify_one(path: Path):
    """Verify one engagement log. Returns a dict suitable for either
    table or JSON output."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as e:
        return {
            "path": str(path), "status": "unreadable", "reason": str(e),
            "ok": False, "legacy": False,
        }
    except json.JSONDecodeError as e:
        return {
            "path": str(path), "status": "invalid_json", "reason": str(e),
            "ok": False, "legacy": False,
        }
    if not isinstance(data, dict):
        return {
            "path": str(path), "status": "invalid_shape",
            "reason": "expected dict at top level", "ok": False, "legacy": False,
        }
    result = verify_session(data)
    status = (
        "ok" if result.ok and not result.legacy else
        "legacy" if result.legacy else
        "broken"
    )
    return {
        "path":         str(path),
        "engagement":   data.get("engagement_id", "?"),
        "host":         data.get("source_ip", "?"),
        "user":         data.get("claimed_user", "?"),
        "status":       status,
        "ok":           result.ok,
        "legacy":       result.legacy,
        "length":       result.length,
        "break_at":     result.break_at,
        "reason":       result.reason,
    }

def _render_table(records, *, allow_legacy: bool) -> int:
    """Print a one-line-per-file table. Returns the process exit code."""
    if not records:
        print("(no engagement logs found)")
        return EXIT_OK

    # Sort: failures first, then legacy, then clean
    rank = {"broken": 0, "unreadable": 0, "invalid_json": 0,
            "invalid_shape": 0, "legacy": 1, "ok": 2}
    records = sorted(records, key=lambda r: (rank.get(r["status"], 9), r["path"]))

    n_ok = sum(1 for r in records if r["status"] == "ok")
    n_legacy = sum(1 for r in records if r["status"] == "legacy")
    n_bad = len(records) - n_ok - n_legacy

    width_path = max(20, min(70, max(len(r["path"]) for r in records)))
    print(f"{'STATUS':<8} {'LEN':>4} {'ENGAGEMENT':<38} {'PATH'}")
    print("-" * (8 + 1 + 4 + 1 + 38 + 1 + min(width_path, 70)))
    for r in records:
        eng = r.get("engagement", "?")[:38]
        ln = r.get("length", 0) or 0
        status_label = r["status"].upper()
        line = f"{status_label:<8} {ln:>4} {eng:<38} {r['path']}"
        print(line)
        if not r["ok"] and r["status"] != "legacy":
            extra_bits = []
            if r.get("break_at") is not None:
                extra_bits.append(f"break_at={r['break_at']}")
            if r.get("reason"):
                extra_bits.append(f"reason={r['reason']}")
            if extra_bits:
                print(f"         └── {' | '.join(extra_bits)}")

    print()
    print(f"Summary: {n_ok} OK, {n_legacy} LEGACY, {n_bad} BROKEN "
           f"(of {len(records)} log file(s))")

    if n_bad > 0:
        return EXIT_BROKEN
    if n_legacy > 0 and not allow_legacy:
        print()
        print("Failing because legacy (un-chained) logs are present and "
              "--no-allow-legacy was passed.")
        return EXIT_BROKEN
    return EXIT_OK

def _render_json(records) -> int:
    n_bad = sum(1 for r in records if not r["ok"])
    print(json.dumps({
        "total":   len(records),
        "ok":      sum(1 for r in records if r["status"] == "ok"),
        "legacy":  sum(1 for r in records if r["status"] == "legacy"),
        "broken":  n_bad,
        "records": records,
    }, indent=2))
    return EXIT_BROKEN if n_bad else EXIT_OK

def main(argv=None):
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "target", nargs="?",
        default="state-docker/logs",
        help="Engagement log file OR directory of logs "
              "(default: state-docker/logs)",
    )
    p.add_argument(
        "--json", action="store_true",
        help="Emit JSON instead of a table (good for monitoring pipelines)",
    )
    p.add_argument(
        "--no-allow-legacy", action="store_true",
        help="Treat legacy (un-chained) logs as failures. Use after the "
             "rollout window has passed and every running agent has "
             "audit_chain enabled.",
    )
    args = p.parse_args(argv)

    target = Path(args.target)
    if not target.exists():
        print(f"error: path does not exist: {target}", file=sys.stderr)
        return EXIT_BAD_ARGS

    records = [_verify_one(p) for p in _walk_files(target)]

    if args.json:
        return _render_json(records)
    return _render_table(records, allow_legacy=not args.no_allow_legacy)

if __name__ == "__main__":
    sys.exit(main())
