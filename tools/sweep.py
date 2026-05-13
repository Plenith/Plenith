"""Retention sweeper for Plenith engagement state + per-connection logs.

By default, dry-run only — prints what would be deleted. Pass `--apply` to
actually delete. Keep window is configurable via `--keep-days N` (default 30).

Usage:
    python tools/sweep.py                      # dry-run, default 30-day window
    python tools/sweep.py --keep-days 7        # dry-run, 7-day window
    python tools/sweep.py --keep-days 7 --apply
    python tools/sweep.py --verbose            # show every kept item too

Persistence files (state/persistence/*.json) are pruned based on their
last_seen_at field. Connection logs (logs/*.json) are pruned based on
their ended_at (or started_at) field.

Safe by default: a missing/corrupt JSON file is NEVER deleted automatically.
"""
import io
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
sys.path.insert(0, str(_ROOT))

if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")


def _iso(epoch):
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def sweep_persistence(state_dir, cutoff_epoch, apply_changes, verbose):
    """Delete persistence files whose last_seen_at < cutoff."""
    deleted = 0
    kept = 0
    skipped = 0
    if not state_dir.exists():
        return deleted, kept, skipped
    for f in sorted(state_dir.glob("*.json")):
        try:
            with open(f, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            skipped += 1
            print(f"  SKIP (unreadable): {f.name}  [{exc}]")
            continue
        last = data.get("last_seen_at") or data.get("first_seen_at") or 0
        if last < cutoff_epoch:
            action = "DELETE" if apply_changes else "would-delete"
            print(f"  {action}: {f.name}  (last_seen {_iso(last)})")
            if apply_changes:
                try:
                    f.unlink()
                    deleted += 1
                except OSError as exc:
                    print(f"    FAILED: {exc}")
            else:
                deleted += 1
        else:
            kept += 1
            if verbose:
                print(f"  keep:   {f.name}  (last_seen {_iso(last)})")
    return deleted, kept, skipped


def sweep_logs(logs_dir, cutoff_epoch, apply_changes, verbose):
    """Delete log files whose ended_at < cutoff."""
    deleted = 0
    kept = 0
    skipped = 0
    if not logs_dir.exists():
        return deleted, kept, skipped
    for f in sorted(logs_dir.glob("*.json")):
        try:
            with open(f, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            skipped += 1
            print(f"  SKIP (unreadable): {f.name}  [{exc}]")
            continue
        ts = data.get("ended_at") or data.get("started_at") or 0
        if ts < cutoff_epoch:
            action = "DELETE" if apply_changes else "would-delete"
            print(f"  {action}: {f.name}  (ended {_iso(ts)})")
            if apply_changes:
                try:
                    f.unlink()
                    deleted += 1
                except OSError as exc:
                    print(f"    FAILED: {exc}")
            else:
                deleted += 1
        else:
            kept += 1
            if verbose:
                print(f"  keep:   {f.name}  (ended {_iso(ts)})")
    return deleted, kept, skipped


def main():
    args = sys.argv[1:]
    apply_changes = "--apply" in args
    verbose = "--verbose" in args or "-v" in args
    keep_days = 30
    for i, a in enumerate(args):
        if a == "--keep-days" and i + 1 < len(args):
            try:
                keep_days = int(args[i + 1])
            except ValueError:
                print(f"invalid --keep-days value: {args[i + 1]}", file=sys.stderr)
                sys.exit(2)

    cutoff = time.time() - keep_days * 86400
    mode = "APPLY (deleting)" if apply_changes else "DRY-RUN"
    print(f"Plenith sweep — {mode}, retention = {keep_days} day(s)")
    print(f"Cutoff: anything older than {_iso(cutoff)} is candidate.")
    print()

    state_dir = _ROOT / "state" / "persistence"
    logs_dir = _ROOT / "logs"

    print("== Persistence ==")
    p_del, p_kept, p_skip = sweep_persistence(state_dir, cutoff, apply_changes, verbose)
    print(f"  ({p_del} {'deleted' if apply_changes else 'candidates'}, "
          f"{p_kept} kept, {p_skip} skipped)")

    print()
    print("== Connection logs ==")
    l_del, l_kept, l_skip = sweep_logs(logs_dir, cutoff, apply_changes, verbose)
    print(f"  ({l_del} {'deleted' if apply_changes else 'candidates'}, "
          f"{l_kept} kept, {l_skip} skipped)")

    if not apply_changes:
        print()
        print("(dry-run — re-run with --apply to actually delete)")


if __name__ == "__main__":
    main()
