"""CLI: render §13 operational runbooks.

Usage:
    python tools/runbook.py                                 # list available
    python tools/runbook.py all --out docs/runbooks/        # write every runbook
    python tools/runbook.py dr                               # print one to stdout
    python tools/runbook.py retention --out retention.md
"""
import argparse
import io
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, io.UnsupportedOperation, ValueError):
    pass

import yaml  # noqa: E402

from plenith.compliance import runbooks  # noqa: E402

_RUNBOOK_HANDLERS = {
    "retention": runbooks.retention_runbook,
    "raci":      runbooks.ir_raci_runbook,
    "burndown":  runbooks.burndown_runbook,
    "capacity":  runbooks.capacity_runbook,
    "rotation":  runbooks.rotation_runbook,
    "dr":        runbooks.dr_runbook,
}

def color(c: str, s: str) -> str:
    return f"\033[{c}m{s}\033[0m"

def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("runbook", nargs="?",
                   choices=list(_RUNBOOK_HANDLERS.keys()) + ["all"],
                   help="which runbook to render (omit to list)")
    p.add_argument("--out", type=Path, default=None,
                   help="write to this path (file for single, directory for `all`)")
    p.add_argument("--config", type=Path, default=_ROOT / "config.yaml")
    args = p.parse_args(argv)

    cfg = {}
    if args.config.exists():
        try:
            cfg = yaml.safe_load(args.config.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError:
            pass
    ctx = runbooks.build_context_from_config(cfg)

    if args.runbook is None:
        print(color("1", "Available runbooks:"))
        for k in _RUNBOOK_HANDLERS:
            print(f"  {k}")
        print(color("90", "  (or `all` to render every runbook)"))
        return 0

    if args.runbook == "all":
        all_books = runbooks.render_all(ctx)
        if args.out:
            args.out.mkdir(parents=True, exist_ok=True)
            for name, body in all_books.items():
                (args.out / name).write_text(body, encoding="utf-8")
            print(color("32", f"wrote {len(all_books)} runbooks → {args.out}"))
        else:
            for name, body in all_books.items():
                print(color("1;36", f"\n{'=' * 70}\n  {name}\n{'=' * 70}"))
                print(body)
        return 0

    body = _RUNBOOK_HANDLERS[args.runbook](ctx)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(body, encoding="utf-8")
        print(color("32", f"wrote {args.out}"))
    else:
        print(body)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
