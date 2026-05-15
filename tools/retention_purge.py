"""Retention purge CLI — actually deletes data per policy.

Wraps `plenith.retention` for cron / manual runs.

Default: --dry-run (prints what WOULD be deleted, deletes nothing).
Pass --apply to actually delete.

Usage:
    # See what would be deleted with the policy in config.yaml
    python tools/retention_purge.py

    # Actually delete
    python tools/retention_purge.py --apply

    # JSON output for monitoring
    python tools/retention_purge.py --apply --json

    # Subject access request: remove a specific person's records
    python tools/retention_purge.py --apply \\
        --filter source_ip=203.0.113.7 --confirm

    # Use overrides instead of config
    python tools/retention_purge.py --apply \\
        --engagements-days 60 --ioc-days 180

Cron example (daily 04:15 UTC):
    15 4 * * * /opt/plenith/.venv/bin/python \\
               /opt/plenith/tools/retention_purge.py --apply --json \\
               >> /var/log/plenith/retention.log 2>&1

Exit codes:
     0  clean run (whether or not anything was deleted)
     1  one or more file deletions failed
     2  bad arguments / configuration error
     3  refused for safety (e.g. filter without --confirm in --apply mode)
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml   # noqa: E402

from plenith.retention import (   # noqa: E402
    DEFAULT_WINDOWS,
    RetentionPolicy,
    purge,
)

EXIT_OK = 0
EXIT_DELETE_FAILURES = 1
EXIT_BAD_ARGS = 2
EXIT_REFUSED = 3

def _parse_filter_kv(raw: str) -> tuple[str, str]:
    """Parse `key=value` for the --filter argument."""
    if "=" not in raw:
        raise argparse.ArgumentTypeError(
            f"--filter expects key=value, got {raw!r}"
        )
    k, v = raw.split("=", 1)
    return k.strip(), v.strip()

def _build_filter_predicate(filters):
    """Build a predicate `(path, json_dict) -> bool` from --filter args.

    Predicate returns True if the file SHOULD be deleted. Each filter
    key is matched against `json_dict[key]` (top-level only, by design
    — operators can grep for nested keys with shell tools if they
    really need to).
    """
    if not filters:
        return None

    def pred(path, parsed):
        # Files we couldn't parse are skipped entirely under a filter
        # (safer than accidentally deleting them).
        if not parsed:
            return False
        for k, v in filters:
            actual = parsed.get(k)
            if actual is None or str(actual) != v:
                return False
        return True

    return pred

def _load_config_windows(cfg_path: Path) -> RetentionPolicy:
    if not cfg_path.exists():
        return RetentionPolicy()
    try:
        with cfg_path.open("r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError) as e:
        raise SystemExit(
            f"error: could not parse {cfg_path}: {e}"
        )
    return RetentionPolicy.from_config(cfg.get("retention") or {})

def _apply_cli_overrides(policy: RetentionPolicy, args) -> RetentionPolicy:
    overrides = {}
    for k in DEFAULT_WINDOWS:
        attr = f"{k}_days"
        val = getattr(args, attr, None)
        if val is not None:
            overrides[attr] = val
    if overrides:
        windows = dict(policy.windows)
        for k, v in overrides.items():
            windows[k[:-len("_days")]] = v
        return RetentionPolicy(windows=windows)
    return policy

def _render_summary(summary: dict) -> None:
    """Operator-friendly table output."""
    dry = summary["dry_run"]
    plan = summary["plan"]
    result = summary["result"]

    print(f"{'CATEGORY':<14} {'WINDOW':<7} {'DELETE':>7} {'BYTES':>14}  {'KEPT':>6}  ROOT")
    print("-" * 78)
    for name, cat in plan["categories"].items():
        marker = "(missing)" if cat["missing_root"] else ""
        print(
            f"{name:<14} {cat['window_days']:>5}d "
            f"{cat['delete_count']:>7} "
            f"{cat['delete_bytes']:>14,}  "
            f"{cat['kept_count']:>6}  {marker}"
        )
    print("-" * 78)
    mode = "DRY-RUN (no files deleted)" if dry else "APPLIED"
    print(
        f"Total to delete: {plan['total_files']} files "
        f"({plan['total_bytes']:,} bytes). Mode: {mode}."
    )
    if not dry:
        print(
            f"Deleted: {result['deleted']} files, "
            f"freed {result['bytes_freed']:,} bytes. "
            f"Failures: {result['failed']}."
        )
        if result["errors"]:
            print("First errors:")
            for e in result["errors"][:5]:
                print(f"  - {e}")

def main(argv=None):
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--root", type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="Repository root (containing state/ and state-docker/). "
             "Default: the repo this script lives in.",
    )
    p.add_argument(
        "--config", type=Path,
        default=None,
        help="Path to config.yaml. Default: <root>/config.yaml. "
             "Reads `retention:` block for policy.",
    )

    # Mode flags
    p.add_argument(
        "--apply", action="store_true",
        help="Actually delete files. Without this, --dry-run is the default.",
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help="Explicit dry-run. (This is the default; flag exists for clarity.)",
    )
    p.add_argument(
        "--json", action="store_true",
        help="Emit JSON output (good for cron + monitoring pipelines).",
    )

    # Per-category overrides
    for k in DEFAULT_WINDOWS:
        p.add_argument(
            f"--{k.replace('_', '-')}-days",
            dest=f"{k}_days",
            type=int, default=None,
            help=f"Override retention.{k}_days (default {DEFAULT_WINDOWS[k]})",
        )

    # Subject access request
    p.add_argument(
        "--filter", type=_parse_filter_kv, action="append", default=[],
        metavar="KEY=VALUE",
        help="Restrict deletion to engagement files where the top-level "
             "field KEY equals VALUE. Used for GDPR DSR fulfilment. "
             "Repeatable for AND-of-filters.",
    )
    p.add_argument(
        "--confirm", action="store_true",
        help="REQUIRED when combining --apply with --filter, to prevent "
             "accidentally widening a DSR purge.",
    )

    args = p.parse_args(argv)

    # Mode resolution: --apply overrides default; otherwise dry-run.
    dry_run = not args.apply

    # Safety interlock for DSR-style purges.
    if args.filter and not dry_run and not args.confirm:
        msg = (
            "error: --filter combined with --apply requires --confirm. "
            "This safety interlock prevents accidentally widening a "
            "subject-access-request purge into a broad deletion."
        )
        if args.json:
            print(json.dumps({"error": msg}))
        else:
            print(msg, file=sys.stderr)
        return EXIT_REFUSED

    # Load policy: file then CLI overrides
    cfg_path = args.config or (args.root / "config.yaml")
    try:
        policy = _load_config_windows(cfg_path)
    except SystemExit as e:
        if args.json:
            print(json.dumps({"error": str(e)}))
        else:
            print(str(e), file=sys.stderr)
        return EXIT_BAD_ARGS
    policy = _apply_cli_overrides(policy, args)

    # Build predicate (None if no filters)
    predicate = _build_filter_predicate(args.filter)

    # Run
    summary = purge(
        root=args.root,
        policy=policy,
        dry_run=dry_run,
        filter_predicate=predicate,
    )

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        _render_summary(summary)

    if summary["result"]["failed"] > 0:
        return EXIT_DELETE_FAILURES
    return EXIT_OK

if __name__ == "__main__":
    sys.exit(main())
