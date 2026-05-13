"""Inspect + verify secret references in a config file.

Two modes:
  --list (default):    walk config.yaml and print every reference URI
                       found, without touching the backend.
  --resolve:           actually attempt to resolve each reference and
                       report success / failure. Failed resolutions exit
                       non-zero so this is cron-suitable in staging.

Usage:
    # See what references are in your config
    python tools/secrets_check.py

    # Test that every reference resolves (for a staging gate)
    python tools/secrets_check.py --resolve

    # Use a specific config file
    python tools/secrets_check.py --config /etc/plenith/config.yaml

    # Emit JSON for CI
    python tools/secrets_check.py --resolve --json

Exit codes:
     0  all references resolved (or just listed, in --list mode)
     1  at least one reference failed to resolve
     2  bad arguments / config not found / parse error
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml   # noqa: E402

from plenith.secrets import (   # noqa: E402
    SecretResolutionError,
    find_references,
    redact,
    registered_schemes,
    resolve,
)

EXIT_OK = 0
EXIT_RESOLVE_FAILURES = 1
EXIT_BAD_ARGS = 2


def main(argv=None):
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    default_cfg = Path(__file__).resolve().parent.parent / "config.yaml"
    p.add_argument("--config", type=Path, default=default_cfg)
    p.add_argument(
        "--resolve", action="store_true",
        help="Actually resolve each reference (calls Vault / AWS / file IO). "
             "Without this flag, only the URIs are listed.",
    )
    p.add_argument(
        "--json", action="store_true",
        help="Emit JSON output suitable for CI / monitoring.",
    )
    p.add_argument(
        "--show-redacted", action="store_true",
        help="Also dump the post-resolution config tree with sensitive "
             "values masked. Useful for debugging a deployment.",
    )
    args = p.parse_args(argv)

    if not args.config.exists():
        msg = f"config file not found: {args.config}"
        if args.json:
            print(json.dumps({"error": msg}))
        else:
            print(f"error: {msg}", file=sys.stderr)
        return EXIT_BAD_ARGS

    try:
        raw = yaml.safe_load(args.config.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        msg = f"could not parse {args.config}: {e}"
        if args.json:
            print(json.dumps({"error": msg}))
        else:
            print(f"error: {msg}", file=sys.stderr)
        return EXIT_BAD_ARGS

    references = find_references(raw)

    if not args.resolve:
        # List mode — no backend calls
        out = {
            "config":           str(args.config),
            "schemes_available": registered_schemes(),
            "reference_count":  len(references),
            "references":       [
                {"path": p_, "uri": u} for p_, u in references
            ],
        }
        if args.json:
            print(json.dumps(out, indent=2))
        else:
            _render_list(out)
        return EXIT_OK

    # Resolve mode — call backends
    results = []
    n_ok = 0
    n_fail = 0
    for field_path, uri in references:
        try:
            # Resolve through the full machinery so caching + default
            # handling matches production behavior.
            resolve({field_path: uri})
            results.append({"path": field_path, "uri": uri, "ok": True})
            n_ok += 1
        except SecretResolutionError as e:
            results.append({
                "path": field_path, "uri": uri,
                "ok": False, "error": str(e),
            })
            n_fail += 1

    out = {
        "config":         str(args.config),
        "total":          len(references),
        "resolved":       n_ok,
        "failed":         n_fail,
        "results":        results,
    }
    if args.show_redacted:
        try:
            resolved_cfg = resolve(raw)
            out["redacted_resolved_config"] = redact(resolved_cfg)
        except SecretResolutionError as e:
            out["redacted_resolved_config"] = f"<resolution failed: {e}>"

    if args.json:
        print(json.dumps(out, indent=2))
    else:
        _render_resolve(out)

    return EXIT_RESOLVE_FAILURES if n_fail else EXIT_OK


def _render_list(out):
    print(f"Config: {out['config']}")
    print(f"Schemes available: {', '.join(out['schemes_available'])}")
    print()
    if not out["references"]:
        print("(no secret references found — config uses plaintext only)")
        return
    print(f"{'FIELD':<40} {'URI'}")
    print("-" * 100)
    for r in out["references"]:
        print(f"{r['path']:<40} {r['uri']}")
    print()
    print(f"Total: {out['reference_count']} reference(s)")


def _render_resolve(out):
    print(f"Config: {out['config']}")
    print()
    if not out["results"]:
        print("(no secret references found)")
        return
    print(f"{'STATUS':<6} {'FIELD':<40} {'URI'}")
    print("-" * 100)
    for r in sorted(out["results"], key=lambda r: (r["ok"], r["path"])):
        status = "OK" if r["ok"] else "FAIL"
        print(f"{status:<6} {r['path']:<40} {r['uri']}")
        if not r["ok"]:
            print(f"        └── {r['error']}")
    print()
    print(f"Summary: {out['resolved']} OK, {out['failed']} FAIL "
           f"(of {out['total']} reference(s))")


if __name__ == "__main__":
    sys.exit(main())
