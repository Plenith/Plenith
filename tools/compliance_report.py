"""CLI: generate a SOC 2 / ISO 27001 / NIS2 attestation report.

Usage:
    python tools/compliance_report.py                      # Markdown to stdout
    python tools/compliance_report.py --html report.html
    python tools/compliance_report.py --json report.json
    python tools/compliance_report.py --framework soc2     # subset
    python tools/compliance_report.py --period-days 30     # custom window
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

from plenith.compliance import controls, evidence, report  # noqa: E402

def color(c: str, s: str) -> str:
    return f"\033[{c}m{s}\033[0m"

def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--framework",
                   choices=("soc2", "iso27001", "nis2", "all"), default="all",
                   help="which framework(s) to report on (default: all)")
    p.add_argument("--period-days", type=int, default=90,
                   help="reporting window in days (default: 90)")
    p.add_argument("--state-dir", type=Path,
                   default=_ROOT / "state" / "persistence",
                   help="engagement state dir")
    p.add_argument("--docker-state-dir", type=Path,
                   default=_ROOT / "state-docker" / "persistence",
                   help="docker-fabric state dir (also harvested)")
    p.add_argument("--logs-dir", type=Path,
                   default=_ROOT / "state-docker" / "logs",
                   help="per-host logs dir")
    p.add_argument("--mfa-dir", type=Path,
                   default=_ROOT / "state-docker" / "mfa")
    p.add_argument("--rotation-dir", type=Path,
                   default=_ROOT / "state" / "content")
    p.add_argument("--config", type=Path,
                   default=_ROOT / "config.yaml")
    p.add_argument("--html", type=Path,
                   help="write HTML to this file (in addition to stdout)")
    p.add_argument("--json", type=Path,
                   help="write JSON to this file (for GRC ingest)")
    p.add_argument("--md", type=Path,
                   help="write Markdown to this file (default: stdout)")
    p.add_argument("--quiet", action="store_true",
                   help="suppress stdout markdown when --html/--json/--md given")
    args = p.parse_args(argv)

    # Load config (for connectors / policy engine)
    cfg = {}
    if args.config.exists():
        try:
            cfg = yaml.safe_load(args.config.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError:
            pass

    # Harvest evidence — prefer docker-state if it exists (live fabric)
    state_dir = args.docker_state_dir if args.docker_state_dir.exists() else args.state_dir

    print(color("36", f"[harvest] state_dir={state_dir}"), file=sys.stderr)
    print(color("36", f"[harvest] logs_dir ={args.logs_dir}"), file=sys.stderr)
    print(color("36", f"[harvest] period   ={args.period_days} days"), file=sys.stderr)

    ev = evidence.collect(
        state_dir=state_dir,
        logs_dir=args.logs_dir,
        mfa_dir=args.mfa_dir,
        rotation_dir=args.rotation_dir,
        config=cfg,
        period_days=args.period_days,
    )

    if args.framework == "all":
        controls_list = controls.all_controls()
    else:
        controls_list = controls.controls_for(args.framework)
    title = f"Plenith Attestation — {args.framework.upper()}"

    md = report.to_markdown(controls_list, ev, title=title)

    if args.html:
        args.html.parent.mkdir(parents=True, exist_ok=True)
        args.html.write_text(report.to_html(controls_list, ev, title=title),
                             encoding="utf-8")
        print(color("32", f"[wrote] {args.html}"), file=sys.stderr)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(report.to_json(controls_list, ev, title=title),
                             encoding="utf-8")
        print(color("32", f"[wrote] {args.json}"), file=sys.stderr)
    if args.md:
        args.md.parent.mkdir(parents=True, exist_ok=True)
        args.md.write_text(md, encoding="utf-8")
        print(color("32", f"[wrote] {args.md}"), file=sys.stderr)

    if not args.quiet and not (args.html or args.json or args.md):
        sys.stdout.write(md)
    elif not args.quiet:
        # Summary line only
        n = len(controls_list)
        ev_count = sum(
            1 for c in controls_list
            if report._assess(c, ev)["status"] == "evidence-present"
        )
        pct = (ev_count / n * 100) if n else 0
        print(color("1", f"[summary] {n} controls in scope, "
                          f"{ev_count} with evidence ({pct:.0f}%)"),
              file=sys.stderr)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
