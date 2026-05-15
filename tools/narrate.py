"""CLI: render an LLM-narrated exec summary for an engagement.

Usage:
    python tools/narrate.py <engagement_id_prefix>
    python tools/narrate.py <engagement_id_prefix> --out report.md
    python tools/narrate.py <engagement_id_prefix> --state-dir state-docker/persistence --logs-dir state-docker/logs

Reads the engagement state via the same loader audit.py uses, calls
the configured LMStudio LLM with a structured prompt, and prints (or
writes) the markdown narrative.
"""
import argparse
import asyncio
import importlib.util
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

from plenith.llm_client import LMStudioClient  # noqa: E402
from plenith.narrate import input_from_engagement, narrate  # noqa: E402

def _load_audit():
    spec = importlib.util.spec_from_file_location("audit", _ROOT / "tools" / "audit.py")
    audit = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(audit)
    return audit

def _build_llm(cfg: dict) -> LMStudioClient:
    llm_cfg = cfg.get("llm", {})
    return LMStudioClient(
        base_url=llm_cfg.get("base_url", "http://localhost:1234/v1"),
        model=llm_cfg.get("model", "qwen2.5-7b-instruct-1m"),
        api_key=llm_cfg.get("api_key", "lm-studio"),
        temperature=float(llm_cfg.get("temperature", 0.3)),
        max_tokens=int(llm_cfg.get("max_tokens", 800)),
        timeout_seconds=float(llm_cfg.get("timeout_seconds", 60)),
    )

def color(c: str, s: str) -> str:
    return f"\033[{c}m{s}\033[0m"

def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("prefix", help="engagement-id prefix (e.g. '7b6c')")
    p.add_argument("--state-dir", type=Path,
                   default=_ROOT / "state-docker" / "persistence",
                   help="directory of engagement state JSONs")
    p.add_argument("--logs-dir", type=Path,
                   default=_ROOT / "state-docker" / "logs",
                   help="root of per-host logs/")
    p.add_argument("--personas-dir", type=Path,
                   default=_ROOT / "personas")
    p.add_argument("--out", type=Path, default=None,
                   help="write the narrative to this file (default: stdout)")
    p.add_argument("--config", type=Path,
                   default=_ROOT / "config.yaml",
                   help="path to config.yaml (for LLM endpoint config)")
    args = p.parse_args(argv)

    if not args.config.exists():
        print(color("31", f"config not found: {args.config}"), file=sys.stderr)
        return 2
    cfg = yaml.safe_load(args.config.read_text(encoding="utf-8"))
    llm = _build_llm(cfg)

    audit = _load_audit()

    # Walk every per-host logs subdirectory under logs-dir/
    logs_dirs = [d for d in args.logs_dir.iterdir() if d.is_dir()] if args.logs_dir.exists() else [args.logs_dir]
    engagements = []
    for d in logs_dirs:
        try:
            engagements.extend(audit.load_engagements(args.state_dir, d, args.personas_dir))
        except Exception:
            continue

    matches = [e for e in engagements if e["engagement_id"].startswith(args.prefix)]
    if not matches:
        print(color("31", f"no engagement matching prefix {args.prefix!r}"),
              file=sys.stderr)
        return 1
    if len(matches) > 1:
        print(color("31",
                    f"ambiguous prefix {args.prefix!r}: matched "
                    f"{[m['engagement_id'][:8] for m in matches]}"),
              file=sys.stderr)
        return 1

    eng = matches[0]
    inp = input_from_engagement(eng)
    print(color("36", f"[narrate] engagement={eng['engagement_id'][:8]}  "
                       f"user={inp.claimed_user}  ip={inp.source_ip}  "
                       f"cmds={len(inp.commands)}  alerts={len(inp.alerts)}"),
          file=sys.stderr)
    print(color("36", f"[narrate] calling {cfg['llm']['model']} at "
                       f"{cfg['llm']['base_url']} ..."), file=sys.stderr)

    try:
        narrative = asyncio.run(narrate(inp, llm))
    except Exception as e:
        print(color("31", f"[narrate] LLM call failed: {type(e).__name__}: {e}"),
              file=sys.stderr)
        return 3

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(narrative.strip() + "\n", encoding="utf-8")
        print(color("32", f"[narrate] wrote {args.out}"), file=sys.stderr)
    else:
        print(narrative.strip())

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
