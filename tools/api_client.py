"""CLI for ad-hoc API queries via the PlenithClient SDK.

Useful for SOC analysts on the command line, CI smoke tests, and
operator runbooks.

Usage:
    python tools/api_client.py health
    python tools/api_client.py engagements                  # list (newest first)
    python tools/api_client.py engagements --severity high
    python tools/api_client.py engagement <id_prefix>       # full detail
    python tools/api_client.py narrate <id_prefix>          # LLM summary
    python tools/api_client.py validate                     # trigger isolation probe
    python tools/api_client.py mfa-decide <ip> --decision pass --reason "approved by SOC L2"
    python tools/api_client.py metrics                      # Prometheus exposition

Env:
    PLENITH_API_URL    base URL (default http://127.0.0.1:8080)
    PLENITH_API_TOKEN  bearer token if the server has auth on
"""
import argparse
import asyncio
import io
import json
import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, io.UnsupportedOperation, ValueError):
    pass

from plenith.api import PlenithClient  # noqa: E402


def color(c: str, s: str) -> str:
    return f"\033[{c}m{s}\033[0m"


_SEV_COLOR = {
    "critical": "31",
    "high":     "33",
    "medium":   "36",
    "info":     "90",
    "low":      "37",
}


async def _client_from_env(args):
    return PlenithClient(
        base_url=args.url, token=args.token,
        timeout_seconds=15.0, verify_tls=not args.insecure,
    )


async def cmd_health(args):
    async with await _client_from_env(args) as c:
        print(json.dumps(await c.health(), indent=2))
    return 0


async def cmd_engagements(args):
    async with await _client_from_env(args) as c:
        engs = await c.list_engagements(
            user=args.user, ip=args.ip, severity=args.severity,
            since_seconds=args.since_seconds, limit=args.limit,
        )
    if not engs:
        print(color("90", "(no engagements matched)"))
        return 0
    print(color("1", f"{'ID':<10} {'USER':<10} {'IP':<16} {'CONNS':>5} {'SEV':>8}  ALERTS"))
    print("-" * 70)
    for e in engs:
        sev = e.get("severity_max", "info")
        col = _SEV_COLOR.get(sev, "0")
        print(
            f"{e['engagement_id'][:8]:<10} "
            f"{e.get('claimed_user', '?'):<10} "
            f"{e.get('source_ip', '?'):<16} "
            f"{e.get('connection_count', 1):>5} "
            f"{color(col, sev.rjust(8))}  "
            f"{e.get('alert_count', 0)}"
        )
    return 0


async def cmd_engagement(args):
    async with await _client_from_env(args) as c:
        e = await c.get_engagement(args.id_prefix)
    print(json.dumps(e, indent=2, default=str))
    return 0


async def cmd_narrate(args):
    async with await _client_from_env(args) as c:
        narr = await c.get_narrative(args.id_prefix)
    print(color("1;36", f"=== Engagement {narr['engagement_id'][:8]} narrative ==="))
    print()
    print(narr["narrative"])
    return 0


async def cmd_validate(args):
    async with await _client_from_env(args) as c:
        r = await c.validate_isolation()
    ok_color = "32" if r["succeeded"] else "31"
    print(color(ok_color, f"{'OK' if r['succeeded'] else 'FAILED'}: "
                            f"{r['pass_count']}/{r['total']} probes passed"))
    return 0 if r["succeeded"] else 1


async def cmd_mfa_decide(args):
    async with await _client_from_env(args) as c:
        r = await c.write_mfa_decision(args.ip, args.decision, args.reason)
    print(json.dumps(r, indent=2))
    return 0


async def cmd_metrics(args):
    async with await _client_from_env(args) as c:
        text = await c.metrics_text()
    print(text)
    return 0


async def cmd_openapi(args):
    async with await _client_from_env(args) as c:
        schema = await c.openapi()
    if args.out:
        Path(args.out).write_text(json.dumps(schema, indent=2), encoding="utf-8")
        print(color("32", f"wrote {args.out}"))
    else:
        print(json.dumps(schema, indent=2))
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--url",
                   default=os.environ.get("PLENITH_API_URL", "http://127.0.0.1:8080"))
    p.add_argument("--token",
                   default=os.environ.get("PLENITH_API_TOKEN"))
    p.add_argument("--insecure", action="store_true",
                   help="skip TLS verify (dev only)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("health",  help="liveness probe")
    sub.add_parser("metrics", help="Prometheus exposition")
    o = sub.add_parser("openapi", help="OpenAPI 3 schema")
    o.add_argument("--out", help="write to file instead of stdout")

    e = sub.add_parser("engagements", help="list engagements")
    e.add_argument("--user")
    e.add_argument("--ip")
    e.add_argument("--severity", choices=("critical", "high", "medium", "info", "low"))
    e.add_argument("--since-seconds", type=float)
    e.add_argument("--limit", type=int, default=100)

    ed = sub.add_parser("engagement", help="engagement detail")
    ed.add_argument("id_prefix")

    n = sub.add_parser("narrate", help="LLM-narrated summary of an engagement")
    n.add_argument("id_prefix")

    sub.add_parser("validate", help="trigger an isolation probe run")

    m = sub.add_parser("mfa-decide", help="write a manual MFA decision")
    m.add_argument("ip")
    m.add_argument("--decision", required=True, choices=("pass", "fail"))
    m.add_argument("--reason")

    handlers = {
        "health":      cmd_health,
        "metrics":     cmd_metrics,
        "openapi":     cmd_openapi,
        "engagements": cmd_engagements,
        "engagement":  cmd_engagement,
        "narrate":     cmd_narrate,
        "validate":    cmd_validate,
        "mfa-decide":  cmd_mfa_decide,
    }
    args = p.parse_args(argv)
    return asyncio.run(handlers[args.cmd](args))


if __name__ == "__main__":
    raise SystemExit(main())
