"""Unified connectors CLI — show every emitter format + STIX export.

Usage:
    python tools/connectors.py demo
        Demo: render one fake alert through every emitter format
        (CEF, LEEF, syslog, JSON, Slack payload, Teams payload, PagerDuty).
        Prints to stdout. Useful when configuring a new SIEM to confirm
        the wire format before wiring up the real endpoint.

    python tools/connectors.py mitre <action>
        Print the ATT&CK technique mapping for one Plenith action.

    python tools/connectors.py coverage
        ATT&CK coverage report — every action and the techniques it tags.

    python tools/connectors.py stix --state-dir DIR --logs-dir DIR
        Build a STIX 2.1 bundle from every engagement in the state dir
        and print to stdout.

    python tools/connectors.py send <alert-json>
        POST a single alert dict to every connector configured in
        config.yaml. Used to manually test the full chain.
"""
import argparse
import asyncio
import importlib.util
import io
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, io.UnsupportedOperation, ValueError):
    pass

import yaml  # noqa: E402

from plenith.connectors import (  # noqa: E402
    chatops, formats, mitre, siem, soar, stix, taxii,
)

def color(c: str, s: str) -> str:
    return f"\033[{c}m{s}\033[0m"

def banner(s: str) -> None:
    print()
    print(color("1;36", "=" * 70))
    print(color("1;36", f"  {s}"))
    print(color("1;36", "=" * 70))

_DEMO_ALERT = {
    "action":       "alert_credential_exfil",
    "severity":     "high",
    "rationale":    "Attacker read planted ~/.aws/credentials honeytoken.",
    "engagement_id": "7b6cf125-abc1-4111-9999-000000000001",
    "source_ip":    "192.0.2.99",
    "claimed_user": "jdoe",
    "hostname":     "bastion-prod",
    "triggered_by": "cat ~/.aws/credentials",
    "ts_offset_s":  124.5,
}

def cmd_demo(_args):
    """Render the demo alert through every formatter."""
    alert = dict(_DEMO_ALERT)
    mitre.enrich(alert)   # adds mitre_technique, mitre_tactic, etc.

    banner("CEF (ArcSight / Splunk / QRadar / LogRhythm / Sumo / Devo)")
    print(formats.to_cef(alert))

    banner("LEEF (IBM QRadar native)")
    print(formats.to_leef(alert))

    banner("Syslog RFC 5424 (wrapped CEF body)")
    print(formats.to_syslog_5424(alert, body_format="cef"))

    banner("JSON event (Splunk HEC / Elastic / Datadog / Sumo)")
    print(json.dumps(formats.to_json_event(alert), indent=2))

    banner("Slack webhook payload")
    print(json.dumps(chatops.SlackWebhook(url="https://example.invalid")
                     ._payload(alert), indent=2))

    banner("Microsoft Teams MessageCard payload")
    print(json.dumps(chatops.TeamsWebhook(url="https://example.invalid")
                     ._payload(alert), indent=2))

    banner("PagerDuty Events API v2 payload")
    print(json.dumps(chatops.PagerDutyEventsV2(routing_key="EXAMPLE")
                     ._payload(alert), indent=2))

    banner("MITRE ATT&CK enrichment fields on the alert")
    for k in ("mitre_technique", "mitre_technique_name",
              "mitre_tactic", "mitre_tactic_id", "mitre_techniques"):
        if alert.get(k):
            print(f"  {k:<24s} = {alert[k]}")
    return 0

def cmd_mitre(args):
    """Show ATT&CK mappings for a specific action."""
    mappings = mitre.all_techniques_for(args.action)
    if not mappings:
        print(color("31", f"no MITRE mapping for action {args.action!r}"),
              file=sys.stderr)
        return 1
    print(color("1", f"MITRE ATT&CK mappings for {args.action}:"))
    for m in mappings:
        print(f"  {m.technique:<14s} {m.technique_name}")
        print(f"  {'':<14s} → tactic: {m.tactic} ({m.tactic_id})")
    print()
    print(color("1", "Sigma rule tags (drop into your rule's `tags:` field):"))
    for t in mitre.sigma_tags(args.action):
        print(f"  - {t}")
    return 0

def cmd_coverage(_args):
    """Print the full ATT&CK coverage map."""
    rep = mitre.coverage_report()
    print(color("1", "Plenith → MITRE ATT&CK coverage"))
    print(f"  Tactics covered     ({len(rep['tactics_covered'])}): "
          + ", ".join(rep["tactics_covered"]))
    print(f"  Techniques covered  ({len(rep['techniques_covered'])}): "
          + ", ".join(rep["techniques_covered"]))
    print()
    print(color("1", "Per-action breakdown:"))
    for action, mappings in sorted(rep["actions"].items()):
        print(f"  {action}")
        for m in mappings:
            print(f"    └─ {m['technique']:<14s} {m['name']}")
    return 0

def cmd_stix(args):
    """Build a STIX 2.1 bundle from real engagement state."""
    spec = importlib.util.spec_from_file_location("audit", _ROOT / "tools" / "audit.py")
    audit = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(audit)
    state_dir = args.state_dir
    logs_dir  = args.logs_dir
    personas  = _ROOT / "personas"

    logs_dirs = [d for d in logs_dir.iterdir() if d.is_dir()] if logs_dir.exists() else [logs_dir]
    engagements = []
    for d in logs_dirs:
        try:
            engagements.extend(audit.load_engagements(state_dir, d, personas))
        except Exception:
            continue

    bundle = stix.bundle_from_engagements(engagements)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
        print(color("32", f"[stix] wrote bundle ({len(bundle['objects'])} objects) → {args.out}"),
              file=sys.stderr)
    else:
        print(json.dumps(bundle, indent=2))
    return 0

def cmd_send(args):
    """POST a single alert through every configured connector."""
    cfg = yaml.safe_load(args.config.read_text(encoding="utf-8"))
    alert = json.loads(args.alert_json.read_text(encoding="utf-8"))
    mitre.enrich(alert)

    siem_fan = siem.build_from_config(cfg)
    chat_list = chatops.build_from_config(cfg)
    if not siem_fan and not chat_list:
        print(color("33", "no connectors configured in config.yaml — nothing to send"),
              file=sys.stderr)
        return 0

    async def go():
        if siem_fan:
            await siem_fan.emit(alert)
            await siem_fan.flush()
        for c in chat_list:
            await c.emit(alert)
    asyncio.run(go())
    print(color("32", "sent"))
    return 0

def cmd_taxii(args):
    """Publish engagement IoCs to every configured TAXII server."""
    cfg = {}
    if args.config.exists():
        cfg = yaml.safe_load(args.config.read_text(encoding="utf-8")) or {}
    clients = taxii.build_clients_from_config(cfg)
    if not clients:
        print(color("33", "no taxii servers configured (config.taxii.servers)"),
              file=sys.stderr)
        return 0
    # Build the bundle
    spec = importlib.util.spec_from_file_location("audit", _ROOT / "tools" / "audit.py")
    audit = importlib.util.module_from_spec(spec); spec.loader.exec_module(audit)
    logs_dirs = [d for d in args.logs_dir.iterdir() if d.is_dir()] if args.logs_dir.exists() else []
    engagements = []
    for d in logs_dirs:
        try:
            engagements.extend(audit.load_engagements(args.state_dir, d, _ROOT / "personas"))
        except Exception:
            continue

    fan = taxii.TAXIIFanOut(clients=clients)
    results = asyncio.run(fan.publish_engagements(engagements))
    print(color("1", f"published bundle to {len(results)} servers:"))
    for r in results:
        status = r.get("status", "?")
        sym = color("32", "ok") if status == "ok" else color("31", status)
        print(f"  {r.get('server', '?')}: [{sym}] objects={r.get('bundle_object_count', '?')}")
    # Exit 1 if any server failed (CI gate)
    return 0 if all(r.get("status") == taxii.TAXIIStatus.OK for r in results) else 1

def cmd_soar(args):
    """Export per-action SOAR playbook templates."""
    hints = soar.all_hints() if args.action == "all" else soar.hints_for(args.action)
    if not hints:
        print(color("31", f"no playbook hints for action {args.action!r}"),
              file=sys.stderr)
        return 1
    out_format = args.platform
    for hint in hints:
        if out_format == "xsoar":
            payload = soar.export_xsoar_playbook(hint)
        else:
            payload = soar.export_splunk_soar_playbook(hint)
        if args.out:
            outpath = args.out
            if args.action == "all":
                outpath.mkdir(parents=True, exist_ok=True)
                outpath = outpath / f"{out_format}-{hint.action}.json"
            outpath.write_text(json.dumps(payload, indent=2),
                                encoding="utf-8")
            print(color("32", f"wrote {outpath}"))
        else:
            print(color("1;36", f"# {hint.name} ({out_format})"))
            print(json.dumps(payload, indent=2))
    return 0

def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("demo", help="render one alert through every emitter format")

    pm = sub.add_parser("mitre", help="show ATT&CK mappings for one action")
    pm.add_argument("action")

    sub.add_parser("coverage", help="full ATT&CK coverage report")

    ps = sub.add_parser("stix", help="build a STIX 2.1 bundle from engagement state")
    ps.add_argument("--state-dir", type=Path,
                    default=_ROOT / "state-docker" / "persistence")
    ps.add_argument("--logs-dir", type=Path,
                    default=_ROOT / "state-docker" / "logs")
    ps.add_argument("--out", type=Path, default=None)

    px = sub.add_parser("send", help="POST one alert through every configured connector")
    px.add_argument("alert_json", type=Path)
    px.add_argument("--config", type=Path, default=_ROOT / "config.yaml")

    pt = sub.add_parser("taxii", help="publish engagement IoCs to TAXII servers")
    pt.add_argument("--state-dir", type=Path,
                    default=_ROOT / "state-docker" / "persistence")
    pt.add_argument("--logs-dir", type=Path,
                    default=_ROOT / "state-docker" / "logs")
    pt.add_argument("--config", type=Path, default=_ROOT / "config.yaml")

    pso = sub.add_parser("soar", help="export SOAR playbook templates")
    pso.add_argument("action", help="Plenith action or 'all'")
    pso.add_argument("--platform", choices=("xsoar", "splunk_soar"),
                     default="xsoar")
    pso.add_argument("--out", type=Path, default=None)

    args = p.parse_args(argv)
    handlers = {
        "demo":     cmd_demo,
        "mitre":    cmd_mitre,
        "coverage": cmd_coverage,
        "stix":     cmd_stix,
        "send":     cmd_send,
        "taxii":    cmd_taxii,
        "soar":     cmd_soar,
    }
    return handlers[args.cmd](args)

if __name__ == "__main__":
    raise SystemExit(main())
