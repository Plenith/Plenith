"""Plenith engagement inspector.

Joins state/persistence/*.json (one per engagement key) with logs/*.json
(one per connection) by `engagement_id` and renders a SOC-friendly view.

Usage:
    python tools/audit.py                   # list every engagement (table)
    python tools/audit.py --summary         # one-line ticket-style per engagement
    python tools/audit.py <prefix>          # full detail for one engagement
    python tools/audit.py -s <prefix>       # ticket-style summary, filtered
    python tools/audit.py --watch           # refresh-on-interval summary view
    python tools/audit.py -w 5              # explicit refresh interval (seconds)

No external deps. ANSI severity coloring is automatic on TTY; on a piped
output (redirected to a file, etc.) it falls back to plain text.
"""
import io
import json
import os
import random
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Make the script runnable from anywhere — add the project root to sys.path
# so we can import the plenith package for honeytoken baseline regen.
_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
sys.path.insert(0, str(_ROOT))

# Re-encode stdout as UTF-8 so persona names / non-ASCII content render
# without choking the Windows cp1252 default. Use reconfigure() rather than
# replacing sys.stdout — replacing breaks pytest's capture and any other
# importer that hooks stdout. reconfigure() is Python 3.7+ and works on
# the wrapped pytest capture stream.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, io.UnsupportedOperation, ValueError):
    pass

from plenith.persona import load_persona  # noqa: E402
from plenith.synthetic import Honeytokens  # noqa: E402


# --- terminal colors ---------------------------------------------------------

try:
    _USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
except (ValueError, AttributeError):
    # Stdout may have been wrapped by another tool (e.g. replay.py); treat
    # as non-tty in that case — replay.py decides its own coloring.
    _USE_COLOR = False
# Enable VT100 mode on Windows so ANSI escapes render in cmd / older terminals.
if _USE_COLOR and os.name == "nt":
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass


_ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "yellow": "\033[33m",
    "green": "\033[32m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "white": "\033[37m",
    "bright_red": "\033[91m",
    "bright_yellow": "\033[93m",
}


def color(text, name):
    if not _USE_COLOR:
        return text
    return f"{_ANSI[name]}{text}{_ANSI['reset']}"


# ---------------------------------------------------------------------------
# C-2 mitigation: attacker-controlled-string sanitizer.
#
# Every attacker SSH session feeds command strings, claimed usernames,
# planted paths, and DNS-exfil URLs into the engagement JSON. When the
# operator runs `python tools/audit.py`, those strings are printed back
# to their terminal — which interprets control sequences. Without this
# sanitizer, an attacker who types
#
#     $ ssh ' \x1b[2J\x1b[H ===INJECTED=== '@victim
#
# can clear the analyst's screen, hide alerts, or smuggle OSC-8
# hyperlinks (paste-on-click). Worse, some terminal emulators historically
# allowed window-title queries or file-launch escapes.
#
# The function below strips ALL C0/C1 control characters and ANY escape
# sequence (CSI, OSC, DCS, SOS, PM, APC, single-char). Our own color()
# helper wraps trusted strings with reset codes AFTER this sanitizer runs
# (we don't sanitize our own output, just attacker-controlled fields).
# Apply via _safe(s) at every print site that takes attacker data.
# ---------------------------------------------------------------------------

_CONTROL_RE = re.compile(
    # Order matters: Python `re` is leftmost-first, so the multi-byte
    # escape patterns MUST come before the bare-control-byte class. If
    # we put the byte class first, it would match the leading ESC of an
    # escape sequence and leave the rest (e.g. `[2J`) as literal text in
    # the output — the exact bug C-2 needs to prevent.
    r"\x1b\[[\x30-\x3f]*[\x20-\x2f]*[\x40-\x7e]"   # CSI: ESC [ params interm final
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"          # OSC: ESC ] ... BEL or ESC\
    r"|\x1b[PX^_][^\x1b]*\x1b\\"                   # DCS / SOS / PM / APC string
    r"|\x1b[@-Z\\-_]"                              # other ESC <single byte>
    r"|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]"      # bare C0 + C1 controls (keep \t \n \r)
)


def _safe(value):
    """Strip ANSI escapes + C0/C1 control bytes from attacker-controlled
    strings before they reach the operator's terminal.

    Whitespace controls (\\t, \\n, \\r) are intentionally preserved so
    that multi-line attacker commands and tabbed output read naturally.
    Anything else that could move the cursor, change colors, query the
    terminal, or inject OSC-8 hyperlinks is replaced with a single `?`.

    Idempotent and safe to apply twice."""
    if value is None:
        return ""
    return _CONTROL_RE.sub("?", str(value))


_SEVERITY_COLORS = {
    "critical": "bright_red",
    "high": "magenta",
    "medium": "yellow",
    "info": "dim",
}


# --- data loading ------------------------------------------------------------

def _state_log_pairs():
    """Candidate (state_dir, logs_dir) pairs. The audit CLI walks both so
    engagements show up regardless of whether they came from the dev-mode
    `run.py` (writes to `state/`) or the docker-compose stack (writes to
    `state-docker/`)."""
    return [
        (_ROOT / "state" / "persistence", _ROOT / "logs"),
        (_ROOT / "state-docker" / "persistence", _ROOT / "state-docker" / "logs"),
    ]


def discover_engagements(personas_dir):
    """Walk every known state-dir pair and merge results. Dedupe by
    engagement_id keeping the entry with the most recent activity, so
    re-running a session that bridges dev/docker doesn't double-list."""
    merged = {}
    for sdir, ldir in _state_log_pairs():
        for e in load_engagements(sdir, ldir, personas_dir):
            cur = merged.get(e["engagement_id"])
            if cur is None or e["last_seen_at"] > cur["last_seen_at"]:
                merged[e["engagement_id"]] = e
    return sorted(merged.values(),
                  key=lambda e: e["last_seen_at"], reverse=True)


def _iter_log_files(logs_dir):
    """Yield every session-log JSON file under `logs_dir`, handling both
    layouts the engine produces:

      - dev-mode (`run.py`)  → `logs/<epoch>_<uuid>.json`         (flat)
      - docker-compose stack → `state-docker/logs/<hostname>/<epoch>_<uuid>.json`

    Pre-fix, this function used a flat `logs_dir.glob("*.json")` which
    silently missed every docker session log — engagements then showed
    up in `audit.py` with persistence metadata only (no commands, no
    alerts, no narrative). Walk one level of hostname-subdirectories
    explicitly to cover the docker layout. Use `**/*.json` would also
    work but a single rglob loses control over depth and would
    confusingly pick up archive backups under sibling dirs."""
    if not logs_dir.exists():
        return
    yield from logs_dir.glob("*.json")
    for child in logs_dir.iterdir():
        if child.is_dir():
            yield from child.glob("*.json")


def load_engagements(state_dir, logs_dir, personas_dir):
    """Return a list of engagement dicts, newest activity first.

    Engagements are surfaced by *log file* (the live, per-command flush
    target), not by state file (which only writes on session close).
    State files, when present, contribute counter-AI / VFS / observed
    metadata; when absent (mid-session), defaults are used instead so
    the in-progress session still appears in the dashboard."""
    engagements = []
    # Index per-engagement metadata from state files (best-effort).
    state_by_engagement = {}
    if state_dir.exists():
        for state_file in state_dir.glob("*.json"):
            try:
                with open(state_file, "r", encoding="utf-8") as f:
                    state = json.load(f)
            except (OSError, json.JSONDecodeError):
                continue
            eid = state.get("engagement_id")
            if eid:
                state_by_engagement[eid] = state
    # Group logs by engagement_id.
    logs_by_engagement = {}
    if logs_dir.exists():
        for log_file in _iter_log_files(logs_dir):
            try:
                with open(log_file, "r", encoding="utf-8") as f:
                    log = json.load(f)
            except (OSError, json.JSONDecodeError):
                continue
            eid = log.get("engagement_id")
            if not eid:
                continue
            logs_by_engagement.setdefault(eid, []).append(log)
    # Build one engagement per distinct engagement_id seen across logs
    # OR state.  Logs are authoritative for the existence of a session
    # (a state file without any logs is stale and not interesting);
    # state contributes metadata when both are present.
    seen_eids = set()
    for eid in list(logs_by_engagement.keys()) + list(state_by_engagement.keys()):
        if not eid or eid in seen_eids:
            continue
        seen_eids.add(eid)
        logs = sorted(
            logs_by_engagement.get(eid, []),
            key=lambda log: log.get("started_at", 0),
        )
        state = state_by_engagement.get(eid) or {}
        # Fall back to the most-recent log for fields the state file
        # would normally carry — this is what makes a still-open session
        # appear in the dashboard before the disconnect flush.
        last_log = logs[-1] if logs else {}
        if not logs:
            # State file without any logs is a stale handle from a
            # previous run; skip it rather than render an empty row.
            continue
        engagements.append({
            "engagement_id": eid,
            "claimed_user": state.get("claimed_user")
                              or last_log.get("claimed_user", "?"),
            "source_ip":    state.get("source_ip")
                              or last_log.get("source_ip", "?"),
            "first_seen_at": state.get("first_seen_at",
                                       last_log.get("started_at", 0)),
            "last_seen_at":  state.get("last_seen_at",
                                       last_log.get("ended_at",
                                                    last_log.get("started_at", 0))),
            "connection_count": state.get("connection_count", 1),
            "cwd":   state.get("cwd",   last_log.get("cwd", "?")),
            "vfs":   state.get("vfs",   {"files": {}, "deleted": []}),
            "observed": state.get("observed", last_log.get("observed", {})),
            "logs": logs,
            "personas_dir": personas_dir,
        })
    engagements.sort(key=lambda e: e["last_seen_at"], reverse=True)
    return engagements


# --- summary view (ticket-style one-liners) ---------------------------------

# Order in which alert fragments appear in the narrative — most impactful first.
_NARRATIVE_ORDER = [
    "alert_reverse_shell",
    "alert_ssh_persistence",
    "alert_dns_exfil",
    "alert_credential_exfil",
    "alert_lateral_decoy",
    "alert_honeytoken_tamper",
    "alert_log_tampering",
    "alert_credential_search",
    "alert_payload_staging",
    "alert_decoy_swallowed",
    "isolate_session",
    "plant_sudo_vulnerability",
    "spawn_fake_mysql",
    "plant_aws_credentials",
]

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "info": 3}


def print_summary(engagements):
    """Render one ticket-style line per engagement, newest first."""
    if not engagements:
        print(color("(no engagements found)", "dim"))
        return
    for e in engagements:
        print(build_narrative(e))


def build_narrative(eng):
    """Build a one-line, severity-led summary of an engagement."""
    # Collect deduped actions across all connection logs.
    by_name = {}
    for log in eng["logs"]:
        for a in log.get("actions_taken", []):
            by_name.setdefault(a["action"], a)

    # Pick the top severity from this engagement's alerts.
    top_sev = "info"
    for a in by_name.values():
        if _SEVERITY_RANK.get(a.get("severity", "info"), 9) < _SEVERITY_RANK.get(top_sev, 9):
            top_sev = a.get("severity", "info")
    badge = {
        "critical": color("[CRIT]", "bright_red"),
        "high":     color("[HIGH]", "magenta"),
        "medium":   color("[MED ]", "yellow"),
        "info":     color("[info]", "dim"),
    }.get(top_sev, color("[?   ]", "dim"))

    eng_short = color(eng["engagement_id"][:8], "cyan")
    # claimed_user is attacker-controlled (SSH username). source_ip
    # comes from socket inspection so is safe. Sanitize the user side.
    user_at_ip = f"{_safe(eng['claimed_user'])}@{eng['source_ip']}"
    dwell = format_duration(eng["last_seen_at"] - eng["first_seen_at"])
    last_ago = format_relative_ago(eng["last_seen_at"])

    # Narrative fragments in priority order.
    obs = eng["observed"]
    fragments = []
    for name in _NARRATIVE_ORDER:
        if name not in by_name:
            continue
        frag = _narrative_fragment(name, by_name[name], obs)
        if frag:
            fragments.append(frag)

    if not fragments:
        # No alerts — describe by raw observations or fall back to "idle".
        if obs.get("ran_sudo"):
            fragments.append("ran sudo")
        elif obs.get("attempted_lateral"):
            fragments.append("attempted ssh")
        elif eng.get("connection_count", 1) > 1:
            fragments.append(f"reconnected ({eng['connection_count']} conns)")
        else:
            fragments.append("idle")

    narrative = " + ".join(fragments)
    return f"{eng_short}  {badge}  {user_at_ip:<28} · {dwell:>7} · {last_ago:>8} · {narrative}"


def _narrative_fragment(action_name, action, obs):
    """Return a short, IoC-bearing fragment for an action."""
    trigger = action.get("triggered_by", "")

    if action_name == "alert_reverse_shell":
        m = re.search(r"/dev/tcp/(\d+\.\d+\.\d+\.\d+)/(\d+)", trigger)
        if m:
            return color(f"revshell C2→{m.group(1)}:{m.group(2)}", "bright_red")
        m = re.search(r"\bnc(?:at)?\s+\S+\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)", trigger)
        if m:
            return color(f"revshell nc→{m.group(1)}:{m.group(2)}", "bright_red")
        return color("revshell", "bright_red")

    if action_name == "alert_ssh_persistence":
        return color("ssh-persistence", "bright_red")

    if action_name == "alert_dns_exfil":
        cmds = obs.get("dns_exfil_commands") or []
        if cmds:
            cmd = cmds[0] if isinstance(cmds, list) else next(iter(cmds))
            m = re.search(r"https?://([\w.-]+)", cmd)
            if m:
                # Trim to last two domain components for readability
                host = m.group(1)
                parts = host.split(".")
                short = ".".join(parts[-2:]) if len(parts) > 2 else host
                return color(f"exfil→{short}", "magenta")
        return color("exfil", "magenta")

    if action_name == "alert_credential_exfil":
        files = obs.get("credential_files_read") or []
        n = len(files) if isinstance(files, list) else 1
        return color(f"cred-exfil ({n} file{'s' if n != 1 else ''})", "magenta")

    if action_name == "alert_lateral_decoy":
        targets = obs.get("decoy_targets") or []
        if targets:
            t = sorted(targets)[0] if isinstance(targets, list) else next(iter(targets))
            return color(f"lateral→{t}", "magenta")
        return color("lateral", "magenta")

    if action_name == "alert_honeytoken_tamper":
        return color("honeytoken-tampered", "magenta")

    if action_name == "alert_log_tampering":
        return color("logs-cleared", "magenta")

    if action_name == "alert_credential_search":
        terms = obs.get("credential_search_terms") or []
        if terms:
            t = sorted(terms)[0] if isinstance(terms, list) else next(iter(terms))
            # credential_search_terms come from attacker `grep -r 'pattern'`
            # commands — the pattern is attacker-controlled. Sanitize.
            return color(f"cred-hunt ({_safe(t)})", "yellow")
        return color("cred-hunt", "yellow")

    if action_name == "alert_payload_staging":
        drops = obs.get("payload_drops") or []
        n = len(drops) if isinstance(drops, list) else 1
        return color(f"staging ({n} files in /tmp)", "yellow")

    if action_name == "alert_decoy_swallowed":
        swallowed = obs.get("decoys_swallowed") or []
        n = len(swallowed) if isinstance(swallowed, list) else 1
        return color(f"took-bait ({n})", "yellow")

    if action_name == "isolate_session":
        return color("[isolated]", "dim")

    # The plant_* actions are info-level deception responses; only mention
    # them when nothing else fired, to avoid noise.
    if action_name in ("plant_sudo_vulnerability", "spawn_fake_mysql", "plant_aws_credentials"):
        return None

    return None


# --- list view ---------------------------------------------------------------

def print_list(engagements):
    if not engagements:
        print("(no engagements found — nothing under state/persistence/ or state-docker/persistence/)")
        return
    hdr = f"{'ENGAGE':10} {'USER':<10} {'IP':<15} {'CONNS':>5}  {'DWELL':>9}  {'LAST':>10}  ALERTS"
    print(color(hdr, "bold"))
    print(color("-" * 92, "dim"))
    for e in engagements:
        eng = e["engagement_id"][:8]
        # claimed_user is attacker-controlled — sanitize before slicing
        # so escape sequences can't span the truncation boundary.
        user = _safe(e["claimed_user"])[:10]
        ip = e["source_ip"][:15]
        conns = e["connection_count"]
        dwell = format_duration(e["last_seen_at"] - e["first_seen_at"])
        last = format_relative_ago(e["last_seen_at"])
        counts = count_alerts(e["logs"])
        alerts = format_alert_counts(counts)
        print(f"{color(eng, 'cyan'):20} {user:<10} {ip:<15} {conns:>5}  {dwell:>9}  {last:>10}  {alerts}")
    print()
    print(color(f"({len(engagements)} engagement{'s' if len(engagements) != 1 else ''} — pass an id prefix for detail)", "dim"))


# --- detail view -------------------------------------------------------------

def print_detail(eng):
    eid = eng["engagement_id"]
    print()
    print(color(f"=== Engagement {eid} ===", "bold"))
    # claimed_user and cwd are attacker-controlled — they could contain
    # ANSI escape sequences typed during the SSH session. Sanitize before
    # printing so they can't move the operator's cursor or hide alerts.
    print(f"User:           {color(_safe(eng['claimed_user']), 'cyan')} (claimed)")
    print(f"Source IP:      {eng['source_ip']}")
    print(f"First seen:     {format_iso(eng['first_seen_at'])}")
    print(f"Last seen:      {format_iso(eng['last_seen_at'])}  ({format_relative_ago(eng['last_seen_at'])})")
    print(f"Engagement age: {format_duration(eng['last_seen_at'] - eng['first_seen_at'])}")
    print(f"Connections:    {eng['connection_count']}")
    print(f"Current cwd:    {_safe(eng['cwd'])}")

    _print_alerts(eng)
    _print_observations(eng)
    _print_diff(eng)
    _print_timeline(eng)


def _print_alerts(eng):
    print()
    print(color("=== Alerts (highest severity first) ===", "bold"))
    alerts = []
    for log in eng["logs"]:
        for a in log.get("actions_taken", []):
            alerts.append((log.get("started_at", 0), a))
    if not alerts:
        print(color("  (no alerts fired in this engagement)", "dim"))
        return
    sev_order = {"critical": 0, "high": 1, "medium": 2, "info": 3}
    alerts.sort(key=lambda x: (sev_order.get(x[1].get("severity", "info"), 9), x[0]))
    # De-duplicate: same action appearing in multiple connection logs is
    # the same alert (it fires once per engagement by design).
    seen = set()
    for ts, a in alerts:
        if a["action"] in seen:
            continue
        seen.add(a["action"])
        sev = a.get("severity", "info")
        col = _SEVERITY_COLORS.get(sev, "white")
        print(f"  [{color(sev.upper().center(8), col)}] {color(a['action'], 'bold')}")
        # triggered_by is the verbatim attacker command — sanitize.
        print(f"     {color('via:', 'dim')} {_safe(a.get('triggered_by', '?'))}")
        rat = a.get("rationale", "").strip()
        if rat:
            # Wrap rationale at ~90 cols for readability. The rationale
            # is built from templates + observed dict values (some
            # attacker-controlled, e.g. lists of paths); sanitize the
            # composed string defensively.
            print("     " + color(_safe(rat[:300]), "dim"))
        print()


def _print_observations(eng):
    obs = eng["observed"]
    interesting = []
    for k, v in obs.items():
        if v in (False, [], 0, "", None):
            continue
        if k.startswith("alerted_"):
            continue  # internal bookkeeping, not user-facing
        interesting.append((k, v))
    if not interesting:
        return
    print(color("=== Observed signals ===", "bold"))
    for k, v in interesting:
        # Many observed values are lists of attacker-controlled strings
        # (paths the attacker `cat`-ed, hostnames they tried to ssh to,
        # commands they ran to tamper with logs). Sanitize before
        # printing — see C-2 mitigation comment near _safe() definition.
        if isinstance(v, list) and len(v) > 0:
            preview = ", ".join(_safe(x) for x in v[:4])
            extra = f" (+{len(v)-4} more)" if len(v) > 4 else ""
            print(f"  {k:32} = [{preview}]{extra}")
        else:
            print(f"  {k:32} = {_safe(v)}")
    print()


def _print_diff(eng):
    print(color("=== Filesystem diff vs honeytoken baseline ===", "bold"))
    diff = compute_diff(eng)
    for line in diff:
        # Each line includes a path the attacker may have planted with
        # ANSI escapes in its name (`touch /tmp/$(printf '\\x1b[2J')evil`).
        # Sanitize before colorizing — we wrap our color codes AFTER.
        safe_line = _safe(line)
        first = safe_line[:1]
        if first == "+":
            print("  " + color(safe_line, "green"))
        elif first == "-":
            print("  " + color(safe_line, "red"))
        elif first == "M":
            print("  " + color(safe_line, "yellow"))
        else:
            print("  " + color(safe_line, "dim"))
    print()


def _print_timeline(eng, limit=40):
    print(color(f"=== Command timeline (last {limit} of session) ===", "bold"))
    all_commands = []
    for log in eng["logs"]:
        for c in log.get("commands", []):
            all_commands.append(c)
    all_commands.sort(key=lambda c: c["ts"])
    shown = all_commands[-limit:]
    if not shown:
        print(color("  (no commands captured yet)", "dim"))
        return
    for c in shown:
        ts = format_hms(c["ts"])
        src = c.get("response_source", "?")
        src_col = _src_color(src)
        # cmd is the verbatim attacker command — primary C-2 risk surface.
        cmd = _safe(c["cmd"])
        if len(cmd) > 90:
            cmd = cmd[:87] + "..."
        print(f"  {color(ts, 'dim')}  [{color(src.ljust(12), src_col)}]  {cmd}")
    if len(all_commands) > limit:
        print(color(f"  ... ({len(all_commands) - limit} earlier commands omitted)", "dim"))
    print()


def _src_color(src):
    if src.startswith("alert_") or src == "error":
        return "red"
    if src.startswith("vfs-"):
        return "green"
    if src in ("find", "grep", "ls"):
        return "cyan"
    if src == "sim-bot":
        return "blue"
    if src == "llm":
        return "magenta"
    return "dim"


# --- HTML report -----------------------------------------------------------

_HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Plenith engagement {short_id}</title>
<style>
  :root {{
    --bg: #0f172a; --panel: #1e293b; --line: #334155;
    --text: #e2e8f0; --dim: #94a3b8;
    --crit: #ef4444; --high: #c026d3; --med: #eab308; --info: #64748b;
    --vfs: #22c55e; --tool: #06b6d4; --bot: #3b82f6; --llm: #d946ef;
  }}
  * {{ box-sizing: border-box; }}
  body {{ font: 14px/1.5 -apple-system, "Segoe UI", system-ui, sans-serif;
         margin: 0; padding: 24px; background: var(--bg); color: var(--text); }}
  .wrap {{ max-width: 1100px; margin: 0 auto; }}
  h1 {{ font-size: 22px; margin: 0 0 4px; }}
  h2 {{ font-size: 16px; color: var(--dim); margin: 28px 0 10px;
        text-transform: uppercase; letter-spacing: .08em; font-weight: 600; }}
  .sub {{ color: var(--dim); margin-bottom: 24px; }}
  .panel {{ background: var(--panel); border: 1px solid var(--line); border-radius: 8px;
            padding: 14px 18px; margin-bottom: 16px; }}
  .kv {{ display: grid; grid-template-columns: 200px 1fr; gap: 6px 14px; font-size: 13px; }}
  .kv .k {{ color: var(--dim); }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px;
            font-size: 11px; font-weight: 700; letter-spacing: .05em; }}
  .b-crit {{ background: var(--crit); color: #fff; }}
  .b-high {{ background: var(--high); color: #fff; }}
  .b-med  {{ background: var(--med);  color: #1f1f1f; }}
  .b-info {{ background: var(--info); color: #fff; }}
  .alert {{ padding: 10px 14px; border-left: 3px solid var(--line);
            margin-bottom: 8px; background: rgba(255,255,255,0.02); }}
  .alert.crit {{ border-color: var(--crit); }}
  .alert.high {{ border-color: var(--high); }}
  .alert.med  {{ border-color: var(--med); }}
  .alert.info {{ border-color: var(--info); }}
  .alert .name {{ font-weight: 700; font-size: 14px; }}
  .alert .via {{ font-family: "Cascadia Mono", Consolas, monospace; font-size: 12px;
                 color: var(--dim); margin: 4px 0 6px; }}
  .alert .rat {{ color: var(--dim); font-size: 13px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
  table th {{ text-align: left; color: var(--dim); font-weight: 600;
              padding: 6px 8px; border-bottom: 1px solid var(--line); }}
  table td {{ padding: 6px 8px; border-bottom: 1px solid rgba(255,255,255,0.03);
              vertical-align: top; font-family: "Cascadia Mono", Consolas, monospace; }}
  .tag {{ display: inline-block; padding: 1px 6px; border-radius: 3px;
          font-size: 10px; letter-spacing: .03em; }}
  .tag.vfs  {{ background: rgba(34,197,94,0.15);  color: var(--vfs); }}
  .tag.tool {{ background: rgba(6,182,212,0.15);  color: var(--tool); }}
  .tag.bot  {{ background: rgba(59,130,246,0.15); color: var(--bot); }}
  .tag.llm  {{ background: rgba(217,70,239,0.15); color: var(--llm); }}
  .tag.alert {{ background: rgba(239,68,68,0.15); color: var(--crit); }}
  .diff-add  {{ color: var(--vfs); }}
  .diff-stage {{ color: var(--med); font-weight: 600; }}
  .diff-mod  {{ color: var(--med); }}
  .diff-del  {{ color: var(--crit); }}
  pre {{ margin: 0; white-space: pre-wrap; word-break: break-all; }}
  footer {{ color: var(--dim); font-size: 11px; margin-top: 32px; text-align: center; }}
</style>
</head>
<body><div class="wrap">

<h1>Engagement {full_id}</h1>
<div class="sub">{badge_html} &nbsp;&middot;&nbsp; {claimed_user}@{source_ip} &nbsp;&middot;&nbsp; {first_seen} → {last_seen} &nbsp;&middot;&nbsp; dwell {dwell} &nbsp;&middot;&nbsp; {conn_count} connection(s)</div>

<div class="panel"><div class="kv">
<div class="k">Engagement ID</div><div>{full_id}</div>
<div class="k">Claimed user</div><div>{claimed_user}</div>
<div class="k">Source IP</div><div>{source_ip}</div>
<div class="k">First seen (UTC)</div><div>{first_seen}</div>
<div class="k">Last seen (UTC)</div><div>{last_seen}</div>
<div class="k">Engagement age</div><div>{dwell}</div>
<div class="k">Connections</div><div>{conn_count}</div>
<div class="k">Current cwd</div><div><code>{cwd}</code></div>
</div></div>

<h2>Alerts ({alerts_count})</h2>
{alerts_html}

<h2>Filesystem diff vs honeytoken baseline</h2>
<div class="panel"><pre>{diff_html}</pre></div>

<h2>Observed signals</h2>
<div class="panel">{obs_html}</div>

<h2>Command timeline ({commands_count} commands)</h2>
<div class="panel"><table>
<thead><tr><th style="width:80px">time</th><th style="width:120px">source</th><th>command</th></tr></thead>
<tbody>{timeline_html}</tbody>
</table></div>

<footer>Plenith audit report &nbsp;&middot;&nbsp; generated {generated_at}</footer>

</div></body></html>
"""


def render_html(engagement):
    """Build a self-contained HTML page summarizing one engagement.

    No external CSS, no JS. Suitable for emailing or attaching to a ticket.
    """
    obs = engagement["observed"]
    full_id = engagement["engagement_id"]
    short_id = full_id[:8]
    by_action = {}
    for log in engagement["logs"]:
        for a in log.get("actions_taken", []):
            by_action.setdefault(a["action"], a)

    # Top severity → header badge
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "info": 3}
    top_sev = "info"
    for a in by_action.values():
        if sev_rank.get(a.get("severity", "info"), 9) < sev_rank.get(top_sev, 9):
            top_sev = a.get("severity", "info")
    badge_html = f'<span class="badge b-{_sev_class(top_sev)}">{top_sev.upper()}</span>'

    # Alerts block
    alert_blocks = []
    for a in sorted(
        by_action.values(),
        key=lambda x: (sev_rank.get(x.get("severity", "info"), 9), x.get("ts_offset_s", 0)),
    ):
        sev = a.get("severity", "info")
        cls = _sev_class(sev)
        alert_blocks.append(
            f'<div class="alert {cls}">'
            f'<div class="name"><span class="badge b-{cls}">{sev.upper()}</span> &nbsp;{_h(a["action"])}</div>'
            f'<div class="via">via: <code>{_h(a.get("triggered_by", ""))}</code></div>'
            f'<div class="rat">{_h(a.get("rationale", ""))}</div>'
            f'</div>'
        )
    alerts_html = "\n".join(alert_blocks) if alert_blocks else (
        '<div class="panel" style="color:var(--dim);">(no alerts fired this engagement)</div>'
    )

    # Diff
    diff_lines = compute_diff(engagement)
    diff_html = "\n".join(_html_diff_line(line) for line in diff_lines)

    # Observed signals — only non-empty
    obs_rows = []
    for k, v in obs.items():
        if v in (False, [], 0, "", None) or k.startswith("alerted_"):
            continue
        if isinstance(v, list):
            val = "<br>".join(_h(str(x)) for x in v[:8])
            if len(v) > 8:
                val += f"<br><span style='color:var(--dim)'>(+{len(v)-8} more)</span>"
        else:
            val = _h(str(v))
        obs_rows.append(
            f'<div style="margin-bottom:6px;font-size:12px;">'
            f'<span style="color:var(--dim);min-width:230px;display:inline-block;">{_h(k)}</span> '
            f'<span style="font-family:monospace;">{val}</span></div>'
        )
    obs_html = "\n".join(obs_rows) or '<span style="color:var(--dim);">(no flagged signals)</span>'

    # Timeline
    all_cmds = []
    for log in engagement["logs"]:
        for c in log.get("commands", []):
            all_cmds.append(c)
    all_cmds.sort(key=lambda c: c["ts"])
    tl_rows = []
    for c in all_cmds:
        ts = format_hms(c["ts"])
        src = c.get("response_source", "?")
        tag = _src_tag_class(src)
        cmd_html = _h(c["cmd"])
        if len(cmd_html) > 200:
            cmd_html = cmd_html[:197] + "..."
        tl_rows.append(
            f'<tr><td style="color:var(--dim);">{ts}</td>'
            f'<td><span class="tag {tag}">{_h(src)}</span></td>'
            f'<td>{cmd_html}</td></tr>'
        )
    timeline_html = "\n".join(tl_rows) or '<tr><td colspan=3 style="color:var(--dim)">(no commands)</td></tr>'

    return _HTML_TEMPLATE.format(
        full_id=full_id,
        short_id=short_id,
        badge_html=badge_html,
        claimed_user=_h(engagement["claimed_user"]),
        source_ip=_h(engagement["source_ip"]),
        first_seen=format_iso(engagement["first_seen_at"]),
        last_seen=format_iso(engagement["last_seen_at"]),
        dwell=format_duration(engagement["last_seen_at"] - engagement["first_seen_at"]),
        conn_count=engagement.get("connection_count", 1),
        cwd=_h(engagement["cwd"]),
        alerts_count=len(by_action),
        alerts_html=alerts_html,
        diff_html=diff_html,
        obs_html=obs_html,
        commands_count=len(all_cmds),
        timeline_html=timeline_html,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )


def _sev_class(sev):
    return {"critical": "crit", "high": "high", "medium": "med", "info": "info"}.get(sev, "info")


def _src_tag_class(src):
    if src.startswith("vfs-"):
        return "vfs"
    if src in ("find", "grep", "ls", "awk", "sed", "cache", "cache+elevated"):
        return "tool"
    if src == "sim-bot":
        return "bot"
    if src == "llm":
        return "llm"
    if src.startswith("alert_") or src == "error":
        return "alert"
    return "tool"


def _h(s):
    """HTML-escape."""
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


def _html_diff_line(line):
    if not line:
        return ""
    first = line[:2]
    cls = "diff-add"
    if first == "+!":
        cls = "diff-stage"
    elif line[0] == "+":
        cls = "diff-add"
    elif line[0] == "M":
        cls = "diff-mod"
    elif line[0] == "-":
        cls = "diff-del"
    return f'<span class="{cls}">{_h(line)}</span>'


# --- Sigma rules export -----------------------------------------------------
#
# Sigma is a generic rule format for SIEM detections. From each engagement
# we know:
#   - which heuristics fired (alert type + severity)
#   - the IoCs (C2 endpoint, exfil domains, decoy targets, planted file paths)
#   - the specific commands that triggered each alert
# We emit one Sigma rule per fired alert, with selection criteria that
# match the observed IoCs. The rules are deployable to Elastic, Splunk
# (via sigmac), Sentinel, etc.
#
# Output is multi-document YAML — `--- ` separators between rules.

_SIGMA_HEADER = "# Generated by Plenith audit.py — DO NOT EDIT BY HAND."

# Maps Plenith alert action → (sigma logsource, fields, mitre tactic/technique).
_SIGMA_TEMPLATES = {
    "alert_reverse_shell": {
        "logsource": {"category": "process_creation", "product": "linux"},
        "level": "critical",
        "tags": ["attack.execution", "attack.t1059.004", "attack.command_and_control"],
        "build_detection": lambda ioc: {
            "selection_c2": {
                "DestinationIp": [c["ip"] for c in ioc["c2_endpoints"]],
                "DestinationPort": list({c["port"] for c in ioc["c2_endpoints"]}),
            } if ioc["c2_endpoints"] else None,
            "selection_cmdline": {
                "CommandLine|contains": [
                    "/dev/tcp/", "bash -i", "nc -e", "ncat --exec",
                ],
            },
            "condition": "selection_cmdline" + (" or selection_c2" if ioc["c2_endpoints"] else ""),
        },
    },
    "alert_ssh_persistence": {
        "logsource": {"category": "file_event", "product": "linux"},
        "level": "critical",
        "tags": ["attack.persistence", "attack.t1098.004"],
        "build_detection": lambda ioc: {
            "selection": {
                "TargetFilename|endswith": [
                    "/.ssh/authorized_keys",
                    "/.bashrc",
                    "/.bash_profile",
                    "/.profile",
                ],
            },
            "filter_legit": {
                "Image|endswith": ["/bin/ssh-copy-id", "/usr/bin/ssh-copy-id"],
            },
            "condition": "selection and not filter_legit",
        },
    },
    "alert_credential_exfil": {
        "logsource": {"category": "file_event", "product": "linux"},
        "level": "high",
        "tags": ["attack.credential_access", "attack.t1552.001"],
        "build_detection": lambda ioc: {
            "selection": {
                "TargetFilename": ioc["credential_files_read"] or [
                    "*/.aws/credentials", "*/.ssh/id_rsa", "*/.kube/config",
                ],
            },
            "condition": "selection",
        },
    },
    "alert_lateral_decoy": {
        "logsource": {"category": "process_creation", "product": "linux"},
        "level": "high",
        "tags": ["attack.lateral_movement", "attack.t1021.004"],
        "build_detection": lambda ioc: {
            "selection": {
                "CommandLine|contains": [
                    f"ssh {h}" for h in ioc["decoy_targets_probed"]
                ] + [
                    f"scp {h}" for h in ioc["decoy_targets_probed"]
                ] if ioc["decoy_targets_probed"] else ["ssh "],
            },
            "condition": "selection",
        },
    },
    "alert_dns_exfil": {
        "logsource": {"category": "dns_query", "product": "linux"},
        "level": "high",
        "tags": ["attack.exfiltration", "attack.t1048.003"],
        "build_detection": lambda ioc: {
            "selection_domains": {
                "QueryName|endswith": [d["host"] for d in ioc["exfil_domains"]],
            } if ioc["exfil_domains"] else None,
            "selection_known_bad": {
                "QueryName|contains": [
                    ".ngrok.io", ".burpcollaborator.net", ".oast.live",
                    "webhook.site", ".requestbin.io",
                ],
            },
            "condition": "selection_domains or selection_known_bad" if ioc["exfil_domains"] else "selection_known_bad",
        },
    },
    "alert_honeytoken_tamper": {
        "logsource": {"category": "file_event", "product": "linux"},
        "level": "high",
        "tags": ["attack.defense_evasion", "attack.t1070"],
        "build_detection": lambda ioc: {
            "selection_overwrite": {
                "TargetFilename": ioc["honeytokens_modified"] or ["*/.aws/credentials"],
                "EventType": ["modify", "delete"],
            },
            "condition": "selection_overwrite",
        },
    },
    "alert_log_tampering": {
        "logsource": {"category": "process_creation", "product": "linux"},
        "level": "high",
        "tags": ["attack.defense_evasion", "attack.t1070.003"],
        "build_detection": lambda ioc: {
            "selection_cmd": {
                "CommandLine|contains": [
                    "history -c", "unset HISTFILE", "HISTFILE=/dev/null",
                ],
            },
            "selection_logfile": {
                "CommandLine|contains": [
                    "rm /var/log/", "shred /var/log/",
                    "> /var/log/", "truncate -s 0 /var/log/",
                ],
            },
            "condition": "1 of selection_*",
        },
    },
    "alert_credential_search": {
        "logsource": {"category": "process_creation", "product": "linux"},
        "level": "medium",
        "tags": ["attack.discovery", "attack.t1552"],
        "build_detection": lambda ioc: {
            "selection": {
                "CommandLine|contains": [
                    "find / -name id_rsa", "find / -name *.pem",
                    "find / -name authorized_keys",
                    "grep -r AKIA", "grep -r BEGIN PRIVATE KEY",
                    "grep -r aws_secret",
                ],
            },
            "condition": "selection",
        },
    },
    "alert_payload_staging": {
        "logsource": {"category": "file_event", "product": "linux"},
        "level": "medium",
        "tags": ["attack.command_and_control", "attack.t1105"],
        "build_detection": lambda ioc: {
            "selection": {
                "TargetFilename|startswith": ["/tmp/", "/var/tmp/", "/dev/shm/"],
                "EventType": ["create"],
            },
            "timeframe": "10m",
            "condition": "selection | count() by SourceIp > 2",
        },
    },
}


def render_sigma(engagement):
    """Build a multi-document Sigma YAML from an engagement's fired alerts.

    Each alert that has a template above becomes one rule, with the rule's
    selection populated from the engagement's actual IoCs. Output is ready
    to drop into Elastic Detection Rules / Splunk via sigmac / Sentinel.
    """
    ioc = json.loads(export_ioc(engagement))
    rules = []
    seen = set()
    for alert in ioc["alerts"]:
        action = alert["name"]
        if action in seen:
            continue
        seen.add(action)
        tmpl = _SIGMA_TEMPLATES.get(action)
        if not tmpl:
            continue
        detection = {k: v for k, v in tmpl["build_detection"](ioc).items() if v is not None}
        rule = {
            "title": _sigma_title(action),
            "id": _sigma_id(engagement["engagement_id"], action),
            "status": "experimental",
            "description": alert.get("triggered_by", "")[:200] or _sigma_description(action),
            "references": [
                f"https://attack.mitre.org/techniques/{t.replace('attack.', 'T').upper().replace('T.', 'T')}/"
                for t in tmpl["tags"] if t.startswith("attack.t")
            ],
            "author": "Plenith audit",
            "date": datetime.now(timezone.utc).strftime("%Y/%m/%d"),
            "tags": tmpl["tags"],
            "logsource": tmpl["logsource"],
            "detection": detection,
            "fields": ["SourceIp", "CommandLine", "TargetFilename"],
            "falsepositives": ["Legitimate admin activity matching the same patterns"],
            "level": tmpl["level"],
            # Plenith-specific metadata
            "_plenith": {
                "engagement_id": engagement["engagement_id"],
                "source_ip_observed": engagement["source_ip"],
                "first_seen_utc": ioc["first_seen_utc"],
                "triggered_by_command": alert.get("triggered_by", ""),
            },
        }
        rules.append(rule)

    if not rules:
        return _SIGMA_HEADER + "\n# (no alerts in this engagement had Sigma templates)\n"
    # Multi-doc YAML
    import yaml as _yaml
    docs = "\n---\n".join(_yaml.safe_dump(r, sort_keys=False, default_flow_style=False) for r in rules)
    return _SIGMA_HEADER + "\n" + docs


def _sigma_title(action):
    return {
        "alert_reverse_shell": "Plenith — Reverse shell idiom",
        "alert_ssh_persistence": "Plenith — SSH/profile persistence write",
        "alert_credential_exfil": "Plenith — Credential file read",
        "alert_lateral_decoy": "Plenith — Lateral movement to internal host",
        "alert_dns_exfil": "Plenith — DNS / HTTP exfil to interaction service",
        "alert_honeytoken_tamper": "Plenith — Credential file modification",
        "alert_log_tampering": "Plenith — Log / history clearing",
        "alert_credential_search": "Plenith — Credential discovery activity",
        "alert_payload_staging": "Plenith — Multiple file drops in payload dirs",
    }.get(action, f"Plenith — {action}")


def _sigma_description(action):
    return {
        "alert_reverse_shell": "Detects canonical reverse-shell command idioms (bash /dev/tcp, nc -e, etc.)",
        "alert_ssh_persistence": "Detects writes to common persistence paths (~/.ssh/authorized_keys, ~/.bashrc)",
        "alert_credential_exfil": "Detects reads of high-value credential files",
        "alert_lateral_decoy": "Detects SSH/SCP attempts to internal infrastructure hostnames",
        "alert_dns_exfil": "Detects exfiltration via curl/wget to interaction services",
        "alert_honeytoken_tamper": "Detects modification or deletion of credential files",
        "alert_log_tampering": "Detects clearing of bash history or log files",
        "alert_credential_search": "Detects active enumeration for credential files",
        "alert_payload_staging": "Detects unusual file drop activity in temp directories",
    }.get(action, f"Plenith-derived detection for {action}")


def _sigma_id(engagement_id, action):
    """Deterministic UUID-shaped id from (engagement_id, action). Lets users
    re-deploy rules without churning IDs in their SIEM."""
    import hashlib
    h = hashlib.sha1(f"{engagement_id}:{action}".encode()).hexdigest()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


# --- IoC export ------------------------------------------------------------

_REVSHELL_RE = re.compile(r"/dev/tcp/(\d+\.\d+\.\d+\.\d+)/(\d+)")
_REVSHELL_NC_RE = re.compile(r"\bnc(?:at)?\s+(?:[^\s]+\s+)*(\d+\.\d+\.\d+\.\d+)\s+(\d+)")
_URL_RE = re.compile(r"\b(?:https?|ftp)://([\w.-]+)(?::(\d+))?(?:/\S*)?")
_DOMAIN_RE = re.compile(r"\b([a-z0-9-]+(?:\.[a-z0-9-]+)+)\b", re.IGNORECASE)


def export_ioc(engagement, as_csv=False):
    """Build a structured IoC bundle from a single engagement, ready for
    ingest into a blocklist / SIEM / threat-intel feed.
    """
    obs = engagement["observed"]
    by_action = {}
    for log in engagement["logs"]:
        for a in log.get("actions_taken", []):
            by_action.setdefault(a["action"], a)

    iocs = {
        "engagement_id": engagement["engagement_id"],
        "claimed_user": engagement["claimed_user"],
        "source_ip": engagement["source_ip"],
        "first_seen_utc": _iso(engagement["first_seen_at"]),
        "last_seen_utc": _iso(engagement["last_seen_at"]),
        "dwell_seconds": int(engagement["last_seen_at"] - engagement["first_seen_at"]),
        "connection_count": engagement.get("connection_count", 1),
        "alerts": [],
        "c2_endpoints": [],
        "exfil_domains": [],
        "decoy_targets_probed": sorted(obs.get("decoy_targets", []) or []),
        "credential_files_read": sorted(obs.get("credential_files_read", []) or []),
        "honeytokens_modified": sorted(obs.get("honeytoken_modifications", []) or []),
        "payload_drops": sorted(obs.get("payload_drops", []) or []),
        "log_tampering_commands": sorted(obs.get("tampering_commands", []) or []),
        "credential_search_terms": sorted(obs.get("credential_search_terms", []) or []),
        "decoys_planted": sorted(obs.get("decoys_planted", []) or []),
        "decoys_swallowed": sorted(obs.get("decoys_swallowed", []) or []),
        "ssh_persistence_attempt": bool(obs.get("ssh_persistence_attempt")),
        "reverse_shell_attempted": bool(obs.get("reverse_shell_attempted")),
        "elevated_to_root": bool(obs.get("attempted_sudo_elevation")
                                 and "/etc/sudoers.d/zzz_compat" in (obs.get("decoys_swallowed") or [])),
    }

    # Severity-sorted alert list
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "info": 3}
    for a in sorted(by_action.values(), key=lambda x: sev_rank.get(x.get("severity", "info"), 9)):
        iocs["alerts"].append({
            "name": a["action"],
            "severity": a.get("severity", "info"),
            "triggered_by": a.get("triggered_by", ""),
            "ts_offset_seconds": a.get("ts_offset_s"),
        })

    # Extract C2 endpoints
    rev_cmd = obs.get("reverse_shell_command") or ""
    for cmd in [rev_cmd] + list(obs.get("dns_exfil_commands") or []):
        if not isinstance(cmd, str):
            continue
        for ip, port in _REVSHELL_RE.findall(cmd):
            iocs["c2_endpoints"].append({"ip": ip, "port": int(port), "via": "bash-dev-tcp"})
        for ip, port in _REVSHELL_NC_RE.findall(cmd):
            iocs["c2_endpoints"].append({"ip": ip, "port": int(port), "via": "netcat"})

    # Extract exfil domains
    for cmd in obs.get("dns_exfil_commands") or []:
        if not isinstance(cmd, str):
            continue
        for host, port in _URL_RE.findall(cmd):
            iocs["exfil_domains"].append({"host": host, "port": int(port) if port else None})

    # Deduplicate
    iocs["c2_endpoints"] = [dict(t) for t in {tuple(sorted(d.items())) for d in iocs["c2_endpoints"]}]
    seen_hosts = set()
    deduped_domains = []
    for d in iocs["exfil_domains"]:
        if d["host"] not in seen_hosts:
            seen_hosts.add(d["host"])
            deduped_domains.append(d)
    iocs["exfil_domains"] = deduped_domains

    if as_csv:
        return _ioc_to_csv(iocs)
    return json.dumps(iocs, indent=2, default=str)


def _iso(epoch):
    if not epoch:
        return None
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _csv_safe(value):
    """C-3 mitigation: harden a cell value against CSV formula injection.

    Excel / LibreOffice / Google Sheets execute any cell whose value
    begins with `=`, `+`, `-`, `@`, `\\t`, or `\\r` as a formula or DDE
    command. Attacker-controlled fields in our IoC export — payload
    paths, credential paths, hostnames — flow straight into the CSV
    that a SOC analyst opens in Excel. Pre-fix, an attacker who runs
    `touch /tmp/=cmd|'/c calc.exe'!A0` lands code execution in the
    analyst's spreadsheet.

    Defense (per OWASP CSV injection guidance):
      1. Strip CR/LF so a single cell can't break the row.
      2. Prefix the dangerous leading bytes with a single quote, which
         Excel/Sheets treat as 'this is text, not a formula'.
      3. Always go through csv.writer so embedded commas and quotes
         are properly RFC-4180-escaped (the old f-string approach
         would corrupt the row on any path containing a comma).
    """
    s = str(value).replace("\r", " ").replace("\n", " ")
    if s and s[0] in "=+-@\t":
        return "'" + s
    return s


def _ioc_to_csv(iocs):
    """Flat CSV view — one row per observable artifact. Suitable for
    pasting into a SIEM ingest column.

    SECURITY: every attacker-controlled cell goes through `_csv_safe`
    (see C-3 mitigation above). Don't bypass this by reverting to
    f-string concatenation — Excel/Sheets remote code execution lives
    on the other side of that change."""
    import csv
    import io

    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
    writer.writerow(["type", "value", "severity", "engagement_id",
                     "source_ip", "seen_at_utc"])
    eid = iocs["engagement_id"][:8]
    sip = iocs["source_ip"]
    seen = iocs["last_seen_utc"]

    def _row(type_, value, severity):
        writer.writerow([
            type_,
            _csv_safe(value),
            severity,
            eid,
            sip,
            seen,
        ])

    for c in iocs["c2_endpoints"]:
        _row("c2_ip", f"{c['ip']}:{c['port']}", "critical")
    for d in iocs["exfil_domains"]:
        _row("exfil_domain", d["host"], "high")
    for h in iocs["decoy_targets_probed"]:
        _row("lateral_target", h, "high")
    for path in iocs["credential_files_read"]:
        _row("credential_read", path, "high")
    for path in iocs["honeytokens_modified"]:
        _row("honeytoken_modified", path, "high")
    for path in iocs["payload_drops"]:
        _row("payload_drop", path, "medium")
    _row("source_ip", sip, "info")
    return buf.getvalue()


# --- honeytoken baseline diff -----------------------------------------------

def compute_diff(eng):
    """Compare current VFS state vs the original baseline (honeytokens +
    persona-seeded placeholders). Returns a list of human-readable lines
    focused on ATTACKER actions — platform-seeded placeholders are
    folded into the baseline so they don't drown out the signal.
    """
    try:
        persona = load_persona(eng["personas_dir"], eng["claimed_user"])
    except FileNotFoundError:
        return ["(no persona file available — cannot compute baseline)"]
    rng = random.Random(eng["engagement_id"])
    baseline = Honeytokens.generate_for(persona, rng)
    baseline_files = dict(baseline.files)

    # Fold in the persona-seeded placeholders so they're not mistaken for
    # attacker writes. These match what `Session._seed_persona_listing`
    # writes at fresh-engagement init.
    known_dirs = {".ssh", ".aws", ".config", ".local", ".cache",
                  "projects", "src", "bin", "tmp", "Downloads", "Documents",
                  ".kube", "terraform", "runbooks", "infra-tools"}
    for name in persona.home_listing:
        full = f"{persona.home}/{name}"
        if name in known_dirs:
            baseline_files.setdefault(f"{full}/.keep", "")
        else:
            baseline_files.setdefault(full, "")

    current_files = eng["vfs"].get("files", {})
    deleted_paths = set(eng["vfs"].get("deleted", []))
    baseline_paths = set(baseline_files.keys())
    current_paths = set(current_files.keys())

    lines = []
    # Attacker-created paths
    seeded_system_prefixes = ("/etc/", "/var/log/")
    new_paths = current_paths - baseline_paths
    for p in sorted(new_paths):
        if p.endswith("/.keep"):
            continue
        if any(p.startswith(pfx) for pfx in seeded_system_prefixes):
            continue
        body = current_files[p]
        size = len(body)
        # `+!` flags payload-dir drops which the SOC should triage first
        prefix = "+ "
        if p.startswith("/tmp/") or p.startswith("/var/tmp/") or p.startswith("/dev/shm/"):
            prefix = "+!"
        lines.append(f"{prefix}{p}  ({size} bytes)")
    # Baseline files the attacker touched
    for p in sorted(baseline_paths):
        if p in deleted_paths:
            lines.append(f"- {p}  (DELETED by attacker)")
        elif p in current_paths and current_files[p] != baseline_files[p]:
            old_n, new_n = len(baseline_files[p]), len(current_files[p])
            # Skip noise where an empty placeholder is still empty
            if old_n == new_n == 0:
                continue
            lines.append(f"M {p}  (modified: {old_n}->{new_n} bytes)")
    if not lines:
        lines = ["(no changes from baseline — attacker hasn't touched anything yet)"]
    return lines


# --- formatting helpers ------------------------------------------------------

def count_alerts(logs):
    counts = {"critical": 0, "high": 0, "medium": 0, "info": 0}
    seen = set()
    for log in logs:
        for a in log.get("actions_taken", []):
            if a["action"] in seen:
                continue
            seen.add(a["action"])
            sev = a.get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1
    return counts


def format_alert_counts(counts):
    parts = []
    if counts.get("critical"):
        parts.append(color(f"{counts['critical']} crit", "bright_red"))
    if counts.get("high"):
        parts.append(color(f"{counts['high']} high", "magenta"))
    if counts.get("medium"):
        parts.append(color(f"{counts['medium']} med", "yellow"))
    if counts.get("info"):
        parts.append(color(f"{counts['info']} info", "dim"))
    return ", ".join(parts) if parts else color("—", "dim")


def format_duration(seconds):
    seconds = max(0, int(seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h:d}:{m:02d}:{s:02d}"


def format_iso(epoch):
    if not epoch:
        return "?"
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def format_hms(epoch):
    if not epoch:
        return "??:??:??"
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%H:%M:%S")


def format_relative_ago(epoch):
    if not epoch:
        return "?"
    delta = max(0, time.time() - epoch)
    if delta < 60:
        return f"{int(delta)}s ago"
    if delta < 3600:
        return f"{int(delta // 60)}m ago"
    if delta < 86400:
        return f"{int(delta // 3600)}h ago"
    return f"{int(delta // 86400)}d ago"


# --- main --------------------------------------------------------------------

def main():
    personas_dir = _ROOT / "personas"

    raw_args = sys.argv[1:]
    summary_mode = any(a in ("--summary", "-s") for a in raw_args)
    export_mode = "--export-ioc" in raw_args
    csv_mode = "--csv" in raw_args
    html_mode = "--html" in raw_args
    sigma_mode = "--sigma" in raw_args
    watch_mode = any(a in ("--watch", "-w") for a in raw_args)
    interval = 3.0
    since_window = None
    webhook_url = None
    skip_indices = set()
    for i, a in enumerate(raw_args):
        if a in ("--watch", "-w") and i + 1 < len(raw_args):
            nxt = raw_args[i + 1]
            try:
                interval = float(nxt)
                skip_indices.add(i + 1)
            except ValueError:
                pass
        if a in ("--since", "--from") and i + 1 < len(raw_args):
            since_window = _parse_duration(raw_args[i + 1])
            skip_indices.add(i + 1)
        if a == "--webhook" and i + 1 < len(raw_args):
            webhook_url = raw_args[i + 1]
            skip_indices.add(i + 1)

    positional = [
        a for idx, a in enumerate(raw_args)
        if not a.startswith("-")
        and idx not in skip_indices
        and not _looks_like_number(a)
    ]

    if watch_mode:
        prefix = positional[0] if positional else None
        watch_loop(personas_dir, interval, prefix)
        return

    engagements = discover_engagements(personas_dir)

    # Time window filter
    if since_window is not None:
        cutoff = time.time() - since_window
        engagements = [e for e in engagements if e["last_seen_at"] >= cutoff]

    if positional:
        prefix = positional[0]
        filtered = [e for e in engagements if e["engagement_id"].startswith(prefix)]
        if not filtered:
            print(f"No engagement matching prefix {prefix!r}", file=sys.stderr)
            sys.exit(1)
        if html_mode:
            if len(filtered) > 1:
                print(f"Ambiguous prefix {prefix!r} — narrow it for --html", file=sys.stderr)
                sys.exit(1)
            print(render_html(filtered[0]))
            return
        if sigma_mode:
            if len(filtered) > 1:
                print(f"Ambiguous prefix {prefix!r} — narrow it for --sigma", file=sys.stderr)
                sys.exit(1)
            print(render_sigma(filtered[0]))
            return
        if export_mode:
            if len(filtered) > 1:
                print(f"Ambiguous prefix {prefix!r} — narrow it for --export-ioc", file=sys.stderr)
                sys.exit(1)
            ioc_text = export_ioc(filtered[0], as_csv=csv_mode)
            if webhook_url:
                _post_to_webhook(webhook_url, filtered[0])
                print(f"posted IoC bundle for {filtered[0]['engagement_id'][:8]} to {webhook_url}",
                      file=sys.stderr)
                return
            print(ioc_text)
            return
        if summary_mode:
            print_summary(filtered)
            return
        if len(filtered) > 1:
            print(f"Ambiguous prefix {prefix!r} — {len(filtered)} matches:")
            for e in filtered:
                print(f"  {e['engagement_id']}  {e['claimed_user']}@{e['source_ip']}")
            sys.exit(1)
        print_detail(filtered[0])
        return

    if export_mode:
        bundle = [json.loads(export_ioc(e)) for e in engagements]
        if webhook_url:
            for e in engagements:
                _post_to_webhook(webhook_url, e)
            print(f"posted {len(engagements)} IoC bundle(s) to {webhook_url}", file=sys.stderr)
            return
        print(json.dumps(bundle, indent=2, default=str))
        return

    if summary_mode:
        print_summary(engagements)
    else:
        print_list(engagements)


def _post_to_webhook(url, engagement):
    """POST a single engagement's IoC bundle to `url`.

    Supports two formats:
    - If the URL looks like a Slack incoming-webhook (`hooks.slack.com`),
      sends a Slack-formatted message with the summary narrative.
    - Otherwise: sends the full IoC JSON as application/json.

    Uses httpx (already in requirements.txt).
    """
    try:
        import httpx
    except ImportError:
        print("httpx not installed; --webhook requires httpx", file=sys.stderr)
        sys.exit(2)
    payload_text = export_ioc(engagement)
    payload = json.loads(payload_text)
    if "hooks.slack.com" in url:
        body = _slack_payload(engagement, payload)
    else:
        body = payload
    try:
        r = httpx.post(url, json=body, timeout=10.0)
        r.raise_for_status()
    except Exception as exc:
        print(f"webhook POST failed: {exc}", file=sys.stderr)
        sys.exit(3)


def _slack_payload(engagement, ioc):
    """Build a compact Slack message from an IoC bundle. Uses Block Kit
    where helpful; falls back to plain text for clients that don't render
    blocks."""
    # Reuse the narrative builder for the headline
    narrative = build_narrative(engagement)
    # Strip ANSI just in case (build_narrative honors _USE_COLOR but be defensive)
    narrative = re.sub(r"\033\[[0-9;]*m", "", narrative)
    top_sev = "info"
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "info": 3}
    for a in ioc.get("alerts", []):
        if sev_rank.get(a.get("severity", "info"), 9) < sev_rank.get(top_sev, 9):
            top_sev = a.get("severity", "info")
    severity_emoji = {
        "critical": ":rotating_light:",
        "high": ":warning:",
        "medium": ":small_orange_diamond:",
        "info": ":information_source:",
    }.get(top_sev, ":mag:")
    # claimed_user is attacker-controlled (SSH username). Slack renders
    # markdown but also forwards through clients that may interpret
    # backticks differently; sanitize to ASCII-printable + safe whitespace
    # so the payload can't deface the Slack-notified analyst's screen
    # either. The narrative is built from sanitized fragments above; the
    # ANSI strip on the prior line is now redundant-but-defensive.
    text = (
        f"{severity_emoji} *Plenith engagement* `{ioc['engagement_id'][:8]}`  "
        f"({_safe(ioc['claimed_user'])}@{ioc['source_ip']})\n"
        f"```\n{narrative}\n```"
    )
    extras = []
    if ioc["c2_endpoints"]:
        extras.append(f"*C2:* " + ", ".join(f"`{c['ip']}:{c['port']}`" for c in ioc["c2_endpoints"]))
    if ioc["exfil_domains"]:
        extras.append(f"*Exfil domains:* " + ", ".join(f"`{d['host']}`" for d in ioc["exfil_domains"]))
    if ioc["decoy_targets_probed"]:
        extras.append(f"*Lateral:* " + ", ".join(f"`{h}`" for h in ioc["decoy_targets_probed"]))
    if extras:
        text += "\n" + "\n".join(extras)
    return {"text": text}


def _parse_duration(s):
    """Parse '5m' / '2h' / '24h' / '7d' / '90s' into a number of seconds."""
    s = s.strip().lower()
    if not s:
        return None
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    if s[-1] in units:
        try:
            return int(s[:-1]) * units[s[-1]]
        except ValueError:
            return None
    try:
        return int(s)
    except ValueError:
        return None


def _looks_like_number(s):
    try:
        float(s)
        return True
    except ValueError:
        return False


def watch_loop(personas_dir, interval, prefix=None):
    """Refresh-on-interval summary loop. Ctrl+C to exit.

    Note: engagement state is written by the server on SSH disconnect, so
    `--watch` shows new alerts each time a session ENDS, not per-command.
    For live per-command observation, watch the server's stdout (the
    `run.py` terminal) where every action is logged in real time.
    """
    try:
        tick = 0
        while True:
            tick += 1
            engagements = discover_engagements(personas_dir)
            if prefix:
                engagements = [e for e in engagements if e["engagement_id"].startswith(prefix)]
            # Clear + home cursor — works in Windows Terminal / PowerShell
            # because we enabled VT100 at startup.
            sys.stdout.write("\033[H\033[2J")
            now = datetime.now(timezone.utc).strftime("%H:%M:%S")
            hdr = (
                f"Plenith audit — watch mode @ {now} UTC "
                f"(refresh every {interval:.1f}s, tick #{tick})"
            )
            print(color(hdr, "bold"))
            print(color(
                "  state writes happen on SSH disconnect; new alerts appear "
                "as sessions end. Tail run.py for per-command activity.",
                "dim",
            ))
            print()
            print_summary(engagements)
            print()
            print(color(f"Ctrl+C to exit  •  {len(engagements)} engagement(s)", "dim"))
            sys.stdout.flush()
            time.sleep(interval)
    except KeyboardInterrupt:
        print()
        print(color("exited watch mode.", "dim"))


if __name__ == "__main__":
    main()
