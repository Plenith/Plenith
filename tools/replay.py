"""Plenith engagement replay.

Walks the chronological command timeline of an engagement and prints each
command + a reconstructed response, with optional pacing control. Useful
for SOC training, post-incident walkthroughs, or pitching the platform to
a stakeholder.

Usage:
    python tools/replay.py <prefix>             # real-time pacing
    python tools/replay.py <prefix> --speed 2   # 2x faster than the original
    python tools/replay.py <prefix> --speed 0   # no delay (instant scroll)
    python tools/replay.py <prefix> --speed 10  # 10x faster
    python tools/replay.py <prefix> --max 50    # limit to N commands

The replayed responses come from a heuristic reconstruction of what the
server returned at runtime — for cached / vfs / sim-bot / ls / find / grep
commands we can reproduce the output deterministically from the persisted
VFS state. For LLM-bound commands we show the response_preview field
captured in the connection log (since the live LLM may give a different
answer now).
"""
import io
import json
import os
import random
import sys
import time
from datetime import datetime, timezone, UTC
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
sys.path.insert(0, str(_ROOT))

# Force UTF-8 on stdout without replacing the stream — reconfigure is
# Python 3.7+ and doesn't trigger the underlying-file-close race.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, io.UnsupportedOperation):
    pass

# Reuse the rich rendering helpers from audit.py via direct import.
import importlib.util
_audit_spec = importlib.util.spec_from_file_location("audit_mod", _HERE / "audit.py")
_audit = importlib.util.module_from_spec(_audit_spec)
_audit_spec.loader.exec_module(_audit)
# Force color on for replay output (audit's import-time isatty saw our
# wrapped stdout and disabled it).
try:
    if sys.stdout.buffer.isatty() and os.environ.get("NO_COLOR") is None:
        _audit._USE_COLOR = True
except Exception:
    pass

def load_engagement(prefix):
    state_dir = _ROOT / "state" / "persistence"
    logs_dir = _ROOT / "logs"
    personas_dir = _ROOT / "personas"
    engagements = _audit.load_engagements(state_dir, logs_dir, personas_dir)
    matches = [e for e in engagements if e["engagement_id"].startswith(prefix)]
    if not matches:
        print(f"no engagement matching prefix {prefix!r}", file=sys.stderr)
        sys.exit(1)
    if len(matches) > 1:
        print(f"ambiguous prefix {prefix!r} ({len(matches)} matches)", file=sys.stderr)
        for e in matches:
            print(f"  {e['engagement_id']}  {e['claimed_user']}@{e['source_ip']}")
        sys.exit(1)
    return matches[0]

_ALERT_COLORS = {"critical": "bright_red", "high": "magenta", "medium": "yellow", "info": "dim"}

def replay(engagement, speed=1.0, max_commands=None):
    """Iterate the timeline, printing each command and its captured
    response with sleeps proportional to the original wall-clock gaps.
    """
    cmds = []
    for log in engagement["logs"]:
        for c in log.get("commands", []):
            cmds.append(c)
    cmds.sort(key=lambda c: c["ts"])
    if max_commands:
        cmds = cmds[:max_commands]
    if not cmds:
        print("(no commands in this engagement)")
        return

    # Index actions by triggering command for inline annotation
    actions_by_cmd = {}
    for log in engagement["logs"]:
        for a in log.get("actions_taken", []):
            key = (a.get("triggered_by", ""), a.get("ts_offset_s"))
            actions_by_cmd.setdefault(key, []).append(a)

    # Header
    eid = engagement["engagement_id"]
    print(_audit.color(f"=== Replaying engagement {eid[:8]}... ===", "bold"))
    print(f"User:           {_audit.color(engagement['claimed_user'], 'cyan')}@{engagement['source_ip']}")
    print(f"First seen:     {_audit.format_iso(engagement['first_seen_at'])}")
    print(f"Connections:    {engagement.get('connection_count', 1)}")
    print(f"Commands:       {len(cmds)}")
    print(f"Speed:          {speed}x" if speed > 0 else "Speed: instant")
    print(_audit.color("-" * 60, "dim"))
    print()

    persona_user = engagement["claimed_user"]
    cwd = engagement.get("cwd", f"/home/{persona_user}")

    prev_ts = cmds[0]["ts"]
    for c in cmds:
        gap = c["ts"] - prev_ts
        prev_ts = c["ts"]
        if speed > 0 and gap > 0:
            # Real-time gap divided by speed; clamp to keep replays watchable
            sleep_s = min(gap / speed, 5.0)
            time.sleep(sleep_s)

        ts = datetime.fromtimestamp(c["ts"], tz=UTC).strftime("%H:%M:%S")
        cmd = c["cmd"]
        src = c.get("response_source", "?")
        body = c.get("response_preview", "") or ""

        # Track cwd through cd commands
        if cmd.startswith("cd ") or cmd.strip() == "cd":
            target = cmd[3:].strip() if cmd.startswith("cd ") else ""
            if target == "" or target == "~":
                cwd = f"/home/{persona_user}"
            elif target.startswith("~/"):
                cwd = f"/home/{persona_user}{target[1:]}"
            elif target.startswith("/"):
                cwd = target.rstrip("/") or "/"
            elif target == "..":
                parent = "/".join(cwd.rstrip("/").split("/")[:-1])
                cwd = parent or "/"
            elif target == "-":
                pass  # previous dir; we don't track it
            else:
                cwd = f"{cwd.rstrip('/')}/{target}"

        # Render the prompt + command
        prompt_cwd = cwd if cwd != f"/home/{persona_user}" else "~"
        prompt = f"{persona_user}@corp-app01:{prompt_cwd}$"
        src_color = _audit._src_color(src)
        src_tag = f"[{_audit.color(src.ljust(11), src_color)}]"
        print(f"{_audit.color(ts, 'dim')}  {src_tag}  {_audit.color(prompt, 'cyan')} {cmd}")
        if body and body.strip():
            for line in body.rstrip().split("\n"):
                print(f"          {line}")

        # Inline alert annotation
        for key, acts in list(actions_by_cmd.items()):
            if key[0] == cmd:
                for a in acts:
                    sev = a.get("severity", "info")
                    col = _ALERT_COLORS.get(sev, "white")
                    badge = _audit.color(f"  ⚠  [{sev.upper()}] {a['action']}", col)
                    print(badge)
                    rationale = a.get("rationale", "")[:140]
                    print(_audit.color(f"     {rationale}", "dim"))
                actions_by_cmd.pop(key, None)
        print()

    print(_audit.color("-" * 60, "dim"))
    print(_audit.color(f"=== End of replay ({len(cmds)} commands) ===", "bold"))

def main():
    args = sys.argv[1:]
    speed = 1.0
    max_commands = None
    positional = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--speed" and i + 1 < len(args):
            try:
                speed = float(args[i + 1])
            except ValueError:
                pass
            i += 2
        elif a == "--max" and i + 1 < len(args):
            try:
                max_commands = int(args[i + 1])
            except ValueError:
                pass
            i += 2
        elif a.startswith("-"):
            i += 1
        else:
            positional.append(a)
            i += 1

    if not positional:
        print("usage: replay.py <engagement-id-prefix> [--speed N] [--max N]",
              file=sys.stderr)
        sys.exit(2)

    eng = load_engagement(positional[0])
    try:
        replay(eng, speed=speed, max_commands=max_commands)
    except KeyboardInterrupt:
        print()
        print(_audit.color("(interrupted)", "dim"))

if __name__ == "__main__":
    main()
