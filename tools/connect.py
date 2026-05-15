"""Convenience SSH wrapper for Plenith.

Reads config.yaml to determine the host/port the honeypot is bound to,
spawns an interactive `ssh` against it, and on disconnect automatically
prints the audit summary for the engagement you just produced.

This makes the dev loop a single command:
    python tools/connect.py
    # ... do your attacker chain ...
    # exit
    # → audit summary prints automatically

Options:
    --user <name>      override the SSH username (default: jdoe)
    --no-audit         skip the auto-audit on exit
    --speed <N>        also replay the engagement at speed N afterwards

Falls back gracefully if `ssh` isn't on PATH or if no engagement was
produced (e.g. you didn't actually authenticate).
"""
import io
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import yaml

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
sys.path.insert(0, str(_ROOT))

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, io.UnsupportedOperation, ValueError):
    pass

def _load_config():
    cfg_path = _ROOT / "config.yaml"
    with open(cfg_path, encoding="utf-8") as f:
        return yaml.safe_load(f)

def _newest_engagement_for(ip, user):
    """Return the path of the most recent state file matching (ip, user),
    or None if nothing's there."""
    state_dir = _ROOT / "state" / "persistence"
    if not state_dir.exists():
        return None
    safe = f"{ip}__{user}".replace(":", "_")
    candidate = state_dir / f"{safe}.json"
    return candidate if candidate.exists() else None

def _engagement_id_from_state(state_path):
    import json
    try:
        with open(state_path, encoding="utf-8") as f:
            return json.load(f).get("engagement_id")
    except Exception:
        return None

def main():
    cfg = _load_config()
    host = cfg["ssh"]["host"]
    port = cfg["ssh"]["port"]
    if host == "0.0.0.0":
        host = "127.0.0.1"  # ssh can't dial 0.0.0.0

    args = sys.argv[1:]
    user = "jdoe"
    speed = None
    auto_audit = True
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--user" and i + 1 < len(args):
            user = args[i + 1]; i += 2
        elif a == "--speed" and i + 1 < len(args):
            speed = args[i + 1]; i += 2
        elif a == "--no-audit":
            auto_audit = False; i += 1
        else:
            i += 1

    ssh = shutil.which("ssh") or "ssh"

    # Heads-up about what we're doing.
    print(f"=== Plenith connect: ssh -p {port} {user}@{host} ===")
    print("(any password works; type `exit` to leave; audit will run automatically)")
    print()

    # Note the latest engagement BEFORE this connection so we can detect
    # whether the connection actually produced one.
    pre_state = _newest_engagement_for(host, user)
    pre_mtime = pre_state.stat().st_mtime if pre_state else 0

    t0 = time.time()
    rc = subprocess.call([ssh, "-p", str(port), f"{user}@{host}"])
    elapsed = time.time() - t0
    print()
    print(f"=== ssh exited (rc={rc}, elapsed {elapsed:.1f}s) ===")

    if not auto_audit:
        return

    # Wait briefly for the server to finish writing the state file
    # (connection_lost is async; small grace period).
    deadline = time.time() + 3.0
    while time.time() < deadline:
        post_state = _newest_engagement_for(host, user)
        if post_state and post_state.stat().st_mtime > pre_mtime:
            break
        time.sleep(0.25)
    post_state = _newest_engagement_for(host, user)

    if post_state is None or post_state.stat().st_mtime <= pre_mtime:
        print()
        print("(no new engagement persisted — did the SSH session reach auth?)")
        return

    eid = _engagement_id_from_state(post_state)
    if not eid:
        print("(engagement state unreadable — skipping audit)")
        return

    prefix = eid[:8]
    print()
    print("─" * 60)
    py = sys.executable
    audit = _ROOT / "tools" / "audit.py"
    subprocess.call([py, str(audit), "--summary", prefix])
    if speed is not None:
        print()
        print("─" * 60)
        replay = _ROOT / "tools" / "replay.py"
        subprocess.call([py, str(replay), prefix, "--speed", str(speed)])

if __name__ == "__main__":
    main()
