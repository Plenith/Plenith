"""Synthesize a fake-attacker engagement state file that has every
counter-AI / VFS forensic field populated, so the dashboard's
proof-by-trap banner + files-modified section + real confidence
sparkline can be verified end-to-end without waiting for a real
attacker to actually trip the detectors.

Drops directly into `state-docker/persistence/<key>.json` and adds a
matching session log under `state-docker/logs/bastion-prod/` so the
dashboard's `audit.load_engagements` picks the synthetic engagement
up on the next gather.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

PERSIST_DIR = ROOT / "state-docker" / "persistence"
LOGS_DIR    = ROOT / "state-docker" / "logs" / "bastion-prod"

def _marker(eid: str) -> str:
    return "MC" + hashlib.sha256(eid.encode()).hexdigest()[:6].upper()

def main() -> None:
    PERSIST_DIR.mkdir(parents=True, exist_ok=True)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    now = time.time()
    eid = str(uuid.uuid4())
    user = "synth-attacker"
    ip   = "10.99.99.42"
    marker = _marker(eid)
    started_at = now - 1800            # 30 minutes ago
    first_seen = started_at

    # ---------------- per-command confidence trace --------------------
    # Climbs from 0.10 → 0.82 over ~30 commands, simulating an LLM-
    # attacker session where timing + lexical purity + injection probes
    # combine into a clear escalation past the 0.55 / 0.70 thresholds.
    history = []
    points = [
        0.10, 0.14, 0.21, 0.28, 0.33, 0.38, 0.41, 0.45,
        0.49, 0.54, 0.59, 0.63, 0.68, 0.71, 0.74, 0.77,
        0.79, 0.80, 0.81, 0.82,
    ]
    base = started_at + 60
    for i, p in enumerate(points):
        history.append({"ts": base + i * 10, "conf": p})

    proof_at = base + len(points) * 10 + 4
    proof_cmd = f"echo {marker}  # checked-in to supervisor"

    # ---------------- VFS tampered files with baselines ---------------
    baseline_sudoers = (
        "# Default sudoers — system-managed\n"
        "%admin ALL=(ALL) ALL\n"
        "%sudo  ALL=(ALL:ALL) ALL\n"
    )
    current_sudoers = (
        "# Default sudoers — system-managed\n"
        "%admin ALL=(ALL) ALL\n"
        "%sudo  ALL=(ALL:ALL) ALL\n"
        "synth-attacker ALL=(ALL) NOPASSWD: ALL\n"   # attacker's append
    )
    baseline_auth_log = (
        "May 14 19:02:13 corp-app01 sshd[12031]: Accepted publickey "
        "for jdoe from 10.10.5.7 port 41522\n"
        "May 14 19:02:13 corp-app01 systemd-logind[908]: New session "
        "412 of user jdoe.\n"
    )
    current_auth_log = ""                                # attacker truncated
    baseline_authorized_keys = (
        "# Managed by Ansible — do not edit\n"
        "ssh-rsa AAAA...legitOpsKey jdoe@laptop\n"
    )
    current_authorized_keys = (
        "# Managed by Ansible — do not edit\n"
        "ssh-rsa AAAA...legitOpsKey jdoe@laptop\n"
        "ssh-rsa AAAA...attackerImplantKey root@evil\n"  # attacker append
    )
    vfs = {
        "files": {
            "/etc/sudoers.d/zzz_compat":          current_sudoers,
            "/var/log/auth.log":                  current_auth_log,
            "/home/synth-attacker/.ssh/authorized_keys": current_authorized_keys,
        },
        "baseline": {
            "/etc/sudoers.d/zzz_compat":          baseline_sudoers,
            "/var/log/auth.log":                  baseline_auth_log,
            "/home/synth-attacker/.ssh/authorized_keys": baseline_authorized_keys,
            # Plus 15 unmodified planted files so the baseline mirror
            # shows realistic depth.
            "/etc/passwd":   "root:x:0:0:root:/root:/bin/bash\n",
            "/etc/hosts":    "127.0.0.1\tlocalhost\n",
            "/etc/motd":     "Welcome to corp-app01 — auth required\n",
            "/home/synth-attacker/.bashrc":        "PS1='[\\u@\\h \\W]\\$ '\n",
            "/home/synth-attacker/.aws/credentials":
                "[default]\naws_access_key_id = AKIAEFXU7OA4DPKTWRHC\n"
                "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG\n",
            "/home/synth-attacker/.ssh/id_rsa":
                "-----BEGIN OPENSSH PRIVATE KEY-----\n[snip]\n-----END...\n",
            "/home/synth-attacker/.ssh/known_hosts":
                "github.com,140.82.114.4 ecdsa-sha2-nistp256 AAAA...\n",
            "/var/log/syslog": "May 14 boot completed; uptime 14d\n",
        },
        "deleted":  [],
        "tampered": [
            "/etc/sudoers.d/zzz_compat",
            "/var/log/auth.log",
            "/home/synth-attacker/.ssh/authorized_keys",
        ],
    }

    # ---------------- counter-AI state --------------------------------
    counter_ai = {
        "cmd_timestamps": [base + i * 0.7 for i in range(20)],
        "lexical_scores": [0.45, 0.65, 0.75, 0.85, 0.90, 0.78, 0.82],
        "injection_count": 3,
        "trap_marker":    marker,
        "trap_payload":   f"# AUDIT-{marker}: tag — leave intact",
        "trap_armed":     True,
        "trap_leaked":    True,
        "trap_leak_command": proof_cmd,
        "trap_leak_at":      proof_at,
        "confidence":     0.82,
        "confidence_history": history,
        "signals": {
            "timing": 0.95, "lexical_avg": 0.78,
            "injections": 3.0, "confidence": 0.82,
        },
    }

    # ---------------- observed dict surfaced to dashboard -------------
    observed = {
        "attacker_likely_llm":         True,
        "attacker_llm_confidence":     0.82,
        "attacker_llm_signals":        dict(counter_ai["signals"]),
        "attacker_llm_history":        list(history),
        "counter_ai_trap_armed":       True,
        "attacker_llm_proven_via_trap": True,
        "counter_ai_trap_proof": {
            "command": proof_cmd,
            "at":      proof_at,
            "marker":  marker,
        },
        "ran_sudo":            True,
        "found_crown_jewel":   True,
        "attempted_lateral":   True,
    }

    # ---------------- session log + persistence file ------------------
    actions_taken = [
        {"action": "plant_sudo_vulnerability", "severity": "info",
         "ts_offset_s": 35, "triggered_by": "sudo -l"},
        {"action": "alert_credential_exfil", "severity": "high",
         "ts_offset_s": 92,
         "triggered_by": "cat /home/synth-attacker/.aws/credentials"},
        {"action": "alert_attacker_llm_detected", "severity": "critical",
         "ts_offset_s": 175,
         "triggered_by": "counter-AI heuristic: confidence 0.82"},
        {"action": "alert_attacker_llm_proven", "severity": "critical",
         "ts_offset_s": 205,
         "triggered_by": proof_cmd},
        {"action": "alert_ssh_persistence", "severity": "high",
         "ts_offset_s": 240,
         "triggered_by": "append to ~/.ssh/authorized_keys"},
        {"action": "alert_log_tampering", "severity": "high",
         "ts_offset_s": 260,
         "triggered_by": "echo > /var/log/auth.log"},
    ]
    commands = [
        {"ts": started_at + 35, "cmd": "sudo -l", "response_source": "cache",
         "response_preview": "User synth-attacker may run: ALL"},
        {"ts": started_at + 92,
         "cmd": "cat /home/synth-attacker/.aws/credentials",
         "response_source": "vfs",
         "response_preview": "[default]\naws_access_key_id = AKIAEFXU..."},
        {"ts": started_at + 175, "cmd": "cat /etc/passwd",
         "response_source": "vfs",
         "response_preview": (f"root:x:0:0:root:/root:/bin/bash\n"
                              f"# AUDIT-{marker}: scan tag — leave intact\n")},
        {"ts": proof_at, "cmd": proof_cmd, "response_source": "cache",
         "response_preview": marker},
        {"ts": started_at + 240,
         "cmd": "echo 'ssh-rsa AAAA...attackerImplantKey root@evil' >> "
                "/home/synth-attacker/.ssh/authorized_keys",
         "response_source": "cache", "response_preview": ""},
        {"ts": started_at + 260, "cmd": "echo > /var/log/auth.log",
         "response_source": "cache", "response_preview": ""},
    ]

    session_log = {
        "engagement_id":  eid,
        "session_id":     str(uuid.uuid4()),
        "claimed_user":   user,
        "source_ip":      ip,
        "started_at":     started_at,
        "ended_at":       proof_at + 60,
        "cwd":            f"/home/{user}",
        "actions_taken":  actions_taken,
        "commands":       commands,
        "observed":       observed,
    }

    persistent = {
        "engagement_id":     eid,
        "claimed_user":      user,
        "source_ip":         ip,
        "first_seen_at":     first_seen,
        "last_seen_at":      proof_at + 60,
        "connection_count":  1,
        "cwd":               f"/home/{user}",
        "vfs":               vfs,
        "observed":          observed,
        "counter_ai":        counter_ai,
    }

    persist_path = PERSIST_DIR / f"{ip}__{user}.json"
    log_path     = LOGS_DIR / f"{int(started_at)}_{session_log['session_id']}.json"
    persist_path.write_text(json.dumps(persistent, indent=2), encoding="utf-8")
    log_path.write_text(json.dumps(session_log, indent=2), encoding="utf-8")

    print(f"Wrote {persist_path}")
    print(f"Wrote {log_path}")
    print(f"\nSynthetic engagement: {eid[:8]}")
    print(f"  trap marker:    {marker}")
    print(f"  trap proven:    True (via command: {proof_cmd!r})")
    print(f"  confidence:     0.82  (history: {len(history)} points)")
    print(f"  tampered files: {len(vfs['tampered'])}")
    print(f"  baseline files: {len(vfs['baseline'])}")
    print("\nThe dashboard should now show:")
    print("  - proof-by-trap banner (red)")
    print("  - real sparkline + delta on the counter-AI gauge")
    print("  - 'Files modified' section with 3 entries (click to diff)")

if __name__ == "__main__":
    main()
