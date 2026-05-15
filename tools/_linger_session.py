"""Throwaway: open ONE attacker SSH session that does a little recon
then stays connected and idle, so an operator can test the dashboard
Kill button against a genuinely live session.

It exercises the idle-poller path of the kill consumer
(plenith/ssh_server.py): the session sends nothing for long stretches,
so only the independent poller — not the per-command fast path — can
drop it. When the server closes the channel (operator clicked Kill),
this prints KILLED and exits.

Username is distinct so it's its own engagement row in the dashboard.
"""
from __future__ import annotations

import asyncio
import time

import asyncssh

USER = "mallory"
RECON = [
    "whoami",
    "id",
    "sudo -l",
    "cat ~/.aws/credentials",
    "cat /etc/sudoers.d/zzz_compat",
]
MAX_LINGER_S = 720          # give up after 12 min if nobody kills it
PROBE_EVERY_S = 8           # idle heartbeat cadence


async def main() -> None:
    print(f"[{USER}] connecting to 127.0.0.1:2222 …", flush=True)
    async with asyncssh.connect(
        "127.0.0.1", port=2222, username=USER, password="x",
        known_hosts=None, client_keys=None,
    ) as conn:
        async with conn.create_process(term_type="xterm",
                                       encoding="utf-8") as proc:
            await asyncio.sleep(0.5)
            for cmd in RECON:
                print(f"[{USER}] $ {cmd}", flush=True)
                proc.stdin.write(cmd + "\n")
                await proc.stdin.drain()
                await asyncio.sleep(3.0)

            print(f"[{USER}] recon done — now IDLE and connected. "
                  f"Click Kill on the '{USER}' engagement in the "
                  f"dashboard; it should drop within ~2s.", flush=True)

            start = time.time()
            while time.time() - start < MAX_LINGER_S:
                # Heartbeat: a tiny write. When the server has closed the
                # channel (Kill consumed), drain()/wait() raises or the
                # process is already gone — that's our KILLED signal.
                if proc.exit_status is not None or proc.stdin.is_closing():
                    print(f"[{USER}] KILLED — server closed the channel "
                          f"after {int(time.time()-start)}s idle.",
                          flush=True)
                    return
                try:
                    proc.stdin.write("\n")
                    await proc.stdin.drain()
                except (BrokenPipeError, ConnectionError, OSError,
                        asyncssh.ChannelOpenError):
                    print(f"[{USER}] KILLED — write failed; connection "
                          f"dropped by server.", flush=True)
                    return
                await asyncio.sleep(PROBE_EVERY_S)

            print(f"[{USER}] lingered {MAX_LINGER_S}s without a kill; "
                  f"exiting on its own.", flush=True)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (asyncssh.Error, OSError) as e:
        print(f"[{USER}] connection ended: {type(e).__name__}: {e}",
              flush=True)
