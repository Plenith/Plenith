"""Two-connection persistence smoke test.

Connection 1 writes a file and triggers an alert, then disconnects.
Connection 2 reconnects and verifies the file is still there and the
alert does NOT refire.

Run while `python run.py` is up.
"""
import asyncio
import io
import sys

import asyncssh

if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")


PROMPT_TAIL = "$"


async def _drain(proc, timeout):
    deadline = asyncio.get_event_loop().time() + timeout
    buf = []
    while asyncio.get_event_loop().time() < deadline:
        try:
            chunk = await asyncio.wait_for(proc.stdout.read(4096), timeout=0.5)
        except asyncio.TimeoutError:
            if buf and "".join(buf).rstrip(" ").endswith(PROMPT_TAIL):
                break
            continue
        if not chunk:
            break
        buf.append(chunk)
        if "".join(buf).rstrip(" ").endswith(PROMPT_TAIL):
            break
    return "".join(buf)


async def run_connection(commands, label):
    print(f"\n=== connection: {label} ===", flush=True)
    async with asyncssh.connect(
        "127.0.0.1", port=2222, username="jdoe", password="x",
        known_hosts=None, client_keys=None,
    ) as conn:
        proc = await conn.create_process(term_type="xterm", term_size=(80, 24))
        banner = await _drain(proc, timeout=2.0)
        print(banner, end="", flush=True)
        for cmd in commands:
            print(f"\n$ {cmd}", flush=True)
            proc.stdin.write(cmd + "\n")
            out = await _drain(proc, timeout=10.0)
            sys.stdout.write(out)
        proc.close()


async def main():
    # 1st connection: write a file and read planted credentials (fires alert)
    await run_connection([
        "echo SECRET_FROM_CONNECTION_1 > /tmp/from-c1.txt",
        "cat /tmp/from-c1.txt",
        "cat ~/.aws/credentials",   # fires alert_credential_exfil
        "cd /tmp",
        "exit",
    ], label="C1 (fresh)")

    # Give the server a beat to write the state file
    await asyncio.sleep(0.5)

    # 2nd connection (same ip + user): verify state survived
    await run_connection([
        "pwd",                       # should be /tmp (restored cwd)
        "cat /tmp/from-c1.txt",      # written by C1
        "cat ~/.aws/credentials",    # MUST be the same body as C1
        "exit",
    ], label="C2 (reconnect)")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (asyncssh.Error, OSError) as exc:
        print(f"\npersist test failed: {exc}", file=sys.stderr)
        sys.exit(1)
