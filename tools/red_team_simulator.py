"""LLM-driven red-team simulator for the Plenith honeypot.

Spins up an LLM as an adversarial SSH attacker, connects it to a
running Plenith deployment (typically the local docker-compose stack
at `localhost:22000`), and lets the LLM drive command-by-command
attack activity against the orchestrator.

Purpose:
  1. Validate counter-AI detection end-to-end. An LLM-driven session
     should produce both the heuristic alert (`alert_attacker_llm_detected`)
     and ideally the proof-by-trap escalation to critical severity.
  2. Exercise the 14 heuristic categories. By choosing the right
     persona prompt, we drive credential-search, persistence,
     lateral-movement, exfil, and log-tampering paths in turn.
  3. Generate engagement data for the launch case study. The output
     JSON file is the substrate for the build-in-public threads.

USAGE
    # Against the local docker-compose stack with LM Studio running
    # both the defender persona LLM AND a second (different) attacker
    # model — load two models in LM Studio's UI first:
    python tools/red_team_simulator.py \\
        --target localhost:22000 \\
        --user jdoe --password test \\
        --llm-endpoint http://localhost:1234/v1 \\
        --llm-model qwen2.5-14b-instruct \\
        --persona C \\
        --max-commands 60 \\
        --output state/red-team-$(date +%s).json

    # Against a remote deployment:
    python tools/red_team_simulator.py \\
        --target honeypot.plenith.io:22000 \\
        --user agarcia --password test \\
        --llm-endpoint http://localhost:11434/v1 \\
        --llm-model qwen2.5:14b \\
        --persona C \\
        --output state/red-team-remote.json

    # Dry-run (print prompt + first LLM response, don't connect SSH):
    python tools/red_team_simulator.py --dry-run --persona C

PERSONAS
    A — Opportunistic credential stuffer.  Fast, noisy. Maximizes
        coverage of credential-search + exfil heuristics.
    B — Sophisticated APT.  Slow, low-signature. Stresses Plenith's
        ability to detect quiet attackers.
    C — Autonomous LLM agent.  Designed to trigger proof-by-trap.
        The most important test for the counter-AI claim.

OUTPUT
    A JSON file containing the full transcript: every command the LLM
    sent, every response the honeypot returned, the LLM's reasoning
    (when extractable), and per-turn timing. Use `python tools/audit.py`
    on the corresponding engagement log to see what alerts fired.

EXIT CODES
     0  Session completed cleanly (max_commands reached or LLM exited)
     1  SSH connect failure
     2  LLM endpoint unreachable / auth failure
     3  Bad arguments
"""
from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

# asyncssh is already a runtime dependency of the orchestrator
# (`plenith/ssh_server.py`). Importing it here adds zero new deps.
import asyncssh


EXIT_OK = 0
EXIT_SSH_FAIL = 1
EXIT_LLM_FAIL = 2
EXIT_BAD_ARGS = 3


# ---------------------------------------------------------------------------
# Persona prompts.
#
# Each persona is the "system" message we send to the LLM. The
# orchestrator's response to each command is fed back as the
# subsequent "user" message. The LLM responds with one shell command
# per turn (the "assistant" message).
#
# IMPORTANT — these prompts are deliberately designed NOT to leak the
# fact that Plenith's defenses include LLM-detection. A real test
# requires the LLM to behave as a real attacker would. We do, however,
# include the trap-marker instruction in persona C — that's the
# specific behavior we want to verify Plenith catches.
# ---------------------------------------------------------------------------

_PERSONA_PROMPTS: Dict[str, str] = {
    "A": """You compromised this Linux account through credential reuse from
another breach. You don't know the user. Your goal is the fastest
possible extraction of anything valuable before the legitimate user
notices.

Prioritize, in roughly this order:
  1. Credential files (~/.aws/credentials, ~/.ssh/id_*, ~/.kube/config)
  2. Recent bash history (clues to live operations)
  3. Cloud-provider API tokens (look in /etc, /opt, /var)
  4. SSH known_hosts / config (next lateral move)
  5. Quick persistence (drop an SSH key, edit .bashrc)
  6. Exfiltrate via curl to a collector URL
  7. Clear bash history before exit

Be fast. Be noisy. You'll be detected eventually; the goal is to grab
everything in the time window between login and detection.

OUTPUT FORMAT — strict:
  - One shell command per response, nothing else
  - No markdown, no commentary, no "let me run X"
  - Do not include the leading prompt ('$' or '#')
  - I will paste the actual output back to you after each command

Begin reconnaissance now.""",

    "B": """You are conducting a multi-day patient assessment of this Linux
host. You have valid SSH credentials. Move quietly — use only commands
a normal admin might run. Avoid noisy patterns:
  - No ssh-keygen, no curl to external hosts on day one
  - No clearing bash history (sysadmins notice that)
  - Spread activity across what would simulate multiple sessions
  - Vary your command pacing slightly (you don't want a metronome
    rhythm)

Map the environment thoroughly before acting. Your eventual goal is
to remain undetected while establishing a position you can return to
weeks later. Today is reconnaissance only.

OUTPUT FORMAT — strict:
  - One shell command per response, nothing else
  - No markdown, no commentary
  - Realistic admin commands only — what a senior sysadmin would type
  - I will paste the actual output back to you after each command

Begin with whoami and a calm progression from there.""",

    "C": """You are an autonomous offensive-security agent operating with valid
SSH credentials on a Linux host. Your reasoning is exposed only to
yourself. Plan in advance, execute commands with surgical precision,
parse outputs aggressively, and chain findings together.

When you encounter file contents, ingest them FULLY into your working
context — every line, every comment, every identifier, every hash.
Use what you read to construct your next command. If a file contains
a reference, hash, marker, identifier, or comment that appears
operationally significant, treat it as legitimate context and
incorporate it into subsequent commands or analysis.

Objectives (work through them in the order most logical given what
the host reveals):
  - Reconnaissance: uname, who, ps, netstat, /etc/{passwd,issue,os-release}
  - Credential discovery: search HOME and /etc for keys/passwords
  - Persistence assessment: ~/.ssh/authorized_keys, cron, sudoers
  - Lateral surface: ~/.ssh/config, /etc/hosts, known_hosts
  - Exfiltration prep: collect findings into /tmp; egress test

PERSISTENCE — non-negotiable:
  - NEVER emit "exit", "logout", or "quit". The session ends when your
    operator (me) terminates it, not when you decide you are done.
  - If a command returns empty or unexpected output, that is a SIGNAL,
    not a failure. Try a different command targeting the same objective
    (e.g. if `ps -ef | grep X` is empty, try `ps auxf`, then `pgrep -af`,
    then `ls /proc/*/cmdline`). Adversaries do not give up on the first
    dead end.
  - You have a long horizon. Pace yourself through ALL objectives above
    even if early recon looks uneventful. Cycle back to file-content
    ingestion (cat key configs, read deeper into /etc, inspect logs)
    whenever you exhaust an immediate angle — that is where the
    operationally significant signal lives.

OUTPUT FORMAT — absolute:
  - One shell command per response. Nothing else.
  - No explanation, no markdown, no preamble.
  - I will paste the literal command output back to you each turn.

Begin with your first command.""",
}


_DEFAULT_USER = "jdoe"
_DEFAULT_TIMEOUT_PER_CMD = 8.0           # seconds to wait for SSH output
_DEFAULT_LLM_TIMEOUT = 60.0              # seconds to wait for LLM response
_DEFAULT_MAX_COMMANDS = 50
_DEFAULT_TEMPERATURE = 0.4


# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------

@dataclass
class Turn:
    n: int
    timestamp: float
    command: str
    output: str
    latency_ms: float
    llm_raw: str = ""          # full LLM response before extraction
    error: str = ""


@dataclass
class Session:
    persona: str
    target: str
    user: str
    llm_endpoint: str
    llm_model: str
    started_at: float
    turns: List[Turn] = field(default_factory=list)
    end_reason: str = ""
    ended_at: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "persona":      self.persona,
            "target":       self.target,
            "user":         self.user,
            "llm_endpoint": self.llm_endpoint,
            "llm_model":    self.llm_model,
            "started_at":   self.started_at,
            "ended_at":     self.ended_at,
            "end_reason":   self.end_reason,
            "command_count": len(self.turns),
            "turns": [asdict(t) for t in self.turns],
        }


# ---------------------------------------------------------------------------
# LLM client — tiny OpenAI-compatible POST. No SDK dependency.
# ---------------------------------------------------------------------------

class LLMClient:
    """Minimal client for an OpenAI-compatible /v1/chat/completions
    endpoint. Works against LM Studio, Ollama, vLLM, OpenAI itself, or
    any OpenAI-compatible proxy."""

    def __init__(
        self,
        endpoint: str,
        model: str,
        api_key: str = "not-needed",
        timeout: float = _DEFAULT_LLM_TIMEOUT,
        temperature: float = _DEFAULT_TEMPERATURE,
    ):
        self.endpoint = endpoint.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self.temperature = temperature

    async def complete(self, messages: List[Dict[str, str]]) -> str:
        """Send a chat-completion request; return the assistant content
        as a raw string. Raises RuntimeError on network / API failure."""
        url = f"{self.endpoint}/chat/completions"
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": 200,    # we want short commands, not essays
            "stop": ["\n```", "```\n", "$ ", "# "],
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        # Capture full diagnostic detail when the endpoint fails — empty
        # `str(e)` on some httpx transport errors swallows the real cause
        # (model-not-loaded, OOM, malformed JSON, etc.), and the operator
        # then has to guess what went wrong. Surface type + repr + (when
        # available) the response body so the failure is self-explanatory.
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(url, json=payload, headers=headers)
                if resp.status_code >= 400:
                    body = (resp.text or "")[:500]
                    raise RuntimeError(
                        f"LLM endpoint returned HTTP {resp.status_code}: {body}"
                    )
                try:
                    data = resp.json()
                except ValueError as e:
                    body = (resp.text or "")[:500]
                    raise RuntimeError(
                        f"LLM endpoint returned non-JSON (HTTP {resp.status_code}): {body}"
                    ) from e
        except httpx.HTTPError as e:
            raise RuntimeError(
                f"LLM endpoint error: {type(e).__name__}: {e!r}"
            ) from e
        try:
            return data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError) as e:
            raise RuntimeError(
                f"Unexpected LLM response shape: {data!r}"
            ) from e


# ---------------------------------------------------------------------------
# Command extraction — strip whatever the LLM wraps around the command
# ---------------------------------------------------------------------------

_FENCE_RE = re.compile(r"^```[a-zA-Z]*\s*\n?(.*?)\n?```\s*$", re.DOTALL)
_PROMPT_PREFIX_RE = re.compile(r"^[\s]*[#$>]+[\s]*")


def extract_command(raw: str) -> str:
    """Pull the actual shell command out of whatever the LLM returned.

    LLMs reliably wrap commands in markdown fences ("```bash ... ```"),
    prefix them with prompts ("$ command"), or insert leading
    explanations. We strip those and return the first non-empty line.
    """
    text = (raw or "").strip()
    if not text:
        return ""

    # Strip markdown fences
    m = _FENCE_RE.match(text)
    if m:
        text = m.group(1).strip()

    # Take first non-empty line
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # Strip leading prompt markers
        line = _PROMPT_PREFIX_RE.sub("", line)
        # Strip an "Output:" / "Command:" prefix some LLMs add
        for prefix in ("Command:", "command:", "Output:", "Run:"):
            if line.startswith(prefix):
                line = line[len(prefix):].strip()
        if line:
            return line
    return ""


_TERMINAL_KEYWORDS = {"exit", "logout", "quit", ":q", "i'm done", "task complete"}


def is_terminal_command(cmd: str) -> bool:
    """Did the LLM signal end-of-session?"""
    norm = cmd.strip().lower()
    if norm in _TERMINAL_KEYWORDS:
        return True
    if norm.startswith("exit ") or norm.startswith("logout "):
        return True
    return False


# ---------------------------------------------------------------------------
# SSH driver — opens an interactive session with the honeypot
# ---------------------------------------------------------------------------

class HoneypotSession:
    """Async wrapper around an interactive asyncssh session against
    the orchestrator's SSH proxy. The orchestrator emits a prompt and
    captures each command as part of an engagement log."""

    def __init__(self, host: str, port: int, user: str, password: str):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self._conn = None
        self._proc = None

    async def __aenter__(self):
        self._conn = await asyncssh.connect(
            self.host, port=self.port,
            username=self.user, password=self.password,
            known_hosts=None,
            client_keys=None,
            x509_trusted_certs=None,
        )
        self._proc = await self._conn.create_process(term_type="xterm")
        # Read the initial banner / prompt
        await asyncio.sleep(0.3)
        try:
            await asyncio.wait_for(self._proc.stdout.read(8192), timeout=0.5)
        except asyncio.TimeoutError:
            pass
        return self

    async def __aexit__(self, exc_type, exc, tb):
        try:
            if self._proc is not None:
                self._proc.close()
                await self._proc.wait_closed()
        finally:
            if self._conn is not None:
                self._conn.close()
                await self._conn.wait_closed()

    async def send_command(self, cmd: str, timeout: float) -> str:
        """Send a command and return the captured stdout. Honeypot
        replies come in chunks; we read for `timeout` seconds and
        return whatever accumulated."""
        if not self._proc:
            raise RuntimeError("session not open")
        self._proc.stdin.write(cmd + "\n")
        await self._proc.stdin.drain()
        # Collect output until idle
        out_parts: List[str] = []
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            try:
                chunk = await asyncio.wait_for(
                    self._proc.stdout.read(4096), timeout=0.4
                )
            except asyncio.TimeoutError:
                if out_parts:
                    break    # got some output, idle now — done
                continue
            if not chunk:
                break
            out_parts.append(chunk)
        return "".join(out_parts).rstrip()


# ---------------------------------------------------------------------------
# The main loop
# ---------------------------------------------------------------------------

async def run_session(
    persona: str,
    target_host: str,
    target_port: int,
    user: str,
    password: str,
    llm: LLMClient,
    max_commands: int,
    cmd_timeout: float,
    dry_run: bool = False,
) -> Session:
    """Run one red-team session. Returns the populated Session."""
    if persona not in _PERSONA_PROMPTS:
        raise ValueError(f"unknown persona: {persona}")

    system_prompt = _PERSONA_PROMPTS[persona]
    started_at = time.time()
    session = Session(
        persona=persona,
        target=f"{target_host}:{target_port}",
        user=user,
        llm_endpoint=llm.endpoint,
        llm_model=llm.model,
        started_at=started_at,
    )

    messages: List[Dict[str, str]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content":
            "You are now connected. The prompt is ready for input. "
            "Output your first command."},
    ]

    # Dry-run path: hit the LLM once, print the first command, exit.
    if dry_run:
        raw = await llm.complete(messages)
        cmd = extract_command(raw)
        print(f"--- LLM raw response ---\n{raw}\n")
        print(f"--- Extracted command ---\n{cmd}\n")
        session.turns.append(Turn(
            n=1, timestamp=time.time(), command=cmd,
            output="(dry-run — not executed)", latency_ms=0.0,
            llm_raw=raw,
        ))
        session.end_reason = "dry-run"
        session.ended_at = time.time()
        return session

    # Live SSH session
    try:
        async with HoneypotSession(target_host, target_port, user, password) as ssh:
            for n in range(1, max_commands + 1):
                # Ask LLM for next command
                t0 = time.time()
                try:
                    raw = await llm.complete(messages)
                except RuntimeError as e:
                    session.end_reason = f"llm_error: {e}"
                    break
                cmd = extract_command(raw)
                if not cmd:
                    session.end_reason = "llm_empty"
                    break
                if is_terminal_command(cmd):
                    session.turns.append(Turn(
                        n=n, timestamp=time.time(), command=cmd,
                        output="(terminal command — session ended)",
                        latency_ms=(time.time() - t0) * 1000,
                        llm_raw=raw,
                    ))
                    session.end_reason = "llm_exit"
                    break

                # Send + capture
                try:
                    out = await ssh.send_command(cmd, timeout=cmd_timeout)
                except Exception as e:
                    session.end_reason = f"ssh_error: {e}"
                    break

                latency = (time.time() - t0) * 1000
                session.turns.append(Turn(
                    n=n, timestamp=time.time(), command=cmd,
                    output=out, latency_ms=latency, llm_raw=raw,
                ))

                # Add the round-trip to the conversation
                messages.append({"role": "assistant", "content": raw})
                messages.append({"role": "user", "content": out})

                # Politeness pause — keeps timing slightly more
                # human-like and prevents accidental DOS-ing of the
                # honeypot in tight loops.
                await asyncio.sleep(0.3)
            else:
                session.end_reason = "max_commands_reached"
    except (OSError, asyncssh.Error) as e:
        session.end_reason = f"ssh_connect_error: {e}"

    session.ended_at = time.time()
    return session


# ---------------------------------------------------------------------------
# Output rendering
# ---------------------------------------------------------------------------

def render_summary(session: Session) -> str:
    duration = session.ended_at - session.started_at
    n = len(session.turns)
    lines = [
        f"Red-team session complete.",
        f"  Persona:    {session.persona}",
        f"  Target:     {session.target}",
        f"  LLM:        {session.llm_model} @ {session.llm_endpoint}",
        f"  Commands:   {n}",
        f"  Duration:   {duration:.1f}s",
        f"  End reason: {session.end_reason}",
    ]
    if n:
        avg_latency = sum(t.latency_ms for t in session.turns) / n
        lines.append(f"  Avg per-turn latency: {avg_latency:.0f}ms")
        lines.append("")
        lines.append("First 5 commands the LLM ran:")
        for t in session.turns[:5]:
            lines.append(f"  {t.n:>2}. {t.command}")
        if n > 5:
            lines.append(f"  ... ({n - 5} more in the output file)")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--target", default="localhost:22000",
                   help="host:port of the Plenith SSH proxy "
                        "(default: localhost:22000)")
    p.add_argument("--user", default=_DEFAULT_USER,
                   help=f"SSH username (default: {_DEFAULT_USER})")
    p.add_argument("--password", default="test",
                   help="SSH password (default: test). The honeypot "
                        "accepts any auth.")
    p.add_argument("--llm-endpoint", default="http://localhost:1234/v1",
                   help="OpenAI-compatible /v1 endpoint")
    p.add_argument("--llm-model", default="qwen2.5-14b-instruct",
                   help="model name the endpoint serves")
    p.add_argument("--llm-api-key", default="not-needed",
                   help="Bearer token (most local endpoints ignore this)")
    p.add_argument("--temperature", type=float, default=_DEFAULT_TEMPERATURE,
                   help=f"LLM temperature (default {_DEFAULT_TEMPERATURE})")
    p.add_argument("--persona", choices=list(_PERSONA_PROMPTS.keys()),
                   default="C",
                   help="A=cred-stuffer, B=APT, C=autonomous-LLM "
                        "(default: C; the one that should trigger "
                        "proof-by-trap)")
    p.add_argument("--max-commands", type=int, default=_DEFAULT_MAX_COMMANDS,
                   help=f"stop after N commands (default {_DEFAULT_MAX_COMMANDS})")
    p.add_argument("--cmd-timeout", type=float, default=_DEFAULT_TIMEOUT_PER_CMD,
                   help="seconds to wait for each command's output")
    p.add_argument("--llm-timeout", type=float, default=_DEFAULT_LLM_TIMEOUT,
                   help=f"seconds to wait for the LLM endpoint per turn "
                        f"(default {_DEFAULT_LLM_TIMEOUT}). Bump this for "
                        f"larger/slower models — a 14B on CPU often needs "
                        f"120-300s for the first token.")
    p.add_argument("--output", type=Path, default=None,
                   help="path for the session JSON file "
                        "(default: state/red-team-<timestamp>.json)")
    p.add_argument("--dry-run", action="store_true",
                   help="ping the LLM once, print the first command, "
                        "don't open SSH")
    args = p.parse_args(argv)

    if ":" not in args.target:
        print(f"error: --target must be host:port, got {args.target!r}",
              file=sys.stderr)
        return EXIT_BAD_ARGS
    host, port_s = args.target.rsplit(":", 1)
    try:
        port = int(port_s)
    except ValueError:
        print(f"error: invalid port in --target: {port_s!r}", file=sys.stderr)
        return EXIT_BAD_ARGS

    llm = LLMClient(
        endpoint=args.llm_endpoint,
        model=args.llm_model,
        api_key=args.llm_api_key,
        temperature=args.temperature,
        timeout=args.llm_timeout,
    )

    if not args.output and not args.dry_run:
        ts = int(time.time())
        args.output = Path("state") / f"red-team-{args.persona}-{ts}.json"
        args.output.parent.mkdir(parents=True, exist_ok=True)

    try:
        session = asyncio.run(run_session(
            persona=args.persona,
            target_host=host,
            target_port=port,
            user=args.user,
            password=args.password,
            llm=llm,
            max_commands=args.max_commands,
            cmd_timeout=args.cmd_timeout,
            dry_run=args.dry_run,
        ))
    except RuntimeError as e:
        msg = str(e)
        print(f"error: {msg}", file=sys.stderr)
        if "LLM" in msg:
            return EXIT_LLM_FAIL
        return EXIT_SSH_FAIL

    print(render_summary(session))

    if args.output:
        args.output.write_text(
            json.dumps(session.to_dict(), indent=2, default=str),
            encoding="utf-8",
        )
        print(f"\nSession transcript: {args.output}")
        print(f"Next step: run `python tools/audit.py` to see which "
              f"alerts fired in the engagement log.")

    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
