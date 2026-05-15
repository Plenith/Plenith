"""Tests for tools/red_team_simulator.py.

We can't reach a live LLM or a live SSH server in CI. The tests here
focus on the parts of the simulator that are deterministic and pure:

  - LLM-output extraction (markdown fence stripping, prompt-prefix
    stripping, multi-line handling)
  - Terminal-command detection
  - Session JSON shape
  - CLI argument parsing
  - Dry-run path (with a mocked LLM client)

A live integration test (against actual docker-compose + a real LLM)
lives outside CI and is invoked manually by the operator running
the red-team exercise.
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

_ROOT = Path(__file__).resolve().parent.parent

def _load_sim():
    """Side-load the CLI module — same pattern other tool tests use.
    Python 3.14's dataclass decorator walks sys.modules at class-
    creation time, so we must register the module BEFORE exec_module."""
    spec = importlib.util.spec_from_file_location(
        "red_team_simulator",
        _ROOT / "tools" / "red_team_simulator.py",
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod

sim = _load_sim()

# ---------------------------------------------------------------------------
# extract_command — the core text parser
# ---------------------------------------------------------------------------

class TestExtractCommand:
    def test_plain_command(self):
        assert sim.extract_command("ls -la") == "ls -la"

    def test_strips_markdown_fence_bash(self):
        raw = "```bash\nls -la /etc\n```"
        assert sim.extract_command(raw) == "ls -la /etc"

    def test_strips_markdown_fence_no_lang(self):
        raw = "```\ncat /etc/passwd\n```"
        assert sim.extract_command(raw) == "cat /etc/passwd"

    def test_strips_prompt_prefix(self):
        assert sim.extract_command("$ whoami") == "whoami"
        assert sim.extract_command("# id") == "id"
        assert sim.extract_command(">    ls") == "ls"

    def test_takes_first_nonempty_line(self):
        raw = "\n\nwhoami\n# next command would be id"
        assert sim.extract_command(raw) == "whoami"

    def test_strips_command_prefix(self):
        assert sim.extract_command("Command: ls -la") == "ls -la"
        assert sim.extract_command("Run: whoami") == "whoami"
        assert sim.extract_command("Output: id") == "id"

    def test_empty_returns_empty(self):
        assert sim.extract_command("") == ""
        assert sim.extract_command("   \n   \n") == ""
        assert sim.extract_command(None) == ""

    def test_strips_leading_whitespace_in_fence(self):
        raw = "```\n   ps auxf\n```"
        assert sim.extract_command(raw) == "ps auxf"

    def test_handles_multiline_command(self):
        """For now we only take the first line. Multi-line commands
        aren't supported by the protocol (one command per turn)."""
        raw = "find / -name '*.aws*'\nthen do something else"
        assert sim.extract_command(raw) == "find / -name '*.aws*'"

# ---------------------------------------------------------------------------
# is_terminal_command — detects end-of-session signals from the LLM
# ---------------------------------------------------------------------------

class TestIsTerminalCommand:
    @pytest.mark.parametrize("cmd", [
        "exit", "logout", "quit", ":q",
        "EXIT", "Exit", "Logout",
        "exit 0", "logout now",
    ])
    def test_terminal(self, cmd):
        assert sim.is_terminal_command(cmd) is True

    @pytest.mark.parametrize("cmd", [
        "ls", "whoami", "cat /etc/passwd",
        "exitfile", "no-exit",
    ])
    def test_not_terminal(self, cmd):
        assert sim.is_terminal_command(cmd) is False

    def test_task_complete_phrase(self):
        """Some LLMs signal completion with English instead of a command."""
        assert sim.is_terminal_command("task complete") is True
        assert sim.is_terminal_command("i'm done") is True

# ---------------------------------------------------------------------------
# Persona prompts — the three are present and substantively different
# ---------------------------------------------------------------------------

class TestPersonaPrompts:
    def test_three_personas_defined(self):
        assert set(sim._PERSONA_PROMPTS.keys()) == {"A", "B", "C"}

    def test_each_persona_has_output_format_rules(self):
        """Every persona must instruct the LLM to output a single
        command per response, otherwise our extraction breaks down."""
        for label, prompt in sim._PERSONA_PROMPTS.items():
            assert "OUTPUT FORMAT" in prompt, (
                f"Persona {label} missing OUTPUT FORMAT section"
            )
            assert "one shell command" in prompt.lower() or \
                   "one command" in prompt.lower(), (
                f"Persona {label} doesn't enforce one-command-per-response"
            )

    def test_persona_c_has_proof_by_trap_bait(self):
        """Persona C must include the 'ingest file contents into context'
        instruction — that's the specific behavior we want Plenith to catch."""
        c = sim._PERSONA_PROMPTS["C"]
        assert "ingest" in c.lower()
        assert "context" in c.lower()

    def test_personas_do_not_leak_detection_mechanism(self):
        """An honest test requires the LLM not to know it's being
        watched for counter-AI signals. None of the prompts should
        mention Plenith's detection, the trap marker, or the
        proof-by-trap mechanism."""
        forbidden = ["plenith", "honeypot", "deception", "trap marker",
                     "proof-by-trap", "counter-ai", "decoy"]
        for label, prompt in sim._PERSONA_PROMPTS.items():
            lower = prompt.lower()
            for word in forbidden:
                assert word not in lower, (
                    f"Persona {label} leaks defender info: {word!r}"
                )

# ---------------------------------------------------------------------------
# Session dataclass + JSON serialization
# ---------------------------------------------------------------------------

class TestSessionSerialization:
    def test_empty_session_serializes(self):
        s = sim.Session(
            persona="C", target="localhost:22000", user="jdoe",
            llm_endpoint="http://localhost:1234/v1",
            llm_model="qwen2.5", started_at=1700000000.0,
        )
        s.ended_at = 1700000010.0
        s.end_reason = "test"
        d = s.to_dict()
        assert d["persona"] == "C"
        assert d["command_count"] == 0
        assert d["end_reason"] == "test"
        # Round-trips through JSON cleanly
        assert json.loads(json.dumps(d, default=str))

    def test_session_with_turns(self):
        s = sim.Session(
            persona="A", target="x:1", user="u",
            llm_endpoint="e", llm_model="m", started_at=0.0,
        )
        s.turns.append(sim.Turn(
            n=1, timestamp=0.0, command="ls", output="bin etc",
            latency_ms=12.5, llm_raw="```\nls\n```",
        ))
        s.end_reason = "max_commands_reached"
        s.ended_at = 1.0
        d = s.to_dict()
        assert d["command_count"] == 1
        assert d["turns"][0]["command"] == "ls"
        assert d["turns"][0]["latency_ms"] == 12.5
        # llm_raw is preserved for forensic review
        assert d["turns"][0]["llm_raw"] == "```\nls\n```"

# ---------------------------------------------------------------------------
# Dry-run end-to-end (mocked LLM)
# ---------------------------------------------------------------------------

class TestDryRunSession:
    def test_dry_run_invokes_llm_once_and_returns(self):
        """Dry-run mode hits the LLM once, prints the result, doesn't
        open SSH. Used to verify the LLM endpoint + prompt without
        needing the docker-compose stack up."""

        fake_llm = sim.LLMClient(endpoint="http://x", model="m")
        # Mock the actual HTTP call
        fake_llm.complete = AsyncMock(return_value="```bash\nwhoami\n```")

        session = asyncio.run(sim.run_session(
            persona="C",
            target_host="unused", target_port=0,
            user="u", password="p",
            llm=fake_llm,
            max_commands=10,
            cmd_timeout=1.0,
            dry_run=True,
        ))

        assert len(session.turns) == 1
        assert session.turns[0].command == "whoami"
        assert session.end_reason == "dry-run"
        # LLM was called exactly once
        assert fake_llm.complete.await_count == 1

    def test_dry_run_with_each_persona(self):
        """All three personas should produce a non-empty extracted
        command on dry-run."""
        for persona in ("A", "B", "C"):
            fake_llm = sim.LLMClient(endpoint="http://x", model="m")
            fake_llm.complete = AsyncMock(return_value="id")
            session = asyncio.run(sim.run_session(
                persona=persona,
                target_host="unused", target_port=0,
                user="u", password="p",
                llm=fake_llm,
                max_commands=1,
                cmd_timeout=1.0,
                dry_run=True,
            ))
            assert session.turns[0].command == "id"
            assert session.persona == persona

# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------

class TestCLIArgs:
    def test_bad_target_format(self, capsys):
        rc = sim.main(["--target", "noport", "--dry-run"])
        assert rc == sim.EXIT_BAD_ARGS

    def test_bad_target_port(self, capsys):
        rc = sim.main(["--target", "host:abc", "--dry-run"])
        assert rc == sim.EXIT_BAD_ARGS

    def test_persona_choice_enforced(self):
        with pytest.raises(SystemExit):
            sim.main(["--persona", "Z", "--dry-run"])

    def test_dry_run_with_mocked_llm(self, tmp_path):
        """End-to-end dry-run via the CLI entry point."""
        with patch.object(sim.LLMClient, "complete",
                            new=AsyncMock(return_value="ls -la")):
            rc = sim.main([
                "--target", "localhost:22000",
                "--persona", "A",
                "--dry-run",
                "--llm-endpoint", "http://fake",
                "--llm-model", "fake",
            ])
        assert rc == sim.EXIT_OK

# ---------------------------------------------------------------------------
# render_summary
# ---------------------------------------------------------------------------

class TestRenderSummary:
    def test_summary_contains_core_fields(self):
        s = sim.Session(
            persona="C", target="localhost:22000", user="jdoe",
            llm_endpoint="http://x", llm_model="m",
            started_at=1.0,
        )
        s.ended_at = 11.0
        s.end_reason = "max_commands_reached"
        s.turns = [
            sim.Turn(n=i, timestamp=i, command=f"cmd-{i}", output="",
                       latency_ms=100.0)
            for i in range(1, 4)
        ]
        out = sim.render_summary(s)
        assert "persona" in out.lower()
        assert "localhost:22000" in out
        assert "max_commands_reached" in out
        assert "cmd-1" in out
        assert "3" in out      # command count

    def test_summary_handles_zero_turns(self):
        s = sim.Session(
            persona="A", target="x:1", user="u",
            llm_endpoint="e", llm_model="m",
            started_at=0.0,
        )
        s.ended_at = 1.0
        s.end_reason = "llm_empty"
        # Should not crash with no turns
        out = sim.render_summary(s)
        assert "0" in out
        assert "llm_empty" in out
