"""LLM-narrated incident summaries.

This is the "analyst-assistive AI" tier per Torq's 2026 SOC research —
take the structured engagement state (command timeline, alerts, IoCs,
planted decoys, actions taken) and ask an LLM to produce a 3-paragraph
exec-readable summary plus a recommended response playbook.

Used by `tools/narrate.py` and `tools/audit.py --narrate <id>`. Single
entry-point function so tests can swap in a FakeLLM. The prompt is
designed to be model-agnostic — works against Qwen / Llama / DeepSeek
/ GLM (the four leading OSS LLMs for security work per the May 2026
benchmarks).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from collections.abc import Awaitable, Callable

SYSTEM_PROMPT = """You are a senior SOC analyst writing a post-engagement
incident summary for a CISO. You will receive structured data from a
deception platform that intercepted an attacker. Your output is THREE
parts, separated by single blank lines, NO markdown headers, NO bullets
in the first two parts:

  Part 1 — WHAT HAPPENED (1 short paragraph, 3-5 sentences):
  A factual narrative of the engagement. Identify the apparent intent
  (recon / credential theft / persistence / exfil) and the most
  significant attacker behavior.

  Part 2 — WHAT WE LEARNED (1 short paragraph, 3-5 sentences):
  Substantive intelligence: which decoys were swallowed, which IoCs
  are exportable, which TTPs were observed, and whether the attacker
  showed signs of being LLM-driven.

  Part 3 — RECOMMENDED RESPONSE (3-5 bullets, each a single line
  starting with "- "):
  Concrete next steps for the SOC. Be specific and actionable.

Tone: precise, executive, no hedging. No "I think", no "appears to be".
Use "the attacker", "the engagement", "our deception". Aim for 250-400
words total. Do not echo back the input data verbatim.
"""

@dataclass
class NarrativeInput:
    """Structured input to the narrator. Keep this dataclass stable
    across audit-tool versions; the LLM prompt depends on field names."""
    engagement_id: str
    claimed_user: str
    source_ip: str
    duration_seconds: float
    connection_count: int
    persona: str | None
    commands: list[str]                 # ordered command stream
    alerts: list[dict[str, str]]        # [{action, severity, rationale}, ...]
    iocs: list[str]                     # extracted IoCs
    decoys_swallowed: list[str]
    decoys_planted: list[str]
    counter_ai: dict[str, Any] | None = None  # {confidence, signals, proven}

    def to_prompt(self) -> str:
        """Render the engagement data as a compact user-prompt body.
        Keep under ~3000 tokens so we fit in a 4k-context model."""
        parts: list[str] = []
        parts.append(f"ENGAGEMENT_ID:       {self.engagement_id}")
        parts.append(f"CLAIMED_USER:        {self.claimed_user}")
        parts.append(f"SOURCE_IP:           {self.source_ip}")
        parts.append(f"DURATION_SECONDS:    {self.duration_seconds:.1f}")
        parts.append(f"CONNECTION_COUNT:    {self.connection_count}")
        if self.persona:
            parts.append(f"PERSONA:             {self.persona}")
        parts.append("")
        parts.append(f"COMMANDS_OBSERVED    ({len(self.commands)}):")
        # Cap at 60 commands to keep token count bounded
        for i, cmd in enumerate(self.commands[:60], 1):
            parts.append(f"  {i:>2}.  {cmd[:160]}")
        if len(self.commands) > 60:
            parts.append(f"  ...{len(self.commands) - 60} more elided")
        parts.append("")
        parts.append(f"ALERTS_FIRED         ({len(self.alerts)}):")
        for a in self.alerts:
            parts.append(
                f"  [{a.get('severity', '?'):>8s}]  {a.get('action', '?')}"
            )
            rat = (a.get("rationale") or "").strip().replace("\n", " ")
            if rat:
                parts.append(f"      → {rat[:200]}")
        parts.append("")
        if self.decoys_planted:
            parts.append(f"DECOYS_PLANTED       ({len(self.decoys_planted)}):")
            for d in self.decoys_planted:
                parts.append(f"  - {d}")
            parts.append("")
        if self.decoys_swallowed:
            parts.append(f"DECOYS_SWALLOWED     ({len(self.decoys_swallowed)}):")
            for d in self.decoys_swallowed:
                parts.append(f"  - {d}")
            parts.append("")
        if self.iocs:
            parts.append(f"IOCS_EXTRACTED       ({len(self.iocs)}):")
            for ioc in self.iocs[:20]:
                parts.append(f"  - {ioc}")
            parts.append("")
        if self.counter_ai:
            parts.append("COUNTER_AI_SIGNALS:")
            parts.append(f"  confidence:     {self.counter_ai.get('confidence', 0):.2f}")
            parts.append(f"  proven_by_trap: {self.counter_ai.get('proven', False)}")
            sigs = self.counter_ai.get("signals") or {}
            if sigs:
                parts.append(f"  signals:        {json.dumps(sigs, sort_keys=True)}")
            parts.append("")
        parts.append("Write the summary now. THREE PARTS as instructed.")
        return "\n".join(parts)

# Type alias for "anything with an async .complete(system, user) -> str"
LLMClient = Any

async def narrate(input_: NarrativeInput, llm: LLMClient) -> str:
    """Generate the exec narrative. The LLM is duck-typed — anything
    with `async def complete(system_prompt: str, user_prompt: str) -> str`
    works (LMStudioClient, OllamaClient, FakeLLM)."""
    return await llm.complete(SYSTEM_PROMPT, input_.to_prompt())

# ---------------------------------------------------------------------------
# Helpers for callers that have an audit-style engagement dict already.
# Lets `tools/narrate.py` go from `audit.load_engagements(...)` straight
# to a narrative without re-deriving field meanings.
# ---------------------------------------------------------------------------

def input_from_engagement(eng: dict[str, Any]) -> NarrativeInput:
    """Build a NarrativeInput from the engagement dict that audit.py
    produces. Handles missing fields gracefully — partial engagements
    still render a reasonable summary."""
    obs = eng.get("observed", {}) or {}

    # Commands are normally aggregated under `commands` (list of dicts)
    cmd_list: list[str] = []
    for c in eng.get("commands", []) or []:
        if isinstance(c, dict):
            cmd_list.append(c.get("cmd", ""))
        elif isinstance(c, str):
            cmd_list.append(c)

    alerts: list[dict[str, str]] = []
    for a in eng.get("actions_taken", []) or []:
        alerts.append({
            "action":    a.get("action", "?"),
            "severity":  a.get("severity", "info"),
            "rationale": a.get("rationale", ""),
        })

    iocs: list[str] = []
    # Common IoC sources
    iocs.extend(obs.get("dns_exfil_commands", []) or [])
    iocs.extend(obs.get("decoy_targets", []) or [])
    iocs.extend(obs.get("credential_files_read", []) or [])
    iocs.extend(obs.get("tampering_commands", []) or [])
    iocs = list(dict.fromkeys(iocs))  # de-dupe, preserve order

    counter_ai = None
    if obs.get("attacker_likely_llm") or obs.get("attacker_llm_confidence"):
        counter_ai = {
            "confidence":  obs.get("attacker_llm_confidence", 0.0),
            "proven":      bool(obs.get("attacker_llm_proven_via_trap")),
            "signals":     obs.get("attacker_llm_signals", {}),
        }

    duration = float(eng.get("dwell_seconds", 0)) or (
        float(eng.get("last_seen_at", 0)) - float(eng.get("first_seen_at", 0))
    )

    return NarrativeInput(
        engagement_id=str(eng.get("engagement_id", "?")),
        claimed_user=str(eng.get("claimed_user", "?")),
        source_ip=str(eng.get("source_ip", "?")),
        duration_seconds=max(0.0, duration),
        connection_count=int(eng.get("connection_count", 1)),
        persona=eng.get("persona"),
        commands=cmd_list,
        alerts=alerts,
        iocs=iocs,
        decoys_swallowed=list(obs.get("decoys_swallowed", []) or []),
        decoys_planted=list(obs.get("decoys_planted", []) or []),
        counter_ai=counter_ai,
    )
