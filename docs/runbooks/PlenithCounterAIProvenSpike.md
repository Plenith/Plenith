# PlenithCounterAIProvenSpike

**Severity:** page · **Component:** detection

## What fired

`increase(plenith_counter_ai_proven_total[10m]) >= 1` immediately.

The counter-AI trap marker was echoed back by the attacker. Their
agent is consuming our outputs as input.

## Why we care

Proof-by-trap is the highest-confidence counter-AI signal we have.
Most LLM-driven attackers are detected probabilistically — timing
rhythm, lexical purity, prompt-injection probes — and we get
`plenith_counter_ai_detections_total` for those. **Proof** is
different: the attacker's agent has just regurgitated a string we
planted specifically to be invisible to a human reader.

This is rare enough that any single firing deserves attention. It
also represents the platform working as designed against the next
generation of automated attackers.

## First 5 minutes

1. **Capture the full command stream NOW.**
   The proof signal can fire and then the engagement ends. Snapshot
   while it's live:
   ```bash
   ssh <agent-host> "cp -r /opt/plenith/state-docker/persistence \\
     /opt/plenith/snapshots/counter-ai-$(date +%s)"
   ssh <agent-host> "cp -r /opt/plenith/state-docker/logs \\
     /opt/plenith/snapshots/counter-ai-$(date +%s)-logs"
   ```
2. **Identify the engagement.**
   ```bash
   curl -sS http://<api-host>:8000/api/engagements?proven=true | jq
   ```
   You want the engagement ID + source IP + claimed user.
3. **Read the trail.**
   The engagement's `observed.attacker_llm_signals` dict has the
   confidence breakdown (timing / lexical / injections). The
   `actions_taken` list shows when the trap was planted vs. when it
   was echoed.

## Likely causes (yes, this is mostly "the design works")

| Pattern | Cause |
| :--- | :--- |
| Trap planted, attacker reads the file, trap marker appears in a later command | Standard counter-AI trap working as intended |
| Trap firing on a benign session | Our heuristic threshold is too generous. Tune. (Should be vanishingly rare for the proof signal.) |
| Proof firing repeatedly across many sessions in a short window | Coordinated campaign by an LLM-orchestrated tool. Notable — likely a new red-team product. |

## Mitigation

1. **Do not** isolate or end the session. The deception is in its most
   valuable state — capture all the data you can.
2. Increase logging verbosity for this engagement: add the source IP
   to the verbose-logging allowlist so subsequent commands log full
   prompt + response context to a separate file.
3. After the engagement ends, run the after-action narrator:
   ```bash
   python tools/after_action.py --engagement <ID>
   ```

## Post-incident

- This is **intelligence-grade output**. Write it up:
  - Which LLM-driven tool / agent was likely in play (the lexical
    fingerprint usually narrows it down to a small set).
  - What trap technique caught them (prompt injection, marker echo,
    something else).
  - What command-flow they ran.
- Share with the community via the threat-intel connector (see
  `plenith/connectors/stix.py`) if your retention policy allows.
- If this is a tool you can identify, log it in `docs/CREDITS.md` as
  a confirmed counter-AI detection and update the counter-AI module's
  test fixtures.
- Consider whether your model of "what LLM-driven attackers look like"
  needs updating based on this sighting.
