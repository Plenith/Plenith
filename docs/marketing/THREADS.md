# Build-in-Public Thread Drafts

Pre-drafted technical threads for the build-in-public posting
phase described in the social-media conversation. Use these after
the trademark clearance lands (Part B of
`docs/PRE_LAUNCH_CHECKLIST.md`) but before the formal v1.0
announcement.

The strategy: each thread surfaces one genuinely interesting
technical decision or capability. Together they build a follower
base of operators + researchers who will be receptive to the
v1.0 launch announcement. Don't link to a usable repo until
trademark clearance + the 30-day self-deployment proof are both
in hand.

**Cadence**: ~one thread every 5–7 days. Three threads covers ~3
weeks of pre-launch presence.

**Voice**: technical, honest, no marketing-speak. Specific
numbers and code references. Acknowledge what doesn't work yet.

**Length**: each thread targets 6–10 posts. Long enough to be
substantive, short enough that readers finish.

---

## Thread 1 — Counter-AI proof-by-trap

**Topic**: detecting when an LLM-driven attacker is consuming our
deception outputs as their own context — and confirming it via
trap markers embedded in our responses.

**Why this thread first**: it's the most novel-feeling thing in
the platform. Security Twitter has noticed LLM-driven attacks
appearing in the wild; few defenders have a documented response.

```
🧵 1/9

Most honeypot research talks about catching humans. But in 2025-26
we started seeing automated attackers driven by an LLM agent loop.
They're different shape:

→ inter-command timing too uniform
→ lexical purity too high
→ probe for prompt-injection vulns

How do you confirm one?

---

2/9

Confidence-only detection isn't enough. You can score a session
"likely LLM-driven" with timing + lexical signals, but you can't
PROVE it without a controlled experiment.

We needed a trap. Something that:
1. is invisible to a human reader
2. would be ingested by an LLM as plausible context
3. shows up in a subsequent command if echoed

---

3/9

The mechanism is a planted marker in our LLM-rendered responses
to suspicious sessions. Embedded as a fake comment / config
artifact:

# auto-generated; do not edit. tag: ${MARKER}

The marker is unique per session, random, looks like a config
hash, hostile to copy-paste.

---

4/9

A human attacker reading the file ignores the marker.

An LLM agent inhaling the file as context will frequently
regurgitate the marker on a subsequent command. ("Check
${MARKER} status" or similar.)

When we see our planted marker come BACK in the attacker's input
stream — proof-by-trap.

---

5/9

We catch about 8% of probable-LLM-driven sessions this way. The
false-positive rate has been zero in our test corpus across 600+
synthetic sessions.

The remaining 92% are still scored by the timing + lexical heuristic
but without the proof bit set.

---

6/9

Implementation is in plenith/counter_ai.py (open source under
Apache 2.0). Key entry points:

- `score_session()` → confidence float
- `maybe_inject_trap()` → adds the marker conditionally
- `check_for_echoed_trap()` → confirms on subsequent commands

PR-welcome for additional trap strategies.

---

7/9

Why we ship this: the LLM-driven attacker is the harder defensive
problem of the next 5 years. Probabilistic detection has both
false positives and false negatives. Proof-by-trap gives a hard
"this WAS automated" signal.

Useful for after-action reports + threat intel sharing.

---

8/9

We're not the first to think about this. Prior art:
- HoneyTrace markers in canary tokens
- prompt-injection canaries in research code
- the academic literature on LLM tool-use detection

What's new here: production-grade integration with a deception
platform, plus the ADR-recorded confidence-vs-proof escalation.

---

9/9

If you build deception infrastructure or detect adversarial AI
behavior, code is at github.com/Plenith/Plenith (Apache 2.0,
open-source forever — see MISSION.md). Counter-AI module is in
plenith/counter_ai.py.

Engagement-quality data is the bottleneck; happy to compare
notes with other defenders.
```

**Source pointers** to cite if anyone asks:

- `plenith/counter_ai.py` — the module
- `plenith/heuristics.py` — the `alert_attacker_llm_detected` rule
- `docs/runbooks/PlenithCounterAIProvenSpike.md` — the operational runbook
- `docs/THREAT_MODEL.md` — where this fits in the broader threat model

---

## Thread 2 — Hash-chained audit logs

**Topic**: how the platform makes on-disk audit logs tamper-
evident, with concrete failure-mode coverage and verifier CLI.

**Why this thread**: appeals to forensics + compliance Twitter.
A working tamper-evident chain is the kind of thing GRC teams
want to read about.

```
🧵 1/9

Threat scenario: an attacker pivots from a deception decoy onto
the bastion host. They now have read-write on
state-docker/logs/*.json. They edit the logs to delete the
evidence of their successful pivot.

What stops them?

---

2/9

Without integrity: nothing. Plain JSON logs trust the writer.
An attacker who got read-write to disk can rewrite anything.

We added hash chaining. Every action entry carries:

- prev_hash (SHA-256 of previous entry)
- entry_hash (SHA-256 of own canonical content)

Plus a session-level chain_tip + chain_length.

---

3/9

Three tamper modes, all detectable:

1. Modify an entry in place
   → entry_hash no longer matches the recomputed hash

2. Delete an entry from the middle
   → next entry's prev_hash references a deleted hash

3. Truncate from the tail
   → session-level chain_tip points to a hash that no longer exists

All caught by a single verifier walk.

---

4/9

Code is in plenith/audit_chain.py. The math is pure functions:

  canonical_hash(payload) → str
  chain_entry(entry, prev) → entry'
  verify_chain(actions) → ChainResult

ChainResult tells you: ok, length, tip, where it broke if
broken, and the reason.

---

5/9

The verifier CLI is `python tools/verify_chain.py <logs_dir>`.

Output is grep-friendly:
- Exit 0: every chain clean
- Exit 1: at least one broken (forensic event)
- Exit 2: bad arguments

Drops into a daily cron. Surfaces as a Prometheus gauge via
textfile collector. Alert: PlenithAuditChainBroken (severity:
page).

---

6/9

Legacy logs (predating the feature) are accepted as ok=True,
legacy=True so rollout is incremental. After the 90-day window,
operators can flip --no-allow-legacy and the verifier refuses
anything un-chained.

This is the kind of detail that matters in real deployments
that aren't greenfield.

---

7/9

The math doesn't prevent tampering — it makes tampering
detectable. There's an important difference.

If the attacker rewrites the ENTIRE chain consistently, the
chain looks self-consistent on disk. The defense is a
periodic snapshot of chain_tip values to a write-once sink
(S3 WORM, append-only log). We document the pattern; we don't
prescribe a specific sink.

---

8/9

Tests cover the six failure modes (modify, mid-deletion, tail-
truncation, insertion, reorder, missing chain fields). 33 tests
in tests/test_audit_chain.py.

The verifier itself is exercised in test_audit_chain.py too —
clean / tampered / legacy / strict / JSON output. CLI exit codes
are part of the test surface.

---

9/9

Source: plenith/audit_chain.py + tools/verify_chain.py.
Apache 2.0. Forensics-grade audit-log tamper-evidence as ~250
lines of Python and a SHA-256 chain.

If you do incident-response work, this is the foundation. If
you're a compliance lead reading auditor reports, this is what
"non-repudiation" looks like in code form.
```

**Source pointers**:

- `plenith/audit_chain.py`
- `tools/verify_chain.py`
- `tests/test_audit_chain.py` (33 tests)
- `docs/adr/` for design history
- `docs/runbooks/PlenithAuditChainBroken.md` for the operational response

---

## Thread 3 — LLM realism constraints

**Topic**: how to make LLM-generated shell output convincing
enough to fool sophisticated attackers without paying cloud-LLM
costs.

**Why this thread**: technical-curious operators want to know
"does this actually work, or does the LLM hallucinate detectable
garbage?" Honest answer to a real concern.

```
🧵 1/9

The pitch for LLM-driven honeypots is obvious: every attacker
gets a unique, contextually-aware shell experience.

The implementation is harder than it sounds. Naive
LLM-generates-shell-output produces obvious tells:

→ inconsistent across turns
→ wrong shell semantics (errors that wouldn't happen, paths
  that don't exist)
→ measurable latency on every command

We hit each of these.

---

2/9

Cross-turn consistency: we don't ask the LLM to invent file
contents from scratch each turn. There's a real overlayfs
backing the decoy container, and the LLM gets the ACTUAL
content via a "ground truth" prompt section.

If the attacker types `cat /etc/passwd`, the LLM sees the
actual passwd we planted and returns its bytes — no
hallucination.

---

3/9

Shell semantics: we don't LLM-render obvious shell commands.
A 4-tier dispatch:

1. VFS-aware reads (cat, ls, head, tail, grep) → real overlayfs
2. Builtins (cd, echo with redirection, mv, cp, rm) → Python
3. Simulation bot (who, w, last, ps, netstat) → consistent
   bot-rendered
4. LLM → only for commands that benefit from creativity

About 75% of attacker commands never hit the LLM. Cache hits
add another 15%. Real LLM invocations: ~10% of the stream.

---

4/9

Latency: we pre-cache common command outputs. Cold path
(LLM invocation) is ~800ms p50, ~2.1s p95. Cache hits are
~4ms. Bot-rendered commands: ~18ms.

Benchmark baseline: state/bench/baseline.json. Regression
gate via tools/bench.py --compare.

A real attacker types fast and watches latency. <100ms p95 on
hot paths is the bar; we hit it on 90% of commands.

---

5/9

Persona consistency: each engagement has a fixed persona
(synthetic developer / DBA / sysadmin). The system prompt
includes their role, recent work, who they report to,
what's on their desk.

LLM responses get the persona block + recent command context
+ ground truth. ~3000-4000 tokens of input per call.

---

6/9

The hard part is making the planted artifacts look authentic.

A real ~/.aws/credentials has:
- correct file mode (0600)
- correct shape (AKIA... access keys, BIRD-style secrets)
- a profile section
- consistent region
- a comment that suggests history (date stamp, op name)

Generated files that miss ANY of these read as fake. We use
deterministic generators per (engagement_id, persona) seeded
with the deployment ID — see plenith/synthetic.py.

---

7/9

Counter-attack: synthetic-data fingerprinting. Attackers who've
seen our decoys before recognize them across deployments.

Mitigation: deployment-keyed content rotation
(plenith/rotation.py). Each install regenerates the
"corporate identity" — corp name, internal subnets, employee
naming, code style — from a stable seed.

Two Plenith installs at different orgs produce visibly
different decoy fabrics.

---

8/9

What we don't do well yet:

- Multi-shell history coherence (attacker can detect if `who`
  and `last` and bash_history don't agree)
- Network-aware command output (netstat that's internally
  consistent with the ps output)
- Time-evolution (clock drift, log timestamps that age)

These are open work items, on the roadmap.

---

9/9

LLM-driven deception is a real engineering problem, not just
"hook up a chatbot." The 14 heuristics + 4-tier dispatch +
synthetic content generators + counter-AI module took longer
than building the SSH proxy and dashboard combined.

Source: plenith/orchestrator.py + the rest of the engine
under Apache 2.0. Open issues welcome on failure modes you
notice in real engagements.
```

**Source pointers**:

- `plenith/orchestrator.py` — the 4-tier dispatch
- `plenith/llm_client.py` — LLM endpoint abstraction
- `plenith/synthetic.py` — content generators
- `plenith/rotation.py` — deployment-keyed rotation
- `plenith/response_cache.py` — cache mechanism
- `state/bench/baseline.json` — performance baseline

---

## After-thread checklist

For each thread before posting:

- [ ] Replace `github.com/Plenith/Plenith` with the actual repo URL
- [ ] Confirm source-file paths still match (after any code reorg)
- [ ] Verify benchmark numbers in thread 3 against current
      `state/bench/baseline.json`
- [ ] Run a final read-through for tone — should sound like the
      person who built it, not like marketing
- [ ] Decide platform: X (single thread), Mastodon (broadcasts
      well to security community), or LinkedIn (longer-form, less
      thread-friendly — adapt to a single-post format)
- [ ] If on X: number posts 1/9, 2/9 etc. — readers track progress
- [ ] If on Mastodon: tag with `#infosec` `#deception` `#honeypot`
      `#counterAI`

## What NOT to do in any of these threads

- Don't claim Plenith is "production-ready" if it doesn't have at
  least one real-world deployment with documented outcomes yet
- Don't compare directly to specific competitors by name
  (Acalvio / Illusive / etc.) — comparison stays at the category
  level
- Don't include screenshots of the dashboard until the UI is
  visually polished
- Don't quote testimonials from individuals without explicit
  permission, even paraphrased
- Don't link to anything behind a paywall
- Don't post any thread that hasn't had at least one other
  person review it for "would this embarrass me in 6 months?"

## Order to post

Recommend posting in this order:

1. **Thread 1 (Counter-AI)** — most novel, draws the most-
   engaged audience first
2. **Thread 2 (Audit chain)** — appeals to forensics + compliance,
   builds technical credibility
3. **Thread 3 (LLM realism)** — addresses the "but does it
   actually work?" skepticism after credibility is established

If anything goes wrong with thread 1 (low engagement, hostile
response, factual correction needed), pause + re-evaluate before
posting 2 and 3.

---

*Last updated: 2026-05-12.*
*Companion to [`PRE_LAUNCH_CHECKLIST.md`](../PRE_LAUNCH_CHECKLIST.md)
Part F (launch communications).*
