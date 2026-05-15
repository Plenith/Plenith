# Concurrency & Capacity — What One Process Can Do, and Why 300 Needs the Fabric

This documents the measured concurrency ceiling of a single Plenith
orchestrator process, the bottlenecks behind it, what was fixed, and
why high concurrency (hundreds of simultaneous attackers) is a
horizontal-scale problem, not a single-process tuning problem.

The honest principle here: *don't claim a number you didn't measure,
and don't measure on a box whose state you didn't control.*

---

## Method

`tools/bench.py` spins N concurrent asyncssh clients through a fixed
20-command workload and reports per-source latency (p50/p95/p99),
throughput, and connect latency. The default workload is almost
entirely fast-path (cache / vfs / sim-bot) with **no LLM calls**, so it
isolates the orchestrator/event-loop/I-O path from the LLM backend.

Caveat learned the hard way: absolute numbers drift with box load
(LM Studio resident, other processes). Comparing a fresh run against a
baseline captured under different conditions measures *box drift*, not
code. Valid comparisons are **same-box-window A/B** only.

---

## The knee (single process, fast-path workload)

| Sessions | Throughput | cache p50 | connect mean / max | Errors |
|---:|---:|---:|---:|---:|
| 25 | ~142 cmd/s | ~45 ms | ~2 s / ~2.5 s | 0 |
| 50 | ~105 cmd/s | ~140 ms | ~6 s / ~7 s | 0 |
| 100 | ~85 cmd/s | ~610 ms | ~12 s / ~20 s | 0 |

The linear-scaling knee is **between 25 and 50**: throughput *declines*
as concurrency rises (anti-scaling), latency grows ~13× by 100. It
degrades gracefully — no errors even at 100 — but the binding failure
mode at higher concurrency is **connect latency** (the RSA-3072 SSH
handshake on the single event loop), which doubles per
concurrency-doubling. Extrapolated to 300, connect latency exceeds any
reasonable `login_timeout` and attackers fail to get a shell at all.

This is backend-independent: the workload had zero LLM calls. Real LLM
commands stack a second, harder ceiling on top (`llm_client.py` has no
concurrency control; a single local 7B model serves only a handful of
concurrent generations).

---

## Bottlenecks, in order

1. **LLM backend.** No client-side concurrency control; a single local
   model is the hard ceiling for any novel-command load. Cached / VFS /
   sim-bot commands don't hit it and scale fine. Mitigation is a real
   inference tier (clustered / hosted), then cost / rate-limit bound.
2. **Synchronous per-command session-log write.** `session_logger.py`
   is called after every command in the worker loop and re-hashes the
   audit chain + re-serializes the *entire growing session* to disk,
   synchronously, on the one event loop. `max_commands_per_session`
   caps per-session blowup but not global contention. **Deferred** —
   it's invasive (audit-chain ordering + the dashboard's per-command
   incremental-flush contract) and partly mooted by horizontal scale;
   it deserves a designed change, not a bench-chasing hack.
3. **Per-session kill poller — fixed.** The first kill-consumer design
   spawned one poller task per connection, each doing a synchronous
   `kill_requests.json` read every interval — O(sessions) blocking file
   reads/interval on the event loop, plus a per-command file read on
   the fast path. This was a regression introduced with the kill fix.

---

## Fix shipped: shared kill poller

Replaced the per-session pollers with **one process-wide poller** that
reads the kill queue once per interval into an in-memory view and
dispatches to a registry of live sessions keyed by engagement_id. The
per-command fast path is now a dict lookup with zero I/O. File reads
are O(1) per interval regardless of session count (proven
deterministically by
`test_kill_enforcement.py::test_poll_reads_queue_once_regardless_of_session_count`).

Connection-scoped enforcement and "kill all live connections for an
engagement" semantics are preserved (see test_kill_enforcement.py).

**Same-box-window A/B** (old per-session poller vs new shared poller,
benched minutes apart so box state is roughly constant):

| Metric | Old | New | Delta |
|---|---:|---:|---:|
| 50-session throughput | 79 cmd/s | 103 cmd/s | **+30%** |
| 50-session connect (mean) | 7.7 s | 6.0 s | **−22%** |
| 100-session throughput | 98 cmd/s | 106 cmd/s | +8% |
| 100-session connect (mean) | 11.3 s | 10.7 s | −5% |

Strongest at the concurrency where the regression bit (50); net
positive, never negative, at 100. Corroborated by the deterministic
O(1)-reads unit test. (Bench on a shared box still has noise; the
direction is consistent and the unit test is box-independent.)

---

## The 300-user answer

Not in one process. A single orchestrator is an MVP / single-decoy
unit. Hundreds of concurrent attackers is the **horizontal** story:
the `linux-fork/` multi-agent fabric — multiple agent containers behind
the identity proxy, each handling a slice of routed sessions — plus an
inference tier sized for concurrency. The shared-poller fix and a
future async/batched session-log write raise the single-process
ceiling and clear a regression, but they are deliberately *not* an
attempt to make one process do 300.

---

## Open follow-ups

- **Async/batched session-log write** (bottleneck #2) — designed
  change, not a prototype. Touches audit-chain ordering + dashboard
  incremental-flush contract.
- **LLM concurrency control + connection pooling** in `llm_client.py`
  (semaphore, shared `AsyncClient`) — bounds the #1 ceiling and stops
  unbounded fan-out to the model.
- **Horizontal-scale validation** — bench the multi-agent fabric, not
  just one process, for any real high-concurrency claim.

---

*Roadmap entry: `ROADMAP.md` → Considering → "Single-process concurrency
ceiling / horizontal scale".*
