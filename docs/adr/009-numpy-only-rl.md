# ADR 009: numpy-only RL training (no torch / jax)

**Status:** Accepted
**Date:** 2026-04

## Context

REINFORCE for our small state-action space could be implemented in
torch, jax, or pure numpy. The trade-off:

- **torch:** standard ML library. ~800MB install (with CUDA), 50+
  transitive deps. Autograd, GPU support, the works.
- **jax:** functional autograd, jit-compile-to-XLA. Similar size to
  torch.
- **numpy:** scientific Python's basic array math. ~50MB, no autograd,
  no GPU support.

## Decision

**numpy only.** Hand-rolled REINFORCE update. No autograd.

## Why

1. **Install size matters.** The agent container is currently ~120MB.
   Adding torch would 7x that. The Helm chart would download multiple
   GB per agent on first pull. Plenith is meant to deploy on
   Raspberry Pi-class hardware (sensor networks, OT decoy hosts).
2. **State-action space is tiny.** 21 features × 16 actions = a 336-
   parameter linear policy. Optional 1-hidden MLP at 16-32 units.
   ~600-800 trainable parameters total. CPU numpy trains 100k
   episodes in under a minute.
3. **REINFORCE's gradient is one line of math.** No autograd needed:
   `grad_logits = -(one_hot(a) - probs) * advantage`. Plus entropy
   regularization, also one line.
4. **Reproducibility.** Pure numpy + `random.Random(seed)` = bit-exact
   training reproduction across machines. CUDA-backed torch has
   nondeterministic floats.
5. **Auditability.** `plenith/training/policy_net.py` is 200 lines.
   An auditor can read it end-to-end. PyTorch's autograd graph is
   opaque.

## Considered alternatives

- **`torch` with CPU-only build** — still ~100MB, ~25 transitive deps.
  Better than CUDA torch but still a big jump.
- **`jax` with CPU-only** — same as torch CPU.
- **`tinygrad`** — minimal autograd library. ~5MB. Tempting but adds
  another framework to learn.
- **stay on heuristic, skip RL** — defeats the V2/V3 part of the
  blueprint.

## Consequences

- **No GPU acceleration for training.** Fine; on CPU we train in
  seconds. Will become a ceiling if we scale to 100+ features.
- **No deep architectures.** Stick to linear or 1-hidden MLP. Mitigated
  by point 2 (the problem doesn't need depth).
- **If we ever need pixel-state input (e.g., screen-capture deception)
  the calculus inverts.** That's a v3 conversation; not today.

## File pointers

- `plenith/training/policy_net.py` — REINFORCE update
- `plenith/training/adversary.py` — co-evolution adversary net
- `requirements.txt` — `numpy>=2.0,<3.0`
