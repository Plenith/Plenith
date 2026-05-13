# ADR 001: REINFORCE over PPO for the V2 policy

**Status:** Accepted
**Date:** 2026-04
**Deciders:** core team

## Context

§11 of the Engineering Blueprint calls for an RL-trained policy
replacing the heuristic action selector. The standard choices in 2026
are REINFORCE (vanilla policy gradient), PPO (clipped surrogate
objective), and A2C / actor-critic variants. PPO is widely considered
"the right choice" in modern RL pipelines because it's sample-efficient
and stable.

## Decision

We use **REINFORCE with a moving-average baseline**, in numpy only, no
deep-learning framework dependency.

## Considered alternatives

- **PPO** — clipped surrogate, value function, GAE returns. More
  sample-efficient by ~5-10×.
- **A2C** — actor-critic with shared body. Slightly faster than
  REINFORCE in practice.
- **DQN** — value-based, would also fit our discrete action space.

## Why REINFORCE wins for this workload

1. **State space is tiny.** 21 features. An MLP with 16-32 hidden
   units saturates within minutes of training. PPO's sample-efficiency
   advantage doesn't matter when we can run 10k episodes in 30 seconds.
2. **No torch/jax dependency.** REINFORCE in numpy is ~200 lines of
   code. PPO/A2C with a value function head needs a real autograd
   library, which means torch/jax + cuda + a 2 GB Docker layer. We
   want Plenith to install on a Raspberry Pi.
3. **Audit-friendly.** REINFORCE's update is literally `(one_hot(a) -
   probs) * advantage`. An auditor can hand-trace one step. PPO's clip
   ratio, advantage normalization, and value loss take a textbook chapter.
4. **Reproducibility.** Pure numpy + seeded `random.Random` =
   bit-exact training reruns. CUDA-backed PPO has nondeterministic
   floats in matmul kernels.

## Consequences

- **Slower convergence per episode.** Mitigated by point 1.
- **No value function** to bootstrap from. We use a moving-average
  baseline instead — simpler but higher-variance.
- **No off-policy reuse.** Each episode's trajectory is used once
  then thrown away. Acceptable given training cost.
- **If we ever scale the state space** beyond ~50 features, this
  becomes a real ceiling — would migrate to PPO + torch at that point.

## File pointers

- `plenith/training/policy_net.py` — REINFORCE update
- `plenith/training/train.py` — moving-average baseline
- `plenith/training/coevolve.py` — adversarial co-evolution loop
