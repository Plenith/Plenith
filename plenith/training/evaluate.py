"""Evaluation harness: trained policy vs heuristic baseline.

Two evaluation modes:

  1. **Stochastic episodes** — run N attacker episodes under each policy
     using the same RNG seed and compare aggregate metrics (mean return,
     mean dwell, IoCs caught, fingerprint signals).

  2. **Regression corpus replay** — load each captured engagement and
     ask the policy to act over its commands, then check that the
     "expected actions" from the fixture are still recovered. This is
     the gate that prevents an RL policy from regressing the alerts we
     used to catch heuristically.

Output is a structured dict that the CLI prints (and that tests assert on).
"""
import json
import random
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from collections.abc import Callable

import numpy as np

from ..policy import ACTION_SPACE
from .attacker import AttackerSim
from .env import DeceptionEnv
from .policy_net import PolicyNet
from .reward import RewardWeights

@dataclass
class EvalResult:
    name: str
    n_episodes: int
    mean_return: float
    median_return: float
    p25_return: float
    p75_return: float
    mean_steps: float
    total_actions: dict[str, int]
    fingerprint_episodes: int
    spurious_alert_episodes: int
    missed_alert_episodes: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

# ---------------------------------------------------------------------------
# Policy factories — wrap PolicyNet and HeuristicPolicy in a common interface
# the eval loop can call.
# ---------------------------------------------------------------------------

class _PolicyAdapter:
    """Common shim. Both trained and heuristic policies expose `act(obs, env)`
    so the eval loop doesn't care which it has."""

    name: str = "abstract"

    def act(self, obs: list[float], env: DeceptionEnv) -> int:
        raise NotImplementedError

class TrainedAdapter(_PolicyAdapter):
    def __init__(self, policy: PolicyNet, *, greedy: bool = True, seed: int = 0):
        self.policy = policy
        self.greedy = greedy
        self._rng = np.random.default_rng(seed)
        self.name = "trained_rl"

    def act(self, obs: list[float], env: DeceptionEnv) -> int:
        if self.greedy:
            return self.policy.greedy(np.asarray(obs))
        action, _ = self.policy.sample(np.asarray(obs), self._rng)
        return action

class HeuristicAdapter(_PolicyAdapter):
    """Translates the heuristic policy's action dict into an action id by
    looking up its `action` name in ACTION_SPACE."""

    name = "heuristic"

    def act(self, obs: list[float], env: DeceptionEnv) -> int:
        # We call the heuristic engine against the *current* session. Note
        # env._orchestrator.policy was replaced with NoOpPolicy in reset; we
        # have to build a real HeuristicPolicy here.
        from ..policy import HeuristicPolicy
        action_dict = HeuristicPolicy().decide(env._session)
        if not action_dict:
            return 0
        name = action_dict.get("action", "noop")
        try:
            return ACTION_SPACE.index(name)
        except ValueError:
            return 0

# ---------------------------------------------------------------------------
# Stochastic evaluation
# ---------------------------------------------------------------------------

def evaluate(
    adapter: _PolicyAdapter,
    *,
    env: DeceptionEnv,
    n_episodes: int = 50,
    seed: int = 1337,
    archetypes: list[str] | None = None,
) -> EvalResult:
    """Run `n_episodes` episodes with `adapter` choosing actions. Returns
    aggregated stats. Both policies should be evaluated with the same
    seed so the attacker sequences match.
    """
    archetypes = archetypes or [
        "balanced", "recon_heavy", "smash_and_grab", "persistence_first"
    ]
    rng = random.Random(seed)

    returns: list[float] = []
    steps: list[int] = []
    action_counts: dict[str, int] = {}
    fp_eps = 0
    spurious_eps = 0
    missed_eps = 0

    for ep in range(n_episodes):
        arch = archetypes[ep % len(archetypes)]
        ep_seed = rng.randint(0, 2**31 - 1)

        obs = env.reset(seed=ep_seed, archetype=arch)
        total_return = 0.0
        n_steps = 0
        had_fp = False
        had_spurious = False
        had_missed = False
        done = False

        while not done:
            a = adapter.act(obs, env)
            res = env.step(a)
            total_return += res.reward
            n_steps += 1
            name = res.info.get("action", "noop")
            action_counts[name] = action_counts.get(name, 0) + 1
            comps = res.info.get("reward_components", {}) or {}
            if "fingerprint" in comps:
                had_fp = True
            if "spurious_alert" in comps:
                had_spurious = True
            if "missed_alert" in comps:
                had_missed = True
            obs = res.obs
            done = res.done

        returns.append(total_return)
        steps.append(n_steps)
        if had_fp:
            fp_eps += 1
        if had_spurious:
            spurious_eps += 1
        if had_missed:
            missed_eps += 1

    returns_arr = np.array(returns)
    return EvalResult(
        name=adapter.name,
        n_episodes=n_episodes,
        mean_return=float(returns_arr.mean()) if len(returns_arr) else 0.0,
        median_return=float(np.median(returns_arr)) if len(returns_arr) else 0.0,
        p25_return=float(np.percentile(returns_arr, 25)) if len(returns_arr) else 0.0,
        p75_return=float(np.percentile(returns_arr, 75)) if len(returns_arr) else 0.0,
        mean_steps=float(np.mean(steps)) if steps else 0.0,
        total_actions=action_counts,
        fingerprint_episodes=fp_eps,
        spurious_alert_episodes=spurious_eps,
        missed_alert_episodes=missed_eps,
    )

def head_to_head(
    *,
    personas_dir: Path,
    trained_policy: PolicyNet,
    corpus_dir: Path | None = None,
    n_episodes: int = 50,
    seed: int = 1337,
    episode_cap: int = 30,
) -> dict[str, EvalResult]:
    """Run trained policy and heuristic baseline with matched seeds and
    return both results. The shared seed means both see the same attacker
    sequences for a fair comparison.
    """
    sim = AttackerSim(corpus_dir=corpus_dir)

    # Two separate env instances so each holds its own session state, but
    # we reset both with the same seed at each episode start.
    env_trained = DeceptionEnv(
        personas_dir=personas_dir, attacker_sim=sim,
        reward_weights=RewardWeights(), episode_cap=episode_cap,
    )
    env_heur = DeceptionEnv(
        personas_dir=personas_dir, attacker_sim=sim,
        reward_weights=RewardWeights(), episode_cap=episode_cap,
    )

    trained = evaluate(
        TrainedAdapter(trained_policy, greedy=True),
        env=env_trained, n_episodes=n_episodes, seed=seed,
    )
    heur = evaluate(
        HeuristicAdapter(),
        env=env_heur, n_episodes=n_episodes, seed=seed,
    )
    return {"trained_rl": trained, "heuristic": heur}

# ---------------------------------------------------------------------------
# Corpus regression eval
# ---------------------------------------------------------------------------

def evaluate_on_corpus(
    adapter: _PolicyAdapter,
    *,
    env: DeceptionEnv,
    corpus_dir: Path,
    seed: int = 0,
) -> dict[str, Any]:
    """Replay each captured engagement's command sequence under `adapter`.

    Returns per-episode action histograms, total return, and a coarse
    "recovered_alerts" set — the set of alerts the adapter fired at least
    once across all episodes. The CLI can compare this against a target
    set in expected.json.
    """
    # Sniff command sequences from logs/*.json
    sequences: list[tuple[str, list[str]]] = []
    for log_file in sorted(corpus_dir.rglob("logs/*.json")):
        try:
            data = json.loads(log_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        cmds = [c["cmd"] for c in data.get("commands", []) if c.get("cmd")]
        if cmds:
            sequences.append((log_file.stem, cmds))

    rng = random.Random(seed)
    out: dict[str, Any] = {"per_episode": [], "alerts_fired": set()}

    # We bypass the attacker_sim by directly setting env._cmd_queue.
    for stem, cmds in sequences:
        env.reset(seed=rng.randint(0, 2**31 - 1))
        env._cmd_queue = list(cmds)
        total = 0.0
        action_counts: dict[str, int] = {}
        obs = env._prev_obs_vec() if hasattr(env, "_prev_obs_vec") else None
        # We don't have the obs from a real reset for the replay sequence,
        # so just re-vectorize.
        from ..policy import vectorize
        obs = vectorize(env._session)

        done = False
        steps = 0
        while not done:
            a = adapter.act(obs, env)
            res = env.step(a)
            total += res.reward
            name = res.info.get("action", "noop")
            action_counts[name] = action_counts.get(name, 0) + 1
            if name != "noop":
                out["alerts_fired"].add(name)
            obs = res.obs
            done = res.done
            steps += 1

        out["per_episode"].append({
            "log_stem": stem,
            "return": total,
            "steps": steps,
            "actions": action_counts,
        })

    # Serialize set as list for json
    out["alerts_fired"] = sorted(out["alerts_fired"])
    return out
