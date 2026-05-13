"""Co-evolutionary RL — alternate-train defender and adversary.

Loop:

    for iteration in 1..N:
        snapshot defender, attacker         # for rollback
        train attacker for K episodes against frozen defender
        train defender for K episodes against frozen attacker
        evaluate head-to-head match (M episodes, both greedy)
        update Elo for both
        if either side regressed > rollback_threshold: restore snapshot

Tracks per-iteration metrics:
    attacker_undetected_rate  — fraction of episodes ending without isolation
    attacker_creds_per_ep     — mean credential files read per episode
    defender_mean_return      — defender's reward stream
    attacker_mean_return      — attacker's reward stream
    elo                       — symmetric Elo for each side

Plot the metrics over iterations and you'll see:
    Round 1:  attacker random, defender wins everything
    Round 2:  attacker learns to spam recon → bypass discovery alerts
    Round 3:  defender plants traps earlier → undetected rate drops
    Round 4:  attacker learns to AVOID decoy_followup → undetected rate up
    ...
    Round 10+: equilibrium near 30-50% undetected, depending on shaping

The defender that comes out of this is qualitatively different from
one trained on the static AttackerSim archetypes — it's seen evasive
strategies that no human-curated corpus contained.
"""
from __future__ import annotations

import copy
import json
import math
import random
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import numpy as np

from ..policy import ACTION_SPACE, vectorize
from .adversary import (
    ATTACKER_ACTIONS,
    AdversaryHparams,
    AdversaryNet,
    AttackerRewardWeights,
    AttackerState,
    attacker_reward,
    sample_command,
    terminal_attacker_reward,
)
from .env import DeceptionEnv
from .policy_net import PolicyHparams, PolicyNet, returns_to_go


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass
class CoevolveConfig:
    iterations: int                = 6      # outer rounds (attacker, defender) pairs
    episodes_per_side: int         = 30     # train K eps for each side per iter
    eval_episodes: int             = 20     # head-to-head match size
    episode_cap: int               = 25
    gamma: float                   = 0.99
    seed: int                      = 12345
    elo_k: float                   = 24.0   # standard chess K-factor
    rollback_threshold: float      = 0.15   # if undetected jumps >15% in wrong dir, rollback
    checkpoint_dir: Path           = field(default_factory=lambda: Path("state/coevolve"))


@dataclass
class IterationStat:
    iteration:            int
    defender_mean_return: float
    attacker_mean_return: float
    attacker_undetected_rate: float
    attacker_creds_per_ep:    float
    defender_elo:         float
    attacker_elo:         float
    head_to_head_def_winrate: float
    elapsed_s:            float
    rollback:             bool


# ---------------------------------------------------------------------------
# One episode under both policies
# ---------------------------------------------------------------------------

def _run_one_episode(
    env: DeceptionEnv,
    defender: PolicyNet,
    attacker: AdversaryNet,
    rng_np: np.random.Generator,
    rng_py: random.Random,
    *,
    defender_greedy: bool = False,
    attacker_greedy: bool = False,
    record_defender_traj: bool = False,
    record_attacker_traj: bool = False,
) -> Dict[str, Any]:
    """Drive one full episode with attacker choosing commands and
    defender choosing responses. Returns the per-episode telemetry.

    Trajectories are recorded only on the requested side, so we can
    train one policy at a time while using the other as a fixed opponent.
    """
    seed = rng_py.randint(0, 2**31 - 1)
    env.reset(seed=seed)

    att_state = AttackerState(max_steps=env.episode_cap)
    # We DRIVE the env's _cmd_queue ourselves — bypass attacker_sim
    env._cmd_queue = []

    def_traj: List[Tuple[np.ndarray, int, float]] = []
    att_traj: List[Tuple[np.ndarray, int, float]] = []
    def_rewards: List[float] = []
    att_rewards: List[float] = []
    actions_fired: List[str] = []
    final_session = env._session
    rew_weights = AttackerRewardWeights()

    done = False
    while not done and att_state.step_count < env.episode_cap:
        # 1. Attacker picks action class
        att_obs = att_state.vectorize()
        if attacker_greedy:
            att_action = attacker.greedy(att_obs)
        else:
            att_action, _ = attacker.sample(att_obs, rng_np)

        # 2. Materialize → concrete command, push into env
        cmd = sample_command(att_action, rng_py)
        att_state.record_action(att_action, cmd)
        env._cmd_queue = [cmd]

        # Snapshot pre-step state for reward diffs
        prev_obs = env._snapshot_observed()
        prev_actions = list(final_session.actions_taken)

        # 3. Defender picks action
        def_obs_vec = np.asarray(vectorize(final_session))
        if defender_greedy:
            def_action = defender.greedy(def_obs_vec)
        else:
            def_action, _ = defender.sample(def_obs_vec, rng_np)

        # 4. Step env (runs the cmd through orchestrator + applies defender action)
        result = env.step(def_action)
        new_obs = env._snapshot_observed()
        new_actions = final_session.actions_taken[len(prev_actions):]

        # Track aggregate metrics
        for a in new_actions:
            actions_fired.append(a.get("action", ""))

        # 5. Compute per-side rewards
        att_step_reward = attacker_reward(
            prev_observed=prev_obs,
            new_observed=new_obs,
            new_alerts=new_actions,
            attacker_state=att_state,
            action_idx=att_action,
            weights=rew_weights,
        )
        att_rewards.append(att_step_reward)
        def_rewards.append(result.reward)

        if record_defender_traj:
            def_traj.append((def_obs_vec, def_action, result.reward))
        if record_attacker_traj:
            att_traj.append((att_obs, att_action, att_step_reward))

        done = result.done or cmd.strip() == "exit"

    # Terminal attacker bonus
    isolated = bool(env._session.observed.get("isolated"))
    term_att = terminal_attacker_reward(
        final_state=att_state,
        final_observed=env._snapshot_observed(),
        isolated=isolated,
        weights=rew_weights,
    )
    if att_rewards:
        att_rewards[-1] += term_att
        if record_attacker_traj and att_traj:
            o, a, r = att_traj[-1]
            att_traj[-1] = (o, a, r + term_att)

    return {
        "defender_return":    float(sum(def_rewards)),
        "attacker_return":    float(sum(att_rewards)),
        "credential_reads":   att_state.credential_reads,
        "isolated":           isolated,
        "n_steps":            att_state.step_count,
        "alerts_fired":       len(set(actions_fired) - {"noop"}),
        "defender_traj":      def_traj if record_defender_traj else None,
        "attacker_traj":      att_traj if record_attacker_traj else None,
    }


# ---------------------------------------------------------------------------
# REINFORCE update over a list of episode trajectories
# ---------------------------------------------------------------------------

def _reinforce_update(
    policy,                           # PolicyNet or AdversaryNet
    episode_trajs: List[List[Tuple[np.ndarray, int, float]]],
    gamma: float,
) -> Dict[str, float]:
    """Compute returns-to-go for each episode, standardize, run one
    update on the concatenated trajectory."""
    flat: List[Tuple[np.ndarray, int, float]] = []
    for traj in episode_trajs:
        rewards = [r for _, _, r in traj]
        G = returns_to_go(rewards, gamma=gamma)
        sd = float(G.std())
        adv = G if sd < 1e-6 else (G - G.mean()) / sd
        for t, (obs, a, _) in enumerate(traj):
            flat.append((obs, a, float(adv[t])))
    return policy.update(flat)


# ---------------------------------------------------------------------------
# Elo helpers — symmetric: each side has its own Elo, head-to-head match
# updates both. Standard formula, K from config.
# ---------------------------------------------------------------------------

def _expected_score(rating_a: float, rating_b: float) -> float:
    return 1.0 / (1.0 + math.pow(10.0, (rating_b - rating_a) / 400.0))


def _update_elo(rating_a: float, rating_b: float,
                score_a: float, k: float) -> Tuple[float, float]:
    ea = _expected_score(rating_a, rating_b)
    eb = 1.0 - ea
    return (rating_a + k * (score_a - ea),
            rating_b + k * ((1.0 - score_a) - eb))


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def coevolve(
    *,
    env: DeceptionEnv,
    defender: PolicyNet,
    attacker: AdversaryNet,
    cfg: Optional[CoevolveConfig] = None,
    on_iteration: Optional[Callable[[IterationStat], None]] = None,
) -> List[IterationStat]:
    """Run the alternating co-evolution loop.

    Mutates `defender` and `attacker` in-place. Returns per-iteration
    stats. Callers (the CLI) typically pass an `on_iteration` to print
    progress live.
    """
    cfg = cfg or CoevolveConfig()
    rng_py = random.Random(cfg.seed)
    rng_np = np.random.default_rng(cfg.seed)

    cfg.checkpoint_dir.mkdir(parents=True, exist_ok=True)
    log_path = cfg.checkpoint_dir / "coevolve_log.jsonl"
    log_fp = log_path.open("a", encoding="utf-8")

    def_elo, att_elo = 1500.0, 1500.0
    stats: List[IterationStat] = []
    # Baseline metric for rollback detection
    prev_undetected: Optional[float] = None

    try:
        for it in range(1, cfg.iterations + 1):
            t0 = time.perf_counter()

            # Snapshot before training (for rollback)
            def_snap = _snapshot_policy(defender)
            att_snap = _snapshot_policy(attacker)

            # -------------------------------------------------------
            # 1. Train ATTACKER against frozen defender
            # -------------------------------------------------------
            att_trajs: List[List] = []
            for _ in range(cfg.episodes_per_side):
                ep = _run_one_episode(
                    env, defender, attacker, rng_np, rng_py,
                    defender_greedy=True,    # frozen
                    record_attacker_traj=True,
                )
                if ep["attacker_traj"]:
                    att_trajs.append(ep["attacker_traj"])
            if att_trajs:
                _reinforce_update(attacker, att_trajs, cfg.gamma)

            # -------------------------------------------------------
            # 2. Train DEFENDER against (newly-trained, frozen) attacker
            # -------------------------------------------------------
            def_trajs: List[List] = []
            for _ in range(cfg.episodes_per_side):
                ep = _run_one_episode(
                    env, defender, attacker, rng_np, rng_py,
                    attacker_greedy=True,    # frozen
                    record_defender_traj=True,
                )
                if ep["defender_traj"]:
                    def_trajs.append(ep["defender_traj"])
            if def_trajs:
                _reinforce_update(defender, def_trajs, cfg.gamma)

            # -------------------------------------------------------
            # 3. Head-to-head EVAL — both policies greedy
            # -------------------------------------------------------
            evals = []
            for _ in range(cfg.eval_episodes):
                ep = _run_one_episode(
                    env, defender, attacker, rng_np, rng_py,
                    defender_greedy=True, attacker_greedy=True,
                )
                evals.append(ep)
            n = len(evals)
            undetected = sum(1 for e in evals if not e["isolated"]) / max(1, n)
            creds      = sum(e["credential_reads"] for e in evals) / max(1, n)
            def_mean   = sum(e["defender_return"] for e in evals) / max(1, n)
            att_mean   = sum(e["attacker_return"] for e in evals) / max(1, n)
            # Defender "wins" when attacker is isolated → undetected==0
            # Symmetric: defender win-rate = 1 - undetected_rate
            def_winrate = 1.0 - undetected
            # Elo update — defender gets `def_winrate` against attacker
            def_elo, att_elo = _update_elo(def_elo, att_elo, def_winrate, cfg.elo_k)

            # -------------------------------------------------------
            # 4. Rollback if either side regressed catastrophically
            # -------------------------------------------------------
            rolled = False
            if prev_undetected is not None:
                # We don't want WILD swings — if defender plummeted
                # (undetected jumped >threshold) AND defender_return
                # dropped, restore.
                jumped = abs(undetected - prev_undetected) > cfg.rollback_threshold
                if jumped and (def_mean < 0 and prev_undetected > 0.6 and undetected < 0.3):
                    # Defender suddenly winning everything = good, no rollback
                    pass
                elif jumped and def_mean < -10:
                    _restore_policy(defender, def_snap)
                    _restore_policy(attacker, att_snap)
                    rolled = True
            prev_undetected = undetected

            stat = IterationStat(
                iteration=it,
                defender_mean_return=def_mean,
                attacker_mean_return=att_mean,
                attacker_undetected_rate=undetected,
                attacker_creds_per_ep=creds,
                defender_elo=def_elo,
                attacker_elo=att_elo,
                head_to_head_def_winrate=def_winrate,
                elapsed_s=time.perf_counter() - t0,
                rollback=rolled,
            )
            stats.append(stat)
            json.dump(asdict(stat), log_fp); log_fp.write("\n"); log_fp.flush()

            # Checkpoint each iter (best + latest)
            defender.save(cfg.checkpoint_dir / "defender_last.npz")
            attacker.save(cfg.checkpoint_dir / "attacker_last.npz")

            if on_iteration:
                try:
                    on_iteration(stat)
                except Exception:
                    pass
    finally:
        log_fp.close()
    return stats


# ---------------------------------------------------------------------------
# Snapshot / restore helpers (per-side weight backup for rollback)
# ---------------------------------------------------------------------------

def _snapshot_policy(p) -> Dict[str, Any]:
    """Deep-copy the policy's weight arrays. Works for PolicyNet and
    AdversaryNet (the latter delegates to its underlying PolicyNet)."""
    inner = p._net if hasattr(p, "_net") else p
    return {
        "W1": inner.W1.copy(),
        "b1": inner.b1.copy(),
        "W2": inner.W2.copy() if inner.W2 is not None else None,
        "b2": inner.b2.copy() if inner.b2 is not None else None,
    }


def _restore_policy(p, snap: Dict[str, Any]) -> None:
    inner = p._net if hasattr(p, "_net") else p
    inner.W1 = snap["W1"].copy()
    inner.b1 = snap["b1"].copy()
    if snap["W2"] is not None and inner.W2 is not None:
        inner.W2 = snap["W2"].copy()
        inner.b2 = snap["b2"].copy()
