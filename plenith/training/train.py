"""REINFORCE-with-baseline training loop.

Drives the `DeceptionEnv`, collects trajectories, and updates the
`PolicyNet` via vanilla REINFORCE with a moving-average baseline. The
baseline is the running mean of episode returns — cheap and effective
for the small, low-variance environment we have.

Pseudocode:

    policy = PolicyNet(hp)
    baseline = 0.0
    for episode in 1..N:
        obs = env.reset()
        traj = []                      # (obs, action, reward)
        while not done:
            action, log_prob = policy.sample(obs, rng)
            obs', r, done, info = env.step(action)
            traj.append((obs, action, r))
            obs = obs'
        G = returns_to_go(rewards, gamma)
        adv = G - baseline                  # baseline-subtracted advantage
        policy.update([(obs, a, adv[t]) for t,(obs,a,_) in enumerate(traj)])
        baseline = ema(baseline, mean(G))   # update baseline

Outputs:
    - per-episode JSONL log under state/checkpoints/train_log.jsonl
    - periodic .npz checkpoints (last + best-by-mean-return)
"""
import json
import random
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import numpy as np

from .attacker import AttackerSim
from .env import DeceptionEnv
from .policy_net import PolicyHparams, PolicyNet, returns_to_go
from .reward import RewardWeights


@dataclass
class TrainConfig:
    n_episodes: int = 200
    gamma: float = 0.99
    baseline_ema: float = 0.9          # baseline = ema*baseline + (1-ema)*mean_return
    seed: int = 42
    archetype_mix: Optional[Dict[str, float]] = None  # None = uniform over all
    episode_cap: int = 30
    log_every: int = 10
    checkpoint_every: int = 50
    checkpoint_dir: Path = field(default_factory=lambda: Path("state/checkpoints"))
    log_path: Optional[Path] = None    # default: checkpoint_dir/train_log.jsonl


@dataclass
class EpisodeStat:
    episode: int
    archetype: str
    n_steps: int
    return_: float
    mean_reward: float
    top_action: str
    actions_fired: Dict[str, int]
    loss: float
    entropy: float
    baseline: float
    elapsed_ms: float


# ---------------------------------------------------------------------------
# Default archetype mix — covers all behaviour modes evenly.
# ---------------------------------------------------------------------------
_DEFAULT_ARCH_MIX = {
    "balanced": 0.30,
    "recon_heavy": 0.25,
    "smash_and_grab": 0.20,
    "persistence_first": 0.25,
}


def _pick_archetype(rng: random.Random, mix: Dict[str, float]) -> str:
    items = list(mix.items())
    names = [n for n, _ in items]
    weights = [w for _, w in items]
    return rng.choices(names, weights=weights, k=1)[0]


def _summarize_actions(traj_actions: List[str]) -> Tuple[str, Dict[str, int]]:
    counts: Dict[str, int] = {}
    for a in traj_actions:
        counts[a] = counts.get(a, 0) + 1
    if not counts:
        return "noop", {}
    top = max(counts.items(), key=lambda kv: (kv[1], kv[0] != "noop"))[0]
    return top, counts


def train(
    policy: PolicyNet,
    env: DeceptionEnv,
    cfg: Optional[TrainConfig] = None,
    *,
    on_episode: Optional[Callable[[EpisodeStat], None]] = None,
) -> List[EpisodeStat]:
    """Run REINFORCE on `env` using `policy`. Returns per-episode stats.

    `on_episode` is an optional callback fired after each episode — used by
    the CLI to print progress live without coupling training to a UI.
    """
    cfg = cfg or TrainConfig()
    rng = random.Random(cfg.seed)
    np_rng = np.random.default_rng(cfg.seed)
    arch_mix = cfg.archetype_mix or _DEFAULT_ARCH_MIX

    cfg.checkpoint_dir.mkdir(parents=True, exist_ok=True)
    log_path = cfg.log_path or (cfg.checkpoint_dir / "train_log.jsonl")
    log_fp = log_path.open("a", encoding="utf-8")

    baseline = 0.0
    best_return = float("-inf")
    stats: List[EpisodeStat] = []

    try:
        for ep in range(1, cfg.n_episodes + 1):
            arch = _pick_archetype(rng, arch_mix)
            seed = rng.randint(0, 2**31 - 1)
            t0 = time.perf_counter()

            obs = env.reset(seed=seed, archetype=arch)
            traj: List[Tuple[np.ndarray, int, float]] = []
            rewards: List[float] = []
            actions: List[str] = []
            done = False

            while not done:
                action, _logp = policy.sample(np.asarray(obs), np_rng)
                result = env.step(action)
                traj.append((np.asarray(obs), action, 0.0))  # advantage filled below
                rewards.append(result.reward)
                actions.append(result.info.get("action", "noop"))
                obs = result.obs
                done = result.done

            # Compute returns-to-go and baseline-adjusted advantages
            G = returns_to_go(rewards, gamma=cfg.gamma)
            advantages = G - baseline
            # Standardize advantages for stability (skip if std is tiny)
            adv_std = float(advantages.std())
            if adv_std > 1e-6:
                advantages = advantages / adv_std

            # Replace the placeholder rewards in traj with advantages
            traj_with_adv: List[Tuple[np.ndarray, int, float]] = [
                (obs_t, act_t, float(advantages[t]))
                for t, (obs_t, act_t, _) in enumerate(traj)
            ]

            telem = policy.update(traj_with_adv)
            episode_return = float(np.sum(rewards))
            mean_reward = float(np.mean(rewards)) if rewards else 0.0

            # EMA baseline update on raw episode mean-return
            ep_mean_G = float(G.mean()) if len(G) else 0.0
            baseline = cfg.baseline_ema * baseline + (1 - cfg.baseline_ema) * ep_mean_G

            top, action_counts = _summarize_actions(actions)
            stat = EpisodeStat(
                episode=ep,
                archetype=arch,
                n_steps=len(rewards),
                return_=episode_return,
                mean_reward=mean_reward,
                top_action=top,
                actions_fired=action_counts,
                loss=float(telem.get("loss", 0.0)),
                entropy=float(telem.get("entropy", 0.0)),
                baseline=baseline,
                elapsed_ms=(time.perf_counter() - t0) * 1000.0,
            )
            stats.append(stat)

            # Persist stat as JSONL
            json.dump(_stat_to_jsonable(stat), log_fp)
            log_fp.write("\n")
            log_fp.flush()

            if on_episode is not None:
                try:
                    on_episode(stat)
                except Exception:
                    # never let a UI callback crash training
                    pass

            # Best-so-far checkpoint
            if episode_return > best_return:
                best_return = episode_return
                policy.save(cfg.checkpoint_dir / "policy_best.npz")
            # Periodic + final checkpoint
            if ep % cfg.checkpoint_every == 0 or ep == cfg.n_episodes:
                policy.save(cfg.checkpoint_dir / "policy_last.npz")

    finally:
        log_fp.close()

    return stats


def _stat_to_jsonable(s: EpisodeStat) -> Dict[str, Any]:
    d = asdict(s)
    # ensure floats, not numpy types
    d["return_"] = float(s.return_)
    d["mean_reward"] = float(s.mean_reward)
    d["loss"] = float(s.loss)
    d["entropy"] = float(s.entropy)
    d["baseline"] = float(s.baseline)
    d["elapsed_ms"] = float(s.elapsed_ms)
    return d


# ---------------------------------------------------------------------------
# Convenience factory: build env + policy + train, all from config.
# ---------------------------------------------------------------------------

def build_default_env(
    personas_dir: Path,
    corpus_dir: Optional[Path] = None,
    *,
    archetype: str = "balanced",
    episode_cap: int = 30,
) -> DeceptionEnv:
    sim = AttackerSim(corpus_dir=corpus_dir)
    return DeceptionEnv(
        personas_dir=personas_dir,
        attacker_sim=sim,
        archetype=archetype,
        reward_weights=RewardWeights(),
        episode_cap=episode_cap,
    )


def train_from_scratch(
    *,
    personas_dir: Path,
    corpus_dir: Optional[Path] = None,
    cfg: Optional[TrainConfig] = None,
    hp: Optional[PolicyHparams] = None,
    on_episode: Optional[Callable[[EpisodeStat], None]] = None,
) -> Tuple[PolicyNet, List[EpisodeStat]]:
    cfg = cfg or TrainConfig()
    hp = hp or PolicyHparams(seed=cfg.seed)
    policy = PolicyNet(hp)
    env = build_default_env(
        personas_dir=personas_dir,
        corpus_dir=corpus_dir,
        episode_cap=cfg.episode_cap,
    )
    stats = train(policy, env, cfg, on_episode=on_episode)
    return policy, stats
