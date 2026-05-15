"""CLI driver: train an RL deception policy.

Usage:
    python tools/train_rl.py                                       # 200 eps, defaults
    python tools/train_rl.py --episodes 500 --hidden 16 --lr 0.02  # fancier
    python tools/train_rl.py --eval-only --checkpoint state/checkpoints/policy_best.npz

Outputs:
    state/checkpoints/policy_best.npz       — best-return checkpoint
    state/checkpoints/policy_last.npz       — most recent checkpoint
    state/checkpoints/train_log.jsonl       — per-episode telemetry
    state/checkpoints/eval_summary.json     — final eval against heuristic

The training runs entirely in-process — no LM Studio, no SSH server.
Episodes synthesize attacker commands via plenith.training.attacker.
"""
import argparse
import io
import json
import sys
import time
from pathlib import Path

# Make `plenith` importable when running from the repo root.
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, io.UnsupportedOperation, ValueError):
    pass

from plenith.training.evaluate import head_to_head  # noqa: E402
from plenith.training.policy_net import PolicyHparams, PolicyNet  # noqa: E402
from plenith.training.train import (  # noqa: E402
    TrainConfig,
    build_default_env,
    train,
)

_PERSONAS_DIR = _ROOT / "personas"
_CORPUS_DIR = _ROOT / "tests" / "fixtures" / "regression-corpus"
_DEFAULT_CKPT_DIR = _ROOT / "state" / "checkpoints"

def _on_episode(stat):
    """Print a one-line summary per episode."""
    top = stat.top_action
    print(
        f"[ep {stat.episode:>4d}] arch={stat.archetype:<18s} "
        f"steps={stat.n_steps:>3d} ret={stat.return_:+8.2f} "
        f"loss={stat.loss:+6.3f} ent={stat.entropy:5.3f} "
        f"top={top:<24s} "
        f"baseline={stat.baseline:+6.2f} "
        f"ms={stat.elapsed_ms:6.1f}"
    )

def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--episodes", type=int, default=200,
                   help="number of training episodes (default 200)")
    p.add_argument("--hidden", type=int, default=0,
                   help="hidden layer dim (0 = linear policy)")
    p.add_argument("--lr", type=float, default=0.02,
                   help="REINFORCE learning rate")
    p.add_argument("--entropy", type=float, default=0.01,
                   help="entropy regularization coefficient")
    p.add_argument("--gamma", type=float, default=0.99,
                   help="discount factor")
    p.add_argument("--episode-cap", type=int, default=30,
                   help="max steps per episode")
    p.add_argument("--seed", type=int, default=42,
                   help="RNG seed")
    p.add_argument("--checkpoint-dir", type=Path, default=_DEFAULT_CKPT_DIR,
                   help="where to write checkpoints + train log")
    p.add_argument("--no-corpus", action="store_true",
                   help="don't load the regression corpus for replay episodes")
    p.add_argument("--eval-episodes", type=int, default=20,
                   help="number of head-to-head eval episodes after training")
    p.add_argument("--eval-only", action="store_true",
                   help="skip training; only evaluate an existing checkpoint")
    p.add_argument("--checkpoint", type=Path, default=None,
                   help="(eval-only) path to .npz to load")
    args = p.parse_args(argv)

    corpus_dir = None if args.no_corpus else (_CORPUS_DIR if _CORPUS_DIR.exists() else None)

    if args.eval_only:
        ck = args.checkpoint or (args.checkpoint_dir / "policy_best.npz")
        if not ck.exists():
            print(f"[error] no checkpoint at {ck}", file=sys.stderr)
            return 2
        print(f"[eval] loading {ck}")
        policy = PolicyNet.load(ck)
    else:
        hp = PolicyHparams(
            hidden_dim=args.hidden,
            learning_rate=args.lr,
            entropy_beta=args.entropy,
            seed=args.seed,
        )
        cfg = TrainConfig(
            n_episodes=args.episodes,
            gamma=args.gamma,
            seed=args.seed,
            episode_cap=args.episode_cap,
            checkpoint_dir=args.checkpoint_dir,
        )
        env = build_default_env(
            personas_dir=_PERSONAS_DIR,
            corpus_dir=corpus_dir,
            episode_cap=args.episode_cap,
        )
        policy = PolicyNet(hp)
        print(f"[train] episodes={args.episodes} hidden={args.hidden} "
              f"lr={args.lr} entropy={args.entropy} gamma={args.gamma}")
        print(f"[train] checkpoints → {args.checkpoint_dir}")
        t0 = time.perf_counter()
        stats = train(policy, env, cfg, on_episode=_on_episode)
        elapsed = time.perf_counter() - t0
        returns = [s.return_ for s in stats]
        print(f"[train] done in {elapsed:.1f}s, "
              f"mean return last-10 = {sum(returns[-10:]) / max(1, len(returns[-10:])):.2f}")

    # --- Head-to-head evaluation against the heuristic ----------------
    print(f"[eval] head-to-head over {args.eval_episodes} episodes ...")
    res = head_to_head(
        personas_dir=_PERSONAS_DIR,
        trained_policy=policy,
        corpus_dir=corpus_dir,
        n_episodes=args.eval_episodes,
        seed=args.seed + 1,  # different seed than training
        episode_cap=args.episode_cap,
    )
    summary = {k: v.to_dict() for k, v in res.items()}
    out = args.checkpoint_dir / "eval_summary.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    # Pretty-print a comparison table
    print()
    print(f"{'metric':<28s} {'heuristic':>12s} {'trained_rl':>12s}   delta")
    print("-" * 70)
    h = res["heuristic"]
    t = res["trained_rl"]
    def _row(label, hv, tv):
        delta = tv - hv
        print(f"{label:<28s} {hv:>12.2f} {tv:>12.2f}   {delta:+8.2f}")
    _row("mean_return",  h.mean_return, t.mean_return)
    _row("median_return", h.median_return, t.median_return)
    _row("mean_steps", h.mean_steps, t.mean_steps)
    _row("fingerprint_episodes",
         h.fingerprint_episodes, t.fingerprint_episodes)
    _row("spurious_alert_episodes",
         h.spurious_alert_episodes, t.spurious_alert_episodes)
    _row("missed_alert_episodes",
         h.missed_alert_episodes, t.missed_alert_episodes)
    print(f"\n[eval] wrote summary → {out}")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
