"""CLI: co-evolutionary RL training — defender vs adversary.

Loop alternates between training the attacker against a frozen defender
and training the defender against the (newly-trained) frozen attacker.
After each iteration, runs a greedy head-to-head match and updates Elo.

Usage:
    python tools/coevolve_rl.py                          # 6 iter × 30 eps default
    python tools/coevolve_rl.py --iterations 12 --episodes-per-side 50
    python tools/coevolve_rl.py --warm-start state/checkpoints/policy_best.npz
"""
import argparse
import io
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, io.UnsupportedOperation, ValueError):
    pass

from plenith.training.adversary import AdversaryHparams, AdversaryNet  # noqa: E402
from plenith.training.attacker import AttackerSim  # noqa: E402
from plenith.training.coevolve import CoevolveConfig, coevolve  # noqa: E402
from plenith.training.env import DeceptionEnv  # noqa: E402
from plenith.training.policy_net import PolicyHparams, PolicyNet  # noqa: E402

_PERSONAS_DIR = _ROOT / "personas"

def color(c: str, s: str) -> str:
    return f"\033[{c}m{s}\033[0m"

def _on_iter(stat) -> None:
    """One-line per-iteration printer with side-by-side win-rate / Elo."""
    rb = color("33", " ROLLBACK") if stat.rollback else ""
    arrow = "↑" if stat.attacker_undetected_rate > 0.5 else "↓"
    print(
        f"[iter {stat.iteration:>3d}] "
        f"def_ret={color('36', f'{stat.defender_mean_return:+7.2f}')}  "
        f"att_ret={color('33', f'{stat.attacker_mean_return:+7.2f}')}  "
        f"undetected={arrow}{stat.attacker_undetected_rate:5.2%}  "
        f"creds/ep={stat.attacker_creds_per_ep:4.2f}  "
        f"def_winrate={stat.head_to_head_def_winrate:5.2%}  "
        f"elo def={stat.defender_elo:6.1f} att={stat.attacker_elo:6.1f}  "
        f"t={stat.elapsed_s:5.1f}s{rb}"
    )

def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--iterations", type=int, default=6,
                   help="number of co-evolution rounds (default 6)")
    p.add_argument("--episodes-per-side", type=int, default=30,
                   help="training episodes per side per iteration (default 30)")
    p.add_argument("--eval-episodes", type=int, default=20,
                   help="greedy match-up size for Elo update (default 20)")
    p.add_argument("--episode-cap", type=int, default=25,
                   help="max steps per episode (default 25)")
    p.add_argument("--def-hidden", type=int, default=16,
                   help="defender hidden-layer size (0 = linear)")
    p.add_argument("--att-hidden", type=int, default=0)
    p.add_argument("--def-lr", type=float, default=0.02)
    p.add_argument("--att-lr", type=float, default=0.03)
    p.add_argument("--seed", type=int, default=12345)
    p.add_argument("--warm-start", type=Path, default=None,
                   help="initialize defender from this .npz checkpoint")
    p.add_argument("--warm-start-attacker", type=Path, default=None,
                   help="initialize attacker from this .npz checkpoint")
    p.add_argument("--checkpoint-dir", type=Path, default=_ROOT / "state" / "coevolve")
    args = p.parse_args(argv)

    print(color("1;36", "=" * 80))
    print(color("1;36", "  Co-evolutionary RL — defender vs adversary"))
    print(color("1;36", "=" * 80))
    print(f"  iterations:        {args.iterations}")
    print(f"  eps/side/iter:     {args.episodes_per_side}")
    print(f"  eval match size:   {args.eval_episodes}")
    print(f"  episode cap:       {args.episode_cap}")
    print(f"  defender hidden:   {args.def_hidden}")
    print(f"  attacker hidden:   {args.att_hidden}")
    print(f"  checkpoint dir:    {args.checkpoint_dir}")
    print()

    # Build defender
    if args.warm_start and args.warm_start.exists():
        print(color("36", f"[init] loading defender from {args.warm_start}"))
        defender = PolicyNet.load(args.warm_start)
    else:
        defender = PolicyNet(PolicyHparams(
            hidden_dim=args.def_hidden,
            learning_rate=args.def_lr,
            seed=args.seed,
        ))

    # Build attacker
    if args.warm_start_attacker and args.warm_start_attacker.exists():
        print(color("36", f"[init] loading attacker from {args.warm_start_attacker}"))
        attacker = AdversaryNet.load(args.warm_start_attacker)
    else:
        attacker = AdversaryNet(AdversaryHparams(
            hidden_dim=args.att_hidden,
            learning_rate=args.att_lr,
            seed=args.seed + 1,
        ))

    sim = AttackerSim(episode_length_range=(8, args.episode_cap))
    env = DeceptionEnv(
        personas_dir=_PERSONAS_DIR,
        attacker_sim=sim,
        episode_cap=args.episode_cap,
    )

    cfg = CoevolveConfig(
        iterations=args.iterations,
        episodes_per_side=args.episodes_per_side,
        eval_episodes=args.eval_episodes,
        episode_cap=args.episode_cap,
        seed=args.seed,
        checkpoint_dir=args.checkpoint_dir,
    )

    t0 = time.perf_counter()
    stats = coevolve(env=env, defender=defender, attacker=attacker,
                     cfg=cfg, on_iteration=_on_iter)
    elapsed = time.perf_counter() - t0

    # Summary
    print()
    print(color("1;36", "=" * 80))
    print(color("1;36", "  Summary"))
    print(color("1;36", "=" * 80))
    print(f"  total time:        {elapsed:.1f}s")
    print(f"  iterations:        {len(stats)}")
    print(f"  final Elo:         defender {stats[-1].defender_elo:.1f}  attacker {stats[-1].attacker_elo:.1f}")
    print(f"  Elo delta:         defender {stats[-1].defender_elo - 1500:+.1f}  attacker {stats[-1].attacker_elo - 1500:+.1f}")
    print()
    print(color("1", "  attacker undetected-rate over iterations:"))
    for s in stats:
        bar = "█" * int(s.attacker_undetected_rate * 30)
        print(f"    [iter {s.iteration:>3d}]  {s.attacker_undetected_rate:5.2%}  {bar}")
    print()
    print(f"  checkpoints: {cfg.checkpoint_dir}/defender_last.npz")
    print(f"               {cfg.checkpoint_dir}/attacker_last.npz")
    print(f"  jsonl log:   {cfg.checkpoint_dir}/coevolve_log.jsonl")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
