"""CLI: regenerate / inspect / diff Plenith rotated content.

Three modes:

  * `--out <dir>`         materialize every rotated artifact under <dir>/
                          and write a `manifest.json` alongside.

  * `--diff <other-dir>`  compare the current deployment+epoch's manifest
                          against another directory's manifest. Returns
                          exit-1 if any artifact hash differs (useful for
                          a "did this epoch actually rotate?" CI gate).

  * `--show`              (default) print the corp identity + per-artifact
                          hashes to stdout. No files written.

Examples:

  # Enable rotation: pick a stable deployment_id once at install time.
  python tools/rotate_content.py \\
      --deployment-id 6f3a8c2e-... --epoch 2026Q2 \\
      --out state/content/2026Q2

  # Bump quarterly. Diff against the prior epoch to confirm rotation:
  python tools/rotate_content.py \\
      --deployment-id 6f3a8c2e-... --epoch 2026Q3 \\
      --out state/content/2026Q3 \\
      --diff state/content/2026Q2

The `deployment_id` is the install-time secret — keep it consistent
across restarts so honeytokens, persisted state, and analyst muscle-
memory all stay coherent. The `epoch` is the rotate-every-quarter knob.
"""
import argparse
import io
import json
import sys
from pathlib import Path

# Repo root on path for `python tools/rotate_content.py` invocation.
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, io.UnsupportedOperation, ValueError):
    pass

from plenith.rotation import ContentRotator, DeploymentSeed  # noqa: E402


def _color(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m"


def _show(rotator: ContentRotator) -> None:
    """Pretty-print corp identity + per-artifact hashes."""
    manifest = rotator.build_manifest()
    if not manifest.get("enabled"):
        print(_color("31", "rotation is disabled (no deployment_id set)"))
        return
    print(_color("1", "=== Plenith content rotation ==="))
    print(f"  deployment: {manifest['deployment_id']}")
    print(f"  epoch:      {manifest['epoch']}")
    print(f"  signature:  {manifest['signature']}")
    print()
    corp = manifest["corp"]
    print(_color("1", "Corp identity"))
    print(f"  name:        {corp['corp_name']}")
    print(f"  short:       {corp['corp_short']}")
    print(f"  domain:      {corp['corp_domain']}")
    print(f"  industry:    {corp['industry_long']} ({corp['industry_short']})")
    print(f"  prod subnet: {corp['prod_subnet']}")
    print(f"  decoy hosts: {', '.join(corp['decoy_hosts'])}")
    print(f"  db dbname:   {corp['db_database_name']}")
    print(f"  motd:        {corp['motd_tagline']}")
    print()
    print(_color("1", "Artifact hashes"))
    for name, h in manifest["artifact_hashes"].items():
        size = manifest["artifact_sizes"][name]
        print(f"  {h}  {size:>5d}B  {name}")


def _diff(rotator: ContentRotator, other_dir: Path) -> int:
    """Compare current rotator's manifest against another's. Returns 0 if
    identical, 1 if any hash differs (suitable as a CI gate)."""
    other_path = other_dir / "manifest.json"
    if not other_path.exists():
        print(_color("31", f"no manifest at {other_path}"), file=sys.stderr)
        return 2
    other = json.loads(other_path.read_text(encoding="utf-8"))
    if not other.get("enabled"):
        print(_color("31", f"manifest at {other_path} is disabled"), file=sys.stderr)
        return 2

    here = rotator.build_manifest()
    if not here.get("enabled"):
        print(_color("31", "current rotator is disabled — nothing to diff"),
              file=sys.stderr)
        return 2

    diffs = []
    for name, this_h in here["artifact_hashes"].items():
        that_h = other["artifact_hashes"].get(name, "<missing>")
        if this_h != that_h:
            diffs.append((name, that_h, this_h))

    if not diffs:
        print(_color("32",
                     f"no diff — both epochs share artifact hashes "
                     f"(sig={here['signature']} == {other.get('signature')})"))
        return 0
    print(_color("33", f"changed {len(diffs)}/{len(here['artifact_hashes'])} artifacts:"))
    for name, before, after in diffs:
        print(f"  {name:<22s}  {before}  →  {after}")
    return 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--deployment-id", required=True,
                   help="stable per-install id (use uuidgen once at deploy time)")
    p.add_argument("--epoch", default="default",
                   help="rotation epoch label, e.g. 2026Q2 (default: 'default')")
    p.add_argument("--out", type=Path,
                   help="write every rotated artifact under this directory")
    p.add_argument("--diff", type=Path, metavar="OTHER_DIR",
                   help="compare against another directory's manifest.json")
    p.add_argument("--show", action="store_true",
                   help="print corp identity + artifact hashes to stdout (default action)")
    args = p.parse_args(argv)

    seed = DeploymentSeed(deployment_id=args.deployment_id, epoch=args.epoch)
    rotator = ContentRotator.from_seed(seed)

    # Default action: --show unless --out or --diff is provided
    if not (args.out or args.diff):
        args.show = True

    if args.show:
        _show(rotator)

    exit_code = 0

    if args.out:
        rotator.write_artifact_bundle(args.out)
        print(_color("32", f"wrote artifacts to {args.out}/"))

    if args.diff:
        rc = _diff(rotator, args.diff)
        exit_code = max(exit_code, rc)

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
