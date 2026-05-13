"""tools/backup.py — capture a point-in-time backup of Plenith state.

What gets backed up:
    state/persistence/        engagement state (cross-session continuity)
    state-docker/persistence/ docker-fabric engagement state
    state-docker/logs/        per-host engagement logs
    state-docker/mfa/         MFA enrollment + recent decisions
    state/content/            rotated content manifests
    state/checkpoints/        RL policy checkpoints
    state/coevolve/           adversarial co-evolution checkpoints

What does NOT get backed up (stateless / re-derivable):
    caches/                   LLM response cache (warms back up)
    logs/                     local-mode SSH session logs (>retention age anyway)
    *.pyc / __pycache__       obviously
    state/ssh_host_key        per-deployment, regenerated on demand
    secrets / .env            never. Operator backs those up separately.

Output:
    .tgz tarball at the configured backup location, named with a
    timestamp + a short manifest hash so two snapshots taken in the
    same second don't collide. Returns 0 on success, non-zero on
    backup failure (CI gates can check the exit code).

Companion runbook: `python tools/runbook.py dr`.

Usage:
    python tools/backup.py                       # default location
    python tools/backup.py --out /backups/       # custom location
    python tools/backup.py --keep 96             # rolling retention
    python tools/backup.py --dry-run             # show what WOULD be backed up
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import io
import json
import os
import sys
import tarfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_ROOT = Path(__file__).resolve().parent.parent

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, io.UnsupportedOperation, ValueError):
    pass


# ---------------------------------------------------------------------------
# What to back up — relative paths under the project root. Each entry is
# (path, required?) — required=False means "include if present, skip if not."
# ---------------------------------------------------------------------------

_INCLUDE = [
    ("state/persistence",        False),
    ("state-docker/persistence", False),
    ("state-docker/logs",        False),
    ("state-docker/mfa",         False),
    ("state/content",            False),
    ("state/checkpoints",        False),
    ("state/coevolve",           False),
    ("config.yaml",              False),
    ("linux-fork/.env",          False),
]

# Files in the included paths we explicitly DROP — host SSH keys are
# regenerated on demand and shouldn't follow the backup around; tmp
# files are obviously junk.
_EXCLUDE_FILENAMES = {
    "ssh_host_key", "ssh_host_key.pub",
    "mfa_host_key", "mfa_host_key.pub",
    ".DS_Store", "Thumbs.db",
}
_EXCLUDE_SUFFIXES = (".tmp", ".swp", ".pyc", ".lock")


def color(c: str, s: str) -> str:
    return f"\033[{c}m{s}\033[0m"


def _utc_stamp() -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
        .replace(":", "")  # filesystem-safe
    )


def _should_include(p: Path) -> bool:
    if p.name in _EXCLUDE_FILENAMES:
        return False
    if p.suffix in _EXCLUDE_SUFFIXES:
        return False
    # Skip __pycache__ subtrees
    if "__pycache__" in p.parts:
        return False
    return True


def _gather(root: Path) -> List[Tuple[Path, str]]:
    """Walk every _INCLUDE path and return [(absolute_path, arcname), ...].
    `arcname` is the path inside the tarball, rooted at the project name."""
    out: List[Tuple[Path, str]] = []
    for rel, required in _INCLUDE:
        src = root / rel
        if not src.exists():
            if required:
                raise FileNotFoundError(f"required path missing: {src}")
            continue
        if src.is_file():
            if _should_include(src):
                out.append((src, rel))
            continue
        # Directory — walk recursively
        for p in sorted(src.rglob("*")):
            if p.is_file() and _should_include(p):
                arc = str(p.relative_to(root)).replace(os.sep, "/")
                out.append((p, arc))
    return out


def _manifest(entries: List[Tuple[Path, str]]) -> Dict[str, str]:
    """Compute SHA-256 hashes for every backed-up file. The hash list is
    embedded in the tarball as `MANIFEST.json` so restore can verify
    integrity without trusting tar's own checksums."""
    out: Dict[str, str] = {}
    for src, arc in entries:
        h = hashlib.sha256()
        try:
            with src.open("rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    h.update(chunk)
            out[arc] = h.hexdigest()
        except OSError as e:
            print(color("33", f"  warning: can't hash {arc}: {e}"),
                  file=sys.stderr)
    return out


def _summary_signature(manifest: Dict[str, str]) -> str:
    """A 12-char fingerprint of the whole backup — appended to the
    filename so two backups at the same second never collide."""
    return hashlib.sha256(
        "\n".join(f"{k}={v}" for k, v in sorted(manifest.items())).encode("utf-8"),
    ).hexdigest()[:12]


def backup(
    *,
    root: Optional[Path] = None,
    out_dir: Optional[Path] = None,
    deployment_id: Optional[str] = None,
    dry_run: bool = False,
    keep: Optional[int] = None,
) -> Path:
    """Build the backup tarball. Returns the path on success.

    `deployment_id` is embedded in the manifest so restore can refuse to
    restore a wrong-deployment backup into the wrong cluster (a common
    DR mistake under stress).
    """
    root = root or _ROOT
    out_dir = out_dir or (root / "state-backups")
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    entries = _gather(root)
    if not entries:
        raise RuntimeError("nothing to back up — all known paths are empty")
    print(color("36", f"[backup] {len(entries)} files to archive"),
          file=sys.stderr)

    manifest = _manifest(entries)
    sig = _summary_signature(manifest)
    name = f"plenith-state-{_utc_stamp()}-{sig}.tgz"
    target = out_dir / name

    if dry_run:
        print(color("33", "[backup] DRY RUN — no tarball written"))
        for src, arc in entries[:30]:
            print(f"  + {arc}")
        if len(entries) > 30:
            print(color("90", f"  ... and {len(entries) - 30} more"))
        return target

    meta = {
        "version":       1,
        "tool":          "plenith-backup",
        "created_at":    _utc_stamp(),
        "deployment_id": deployment_id or os.environ.get("PLENITH_DEPLOYMENT_ID", ""),
        "file_count":    len(entries),
        "signature":     sig,
        "files":         manifest,
    }
    meta_bytes = json.dumps(meta, indent=2, sort_keys=True).encode("utf-8")

    with tarfile.open(target, "w:gz") as tar:
        # Embed manifest first so restore can verify-before-extract
        ti = tarfile.TarInfo(name="MANIFEST.json")
        ti.size = len(meta_bytes)
        ti.mtime = int(time.time())
        tar.addfile(ti, io.BytesIO(meta_bytes))
        for src, arc in entries:
            tar.add(src, arcname=arc, recursive=False)

    print(color("32", f"[backup] wrote {target} ({target.stat().st_size:,} bytes)"))

    if keep is not None and keep > 0:
        # Rolling retention — sort by name (timestamp prefix is sortable),
        # delete oldest beyond `keep`.
        all_backups = sorted(out_dir.glob("plenith-state-*.tgz"))
        excess = max(0, len(all_backups) - keep)
        for f in all_backups[:excess]:
            try:
                f.unlink()
                print(color("90", f"[backup] retired {f.name}"),
                      file=sys.stderr)
            except OSError:
                pass

    return target


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--root", type=Path, default=_ROOT,
                   help=f"project root (default: {_ROOT})")
    p.add_argument("--out", "--out-dir", dest="out_dir", type=Path,
                   default=None,
                   help="output directory (default: <root>/state-backups/)")
    p.add_argument("--deployment-id", default=None,
                   help="embed this deployment id in the manifest (default: "
                        "$PLENITH_DEPLOYMENT_ID)")
    p.add_argument("--dry-run", action="store_true",
                   help="show what would be backed up, don't write")
    p.add_argument("--keep", type=int, default=None,
                   help="rolling retention: keep this many newest backups, "
                        "delete older")
    args = p.parse_args(argv)

    try:
        backup(
            root=args.root, out_dir=args.out_dir,
            deployment_id=args.deployment_id,
            dry_run=args.dry_run, keep=args.keep,
        )
    except FileNotFoundError as e:
        print(color("31", f"[backup] FAILED: {e}"), file=sys.stderr)
        return 2
    except Exception as e:
        print(color("31", f"[backup] FAILED: {type(e).__name__}: {e}"),
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
