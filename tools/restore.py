"""tools/restore.py — restore from a `tools/backup.py` tarball.

Inverse of `tools/backup.py`. Reads the embedded MANIFEST.json,
verifies SHA-256 hashes of every file BEFORE extracting any of them
(no partial-restore states), and refuses to restore a different
deployment's backup unless `--force` is passed (a common DR mistake
under stress).

Usage:
    python tools/restore.py latest                            # restore most recent
    python tools/restore.py /backups/plenith-state-*.tgz   # specific file
    python tools/restore.py --list                            # list available
    python tools/restore.py latest --dry-run                  # verify only
    python tools/restore.py latest --force                    # cross-deployment OK
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import sys
import tarfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_ROOT = Path(__file__).resolve().parent.parent

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, io.UnsupportedOperation, ValueError):
    pass


def color(c: str, s: str) -> str:
    return f"\033[{c}m{s}\033[0m"


def _read_manifest(tar: tarfile.TarFile) -> Dict:
    """Pull MANIFEST.json out of the tarball without extracting anything else."""
    try:
        m = tar.getmember("MANIFEST.json")
    except KeyError:
        raise ValueError("backup is missing MANIFEST.json — not a Plenith backup")
    f = tar.extractfile(m)
    if f is None:
        raise ValueError("MANIFEST.json is empty")
    return json.loads(f.read().decode("utf-8"))


def _list_backups(out_dir: Path) -> List[Path]:
    return sorted(out_dir.glob("plenith-state-*.tgz"))


def _resolve_backup(spec: str, out_dir: Path) -> Path:
    """Resolve `spec` to a concrete file: 'latest', a path, or a glob."""
    if spec == "latest":
        candidates = _list_backups(out_dir)
        if not candidates:
            raise FileNotFoundError(f"no backups under {out_dir}/")
        return candidates[-1]
    p = Path(spec)
    if p.exists():
        return p
    raise FileNotFoundError(f"backup not found: {spec}")


def _verify_hashes(tar: tarfile.TarFile, manifest: Dict) -> List[Tuple[str, str, str]]:
    """Walk the manifest and verify each file's hash in-place inside the
    tarball. Returns a list of mismatches as (arcname, expected, actual)
    triples — empty list = clean backup."""
    bad: List[Tuple[str, str, str]] = []
    expected = manifest.get("files") or {}
    for arc, want in expected.items():
        try:
            m = tar.getmember(arc)
        except KeyError:
            bad.append((arc, want, "MISSING"))
            continue
        f = tar.extractfile(m)
        if f is None:
            bad.append((arc, want, "UNREADABLE"))
            continue
        h = hashlib.sha256()
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
        got = h.hexdigest()
        if got != want:
            bad.append((arc, want, got))
    return bad


def restore(
    *,
    backup_path: Path,
    root: Optional[Path] = None,
    dry_run: bool = False,
    force: bool = False,
    expected_deployment_id: Optional[str] = None,
) -> int:
    """Restore a backup tarball.

    Steps:
      1. Open tar, read MANIFEST.
      2. Cross-check the embedded deployment_id against expected (unless --force).
      3. Verify SHA-256 of every file (in-tarball, no extraction).
      4. If --dry-run, stop here with a clean-or-dirty report.
      5. Extract every file under `root/`, preserving relative paths.
    """
    root = root or _ROOT
    print(color("36", f"[restore] reading {backup_path}"), file=sys.stderr)

    with tarfile.open(backup_path, "r:gz") as tar:
        try:
            manifest = _read_manifest(tar)
        except ValueError as e:
            print(color("31", f"[restore] {e}"), file=sys.stderr)
            return 6
        bk_dep = manifest.get("deployment_id", "")
        bk_sig = manifest.get("signature", "?")
        n_files = manifest.get("file_count", 0)
        print(color("36",
                    f"[restore] manifest: deployment={bk_dep or '(unset)'}  "
                    f"sig={bk_sig}  files={n_files}"),
              file=sys.stderr)

        # Cross-deployment safety check
        target_dep = expected_deployment_id or os.environ.get("PLENITH_DEPLOYMENT_ID")
        if target_dep and bk_dep and target_dep != bk_dep and not force:
            print(color("31",
                        f"[restore] REFUSING: backup is from deployment {bk_dep!r}, "
                        f"but target is {target_dep!r}. Pass --force to override."),
                  file=sys.stderr)
            return 3

        # Integrity check
        print(color("36", "[restore] verifying SHA-256 of every file ..."),
              file=sys.stderr)
        mismatches = _verify_hashes(tar, manifest)
        if mismatches:
            print(color("31",
                        f"[restore] FAILED integrity check — "
                        f"{len(mismatches)} files differ:"),
                  file=sys.stderr)
            for arc, want, got in mismatches[:10]:
                print(f"  - {arc}  expected={want[:12]}  got={got[:12]}",
                      file=sys.stderr)
            return 4
        print(color("32", f"[restore] integrity OK — {n_files} files verified"))

        if dry_run:
            print(color("33", "[restore] DRY RUN — no files extracted"))
            return 0

        # Reopen the tarball so we can extract (we've already consumed all
        # the inner streams during hash verification).
        pass  # 'with' will close; we reopen below

    with tarfile.open(backup_path, "r:gz") as tar:
        members = [m for m in tar.getmembers() if m.name != "MANIFEST.json"]
        # Safety: refuse to extract any absolute path or `..` traversal
        for m in members:
            if m.name.startswith("/") or ".." in Path(m.name).parts:
                print(color("31",
                            f"[restore] FAILED: path-traversal attempt {m.name!r}"),
                      file=sys.stderr)
                return 5
        # Python 3.12+ added `filter="data"` for safe extraction (TAR-style
        # ACE/symlink shenanigans); use it if available.
        try:
            tar.extractall(path=root, members=members, filter="data")
        except TypeError:
            tar.extractall(path=root, members=members)
    print(color("32", f"[restore] extracted {len(members)} files into {root}"))
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("backup", nargs="?", default="latest",
                   help="path to a backup tarball, or 'latest' (default)")
    p.add_argument("--list", action="store_true",
                   help="list available backups under --out-dir and exit")
    p.add_argument("--out-dir", type=Path,
                   default=_ROOT / "state-backups",
                   help="directory to look for 'latest' in")
    p.add_argument("--root", type=Path, default=_ROOT,
                   help="extraction root (default: project root)")
    p.add_argument("--dry-run", action="store_true",
                   help="verify integrity, don't extract")
    p.add_argument("--force", action="store_true",
                   help="permit restore from a different deployment_id")
    p.add_argument("--expected-deployment-id", default=None)
    args = p.parse_args(argv)

    if args.list:
        backups = _list_backups(args.out_dir)
        if not backups:
            print(color("33", f"no backups under {args.out_dir}/"))
            return 0
        print(color("1", f"backups in {args.out_dir}:"))
        for b in backups:
            size = b.stat().st_size
            print(f"  {b.name:<60s}  {size:>12,d} bytes")
        return 0

    try:
        backup_path = _resolve_backup(args.backup, args.out_dir)
    except FileNotFoundError as e:
        print(color("31", f"[restore] {e}"), file=sys.stderr)
        return 1

    return restore(
        backup_path=backup_path,
        root=args.root,
        dry_run=args.dry_run,
        force=args.force,
        expected_deployment_id=args.expected_deployment_id,
    )


if __name__ == "__main__":
    raise SystemExit(main())
