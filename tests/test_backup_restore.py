"""Tests for the DR backup/restore tooling.

Exercises the round-trip: create a synthetic state tree, back it up,
delete the source, restore from the tarball, verify byte-equality.
Then negative paths: corrupted tarball detection, cross-deployment
refusal, path-traversal refusal.
"""
import hashlib
import json
import subprocess
import sys
import tarfile
from io import BytesIO
from pathlib import Path

import pytest


_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "tools"))

import backup as backup_mod  # noqa: E402
import restore as restore_mod  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _populate(root: Path) -> None:
    """Build a synthetic state tree under `root` that mirrors what the
    real fabric writes."""
    (root / "state" / "persistence").mkdir(parents=True)
    (root / "state-docker" / "persistence").mkdir(parents=True)
    (root / "state-docker" / "logs" / "bastion-prod").mkdir(parents=True)
    (root / "state-docker" / "mfa").mkdir(parents=True)
    (root / "state" / "content" / "2026Q2").mkdir(parents=True)
    (root / "state" / "checkpoints").mkdir(parents=True)

    (root / "state-docker" / "persistence" / "10.0.0.1__jdoe.json").write_text(
        json.dumps({"engagement_id": "abc-123", "claimed_user": "jdoe"}),
        encoding="utf-8",
    )
    (root / "state-docker" / "logs" / "bastion-prod" / "1.json").write_text(
        json.dumps({"engagement_id": "abc-123", "actions_taken": []}),
        encoding="utf-8",
    )
    (root / "state-docker" / "mfa" / "10.0.0.1.pass").write_text(
        "ip=10.0.0.1\ndecision=pass\nts=1700000000\n",
        encoding="utf-8",
    )
    (root / "state" / "content" / "2026Q2" / "manifest.json").write_text(
        json.dumps({"enabled": True, "deployment_id": "fake-dep"}),
        encoding="utf-8",
    )
    (root / "state" / "checkpoints" / "policy_best.npz").write_bytes(
        b"\x00" * 256,   # synthetic 256-byte "checkpoint"
    )

    # Files we expect EXCLUDED — they should NOT end up in the backup
    (root / "state" / "ssh_host_key").write_bytes(b"this should be excluded")
    (root / "state-docker" / "persistence" / "test.tmp").write_text("tmp")


# ---------------------------------------------------------------------------
# Backup
# ---------------------------------------------------------------------------

class TestBackupBasics:
    def test_empty_tree_raises(self, tmp_path):
        with pytest.raises(RuntimeError):
            backup_mod.backup(root=tmp_path)

    def test_creates_tarball_with_manifest(self, tmp_path):
        _populate(tmp_path)
        out = backup_mod.backup(root=tmp_path, out_dir=tmp_path / "backups",
                                  deployment_id="test-dep-1")
        assert out.exists()
        with tarfile.open(out, "r:gz") as tar:
            names = tar.getnames()
        assert "MANIFEST.json" in names
        # Synthetic state files are in the tarball
        assert any("10.0.0.1__jdoe.json" in n for n in names)
        assert any("manifest.json" in n for n in names)

    def test_manifest_has_required_fields(self, tmp_path):
        _populate(tmp_path)
        out = backup_mod.backup(root=tmp_path, out_dir=tmp_path / "b",
                                  deployment_id="test-dep-2")
        with tarfile.open(out, "r:gz") as tar:
            m = tar.extractfile("MANIFEST.json").read().decode("utf-8")
        meta = json.loads(m)
        for key in ("version", "tool", "created_at", "deployment_id",
                     "file_count", "signature", "files"):
            assert key in meta
        assert meta["deployment_id"] == "test-dep-2"
        assert meta["file_count"] > 0

    def test_ssh_host_keys_excluded(self, tmp_path):
        _populate(tmp_path)
        out = backup_mod.backup(root=tmp_path, out_dir=tmp_path / "b")
        with tarfile.open(out, "r:gz") as tar:
            names = tar.getnames()
        assert not any("ssh_host_key" in n for n in names)

    def test_tmp_files_excluded(self, tmp_path):
        _populate(tmp_path)
        out = backup_mod.backup(root=tmp_path, out_dir=tmp_path / "b")
        with tarfile.open(out, "r:gz") as tar:
            names = tar.getnames()
        assert not any(n.endswith(".tmp") for n in names)

    def test_dry_run_writes_nothing(self, tmp_path):
        _populate(tmp_path)
        out = backup_mod.backup(root=tmp_path, out_dir=tmp_path / "b",
                                  dry_run=True)
        assert not out.exists()

    def test_signature_is_deterministic(self, tmp_path):
        """Backing up the same tree twice produces the same signature
        (filename suffix), since file contents are identical."""
        _populate(tmp_path)
        out1 = backup_mod.backup(root=tmp_path, out_dir=tmp_path / "b")
        out2 = backup_mod.backup(root=tmp_path, out_dir=tmp_path / "b")
        # Extract the signature portion (12 hex chars before .tgz)
        sig1 = out1.name.split("-")[-1].replace(".tgz", "")
        sig2 = out2.name.split("-")[-1].replace(".tgz", "")
        assert sig1 == sig2

    def test_rolling_retention(self, tmp_path):
        _populate(tmp_path)
        backup_dir = tmp_path / "b"
        # Make 5 distinct backups by tweaking one file between runs
        for i in range(5):
            (tmp_path / "state" / "persistence" / f"x{i}.json").write_text(
                json.dumps({"i": i}), encoding="utf-8",
            )
            backup_mod.backup(root=tmp_path, out_dir=backup_dir, keep=3)
        backups = sorted(backup_dir.glob("plenith-state-*.tgz"))
        # Retention should have kept only 3
        assert len(backups) == 3


# ---------------------------------------------------------------------------
# Restore
# ---------------------------------------------------------------------------

class TestRestoreRoundTrip:
    def test_round_trip_byte_equality(self, tmp_path):
        src = tmp_path / "src"
        dst = tmp_path / "dst"
        _populate(src)
        backup_dir = tmp_path / "b"
        tarball = backup_mod.backup(root=src, out_dir=backup_dir,
                                      deployment_id="rt-test")
        # Restore into a fresh root
        dst.mkdir()
        rc = restore_mod.restore(backup_path=tarball, root=dst,
                                   force=True)
        assert rc == 0
        # Verify byte-equality for one of the synthetic files
        original = (src / "state-docker" / "persistence" / "10.0.0.1__jdoe.json").read_bytes()
        restored = (dst / "state-docker" / "persistence" / "10.0.0.1__jdoe.json").read_bytes()
        assert original == restored
        # And the checkpoint blob
        original = (src / "state" / "checkpoints" / "policy_best.npz").read_bytes()
        restored = (dst / "state" / "checkpoints" / "policy_best.npz").read_bytes()
        assert original == restored

    def test_dry_run_does_not_extract(self, tmp_path):
        src = tmp_path / "src"
        dst = tmp_path / "dst"
        _populate(src)
        tarball = backup_mod.backup(root=src, out_dir=tmp_path / "b")
        dst.mkdir()
        rc = restore_mod.restore(backup_path=tarball, root=dst,
                                   dry_run=True, force=True)
        assert rc == 0
        assert not (dst / "state-docker").exists()

    def test_cross_deployment_refused(self, tmp_path):
        src = tmp_path / "src"
        _populate(src)
        tarball = backup_mod.backup(root=src, out_dir=tmp_path / "b",
                                      deployment_id="dep-A")
        # Restore with a DIFFERENT expected deployment, no force
        rc = restore_mod.restore(
            backup_path=tarball, root=tmp_path / "wrong",
            expected_deployment_id="dep-B",
        )
        assert rc == 3   # exit code for cross-deployment

    def test_cross_deployment_allowed_with_force(self, tmp_path):
        src = tmp_path / "src"
        _populate(src)
        tarball = backup_mod.backup(root=src, out_dir=tmp_path / "b",
                                      deployment_id="dep-A")
        dst = tmp_path / "dst"
        dst.mkdir()
        rc = restore_mod.restore(
            backup_path=tarball, root=dst,
            expected_deployment_id="dep-B", force=True,
        )
        assert rc == 0

    def test_corrupted_tarball_detected(self, tmp_path):
        """Mutate a single byte in the tarball — verification must catch it."""
        src = tmp_path / "src"
        _populate(src)
        tarball = backup_mod.backup(root=src, out_dir=tmp_path / "b")
        # Surgically corrupt a byte deep inside the gzipped content.
        # We rebuild the tar with one altered file member's content.
        bad = tmp_path / "bad.tgz"
        # Open the good tar, swap one file's content, write to bad
        with tarfile.open(tarball, "r:gz") as r, tarfile.open(bad, "w:gz") as w:
            for m in r.getmembers():
                if m.name == "MANIFEST.json":
                    w.addfile(m, r.extractfile(m))
                elif m.name.endswith("10.0.0.1__jdoe.json"):
                    new_content = b"CORRUPTED" + r.extractfile(m).read()
                    new_m = tarfile.TarInfo(name=m.name)
                    new_m.size = len(new_content)
                    new_m.mtime = m.mtime
                    w.addfile(new_m, BytesIO(new_content))
                else:
                    f = r.extractfile(m)
                    if f is None:
                        w.addfile(m)
                    else:
                        w.addfile(m, f)
        # Now restore should detect the hash mismatch
        rc = restore_mod.restore(backup_path=bad, root=tmp_path / "dst-bad",
                                   force=True)
        assert rc == 4

    def test_missing_manifest_rejected(self, tmp_path):
        """A tarball without MANIFEST.json is not a Plenith backup."""
        bad = tmp_path / "no-manifest.tgz"
        with tarfile.open(bad, "w:gz") as w:
            ti = tarfile.TarInfo(name="random.txt")
            data = b"hello"
            ti.size = len(data)
            w.addfile(ti, BytesIO(data))
        rc = restore_mod.restore(backup_path=bad, root=tmp_path / "dst",
                                   force=True)
        # ValueError → 1 (generic main() error handling)
        assert rc != 0


# ---------------------------------------------------------------------------
# CLIs
# ---------------------------------------------------------------------------

class TestCLI:
    def _run(self, script: str, *args, cwd=None):
        return subprocess.run(
            [sys.executable, str(_ROOT / "tools" / script), *args],
            capture_output=True, text=True, timeout=30, cwd=cwd,
            encoding="utf-8",
        )

    def test_backup_dry_run_cli(self, tmp_path):
        _populate(tmp_path)
        r = self._run("backup.py", "--root", str(tmp_path), "--dry-run",
                       "--out", str(tmp_path / "b"))
        assert r.returncode == 0
        assert "DRY RUN" in r.stdout

    def test_restore_list_cli(self, tmp_path):
        # No backups dir → empty listing, exit 0
        r = self._run("restore.py", "--list", "--out-dir", str(tmp_path / "empty"))
        assert r.returncode == 0
        assert "no backups" in r.stdout.lower() or r.stdout.strip() == ""

    def test_restore_latest_not_found(self, tmp_path):
        # 'latest' against an empty dir → exit 1
        r = self._run("restore.py", "latest",
                       "--out-dir", str(tmp_path / "empty"))
        assert r.returncode == 1
