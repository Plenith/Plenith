"""Tests for `plenith.snapshots.SnapshotWriter` — Phase 3 of UI_WIRING.md.

Tests the contract operators depend on: a snapshot is a single self-
contained `.tar.gz` of everything currently known about the engagement,
with a manifest that lists every member's sha256 so downstream consumers
can verify integrity without re-extracting.
"""
from __future__ import annotations

import hashlib
import json
import tarfile
import time
from pathlib import Path

import pytest

from plenith.snapshots import SnapshotWriter

@pytest.fixture
def state_root(tmp_path):
    """A fake state-docker layout the writer can scan."""
    root = tmp_path / "state-docker"
    (root / "persistence").mkdir(parents=True)
    (root / "logs" / "bastion-prod").mkdir(parents=True)
    (root / "logs" / "api-prod-03").mkdir(parents=True)
    return root

def _seed_engagement(root: Path, engagement_id: str, *,
                      hosts=("bastion-prod",), n_logs=1):
    """Write a plausible persistence file + one log per host."""
    persistence = {
        "engagement_id":  engagement_id,
        "claimed_user":   "jdoe",
        "source_ip":      "203.0.113.7",
        "first_seen_at":  time.time() - 600,
        "last_seen_at":   time.time(),
        "cwd":            "/home/jdoe",
        "observed":       {"ran_sudo": True},
    }
    (root / "persistence" / f"203.0.113.7__jdoe.json").write_text(
        json.dumps(persistence), encoding="utf-8",
    )
    for host in hosts:
        for i in range(n_logs):
            (root / "logs" / host / f"100{i}_log-{i}.json").write_text(
                json.dumps({
                    "engagement_id":  engagement_id,
                    "actions_taken": [{"action": "alert_x", "severity": "high"}],
                    "commands":       [{"ts": time.time(), "cmd": "uname -a"}],
                }), encoding="utf-8",
            )

def test_write_creates_tarball_at_expected_path(state_root):
    _seed_engagement(state_root, "eng-001")
    writer = SnapshotWriter(state_root)
    result = writer.write("eng-001", op_id="mwilson", note="for IR review")

    assert result["engagement_id"] == "eng-001"
    assert result["captured_by"] == "mwilson"
    assert result["note"] == "for IR review"
    assert result["size"] > 100
    archive = Path(result["path"])
    assert archive.exists()
    assert archive.name.startswith("eng-001-")
    assert archive.suffix == ".gz"

def test_archive_contains_manifest_and_members(state_root):
    _seed_engagement(state_root, "eng-001",
                      hosts=("bastion-prod", "api-prod-03"))
    writer = SnapshotWriter(state_root)
    result = writer.write("eng-001", op_id="mwilson")

    with tarfile.open(result["path"], "r:gz") as tar:
        names = tar.getnames()
        assert "manifest.json" in names
        assert any(n.startswith("persistence/") for n in names)
        assert any(n.startswith("logs/bastion-prod/") for n in names)
        assert any(n.startswith("logs/api-prod-03/") for n in names)

        # Manifest claims match what's in the archive
        manifest_data = json.loads(
            tar.extractfile("manifest.json").read().decode("utf-8"),
        )
        assert manifest_data["engagement_id"] == "eng-001"
        assert manifest_data["captured_by"]   == "mwilson"
        assert isinstance(manifest_data["members"], list)
        # Every member listed should match a tar entry
        listed = {m["path"] for m in manifest_data["members"]}
        present = set(names) - {"manifest.json"}
        assert listed == present

def test_manifest_sha256_matches_member_content(state_root):
    """Integrity check: a downstream consumer reading the manifest's
    sha256 must get the same hash by re-hashing the member content."""
    _seed_engagement(state_root, "eng-001")
    writer = SnapshotWriter(state_root)
    result = writer.write("eng-001", op_id="x")

    with tarfile.open(result["path"], "r:gz") as tar:
        manifest = json.loads(
            tar.extractfile("manifest.json").read().decode("utf-8"),
        )
        for member in manifest["members"]:
            actual = hashlib.sha256(
                tar.extractfile(member["path"]).read(),
            ).hexdigest()
            assert actual == member["sha256"], member["path"]

def test_write_with_no_matching_files_still_produces_valid_archive(state_root):
    """Edge case: engagement_id has no persistence file yet (extremely
    fresh).  Snapshot must still produce a valid tarball with at least
    the manifest, so the operator gets feedback."""
    writer = SnapshotWriter(state_root)
    result = writer.write("eng-fresh", op_id="x")
    assert Path(result["path"]).exists()
    with tarfile.open(result["path"], "r:gz") as tar:
        assert "manifest.json" in tar.getnames()
        manifest = json.loads(
            tar.extractfile("manifest.json").read().decode("utf-8"),
        )
        # No members; manifest is still well-formed
        assert manifest["engagement_id"] == "eng-fresh"
        assert manifest["members"] == []

def test_write_includes_acks_slice_when_present(state_root):
    _seed_engagement(state_root, "eng-001")
    # Fake acks.json with one entry for the target eng + one for a different eng
    (state_root / "acks.json").write_text(json.dumps({
        "eng-001": {"alert_x": {"ts": time.time(), "op_id": "mwilson"}},
        "eng-OTHER": {"alert_y": {"ts": time.time(), "op_id": "agarcia"}},
    }), encoding="utf-8")
    writer = SnapshotWriter(state_root)
    result = writer.write("eng-001", op_id="mwilson")
    with tarfile.open(result["path"], "r:gz") as tar:
        names = tar.getnames()
        assert "acks.json" in names
        acks_data = json.loads(
            tar.extractfile("acks.json").read().decode("utf-8"),
        )
        # Only the target engagement's acks are included
        assert list(acks_data.keys()) == ["eng-001"]

def test_write_includes_notes_slice_when_present(state_root):
    _seed_engagement(state_root, "eng-001")
    (state_root / "notes.json").write_text(json.dumps({
        "eng-001": [{"id": "n1", "author": "x", "ts": 1, "body": "test"}],
    }), encoding="utf-8")
    writer = SnapshotWriter(state_root)
    result = writer.write("eng-001", op_id="x")
    with tarfile.open(result["path"], "r:gz") as tar:
        assert "notes.json" in tar.getnames()

def test_write_omits_overlays_when_neither_acks_nor_notes_exist(state_root):
    """No acks.json / notes.json on disk → those archive entries don't
    appear.  Keeps small engagements producing small snapshots."""
    _seed_engagement(state_root, "eng-001")
    writer = SnapshotWriter(state_root)
    result = writer.write("eng-001", op_id="x")
    with tarfile.open(result["path"], "r:gz") as tar:
        names = tar.getnames()
        assert "acks.json" not in names
        assert "notes.json" not in names

def test_list_for_returns_snapshots_newest_first(state_root):
    _seed_engagement(state_root, "eng-001")
    writer = SnapshotWriter(state_root)
    first = writer.write("eng-001", op_id="x")
    time.sleep(0.05)
    second = writer.write("eng-001", op_id="x")
    lst = writer.list_for("eng-001")
    assert len(lst) == 2
    assert lst[0]["name"] == Path(second["path"]).name
    assert lst[1]["name"] == Path(first["path"]).name

def test_list_for_filters_to_one_engagement(state_root):
    _seed_engagement(state_root, "eng-001")
    _seed_engagement(state_root, "eng-002")
    writer = SnapshotWriter(state_root)
    writer.write("eng-001", op_id="x")
    writer.write("eng-002", op_id="x")
    assert len(writer.list_for("eng-001")) == 1
    assert len(writer.list_for("eng-002")) == 1

def test_list_for_returns_empty_when_dir_missing(tmp_path):
    """First-time deployment with no snapshots/ dir yet."""
    writer = SnapshotWriter(tmp_path / "fresh-deployment")
    assert writer.list_for("any-eng") == []

def test_write_rejects_empty_engagement_id(state_root):
    writer = SnapshotWriter(state_root)
    with pytest.raises(ValueError):
        writer.write("", op_id="x")
