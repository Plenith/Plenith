"""Engagement snapshot writer — Phase 3 of docs/design/UI_WIRING.md.

When an analyst clicks "Snapshot" on an active engagement, the dashboard
writes a `.tar.gz` of everything currently known about that engagement
to `state-docker/snapshots/<engagement_id>-<ts>.tar.gz`.  Contents:

  manifest.json         — when, who, sha256 of each member, plenith version
  persistence/          — the engagement's per-(ip,user) state file
  logs/                 — every session log file for this engagement
  acks.json             — just the acks for this engagement
  notes.json            — just the notes for this engagement

Goal: a single artifact an analyst can hand to legal, IR, or a customer
without re-querying the live system.  Also used by the proof-by-trap
case-study workflow: take a snapshot at the moment the trap fires.

The original files stay where they are — snapshot is a read-only copy.
"""
from __future__ import annotations

import hashlib
import io
import json
import tarfile
import time
from pathlib import Path
from typing import Any

def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

class SnapshotWriter:
    """Build engagement snapshots.  Statelesss — the writer takes the
    state-docker root and the engagement_id and reads files at write-
    time.  No long-lived handles or registries.
    """

    def __init__(self, state_docker_root: Path | str):
        self.root = Path(state_docker_root)
        self.snapshot_dir = self.root / "snapshots"
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)

    # ----- discovery --------------------------------------------------

    def _persistence_files_for(self, engagement_id: str) -> list[Path]:
        """Find persistence file(s) matching this engagement.  Walk the
        persistence dir and match by engagement_id in the JSON content,
        not by filename pattern — filenames are `<ip>__<user>.json` and
        don't encode the engagement_id."""
        pers_dir = self.root / "persistence"
        if not pers_dir.exists():
            return []
        out: list[Path] = []
        for p in pers_dir.glob("*.json"):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(data, dict) and data.get("engagement_id") == engagement_id:
                out.append(p)
        return out

    def _log_files_for(self, engagement_id: str) -> list[Path]:
        """Find session log files matching this engagement.  Logs are at
        `state-docker/logs/<host>/<epoch>_<uuid>.json` and the filename
        UUID is the *log* uuid, not the engagement.  Match by content."""
        logs_dir = self.root / "logs"
        if not logs_dir.exists():
            return []
        out: list[Path] = []
        for host_dir in logs_dir.iterdir():
            if not host_dir.is_dir():
                continue
            for p in host_dir.glob("*.json"):
                try:
                    data = json.loads(p.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                if isinstance(data, dict) and data.get("engagement_id") == engagement_id:
                    out.append(p)
        return out

    def _acks_slice(self, engagement_id: str) -> dict[str, Any]:
        """Return just the ack overlay entries for this engagement."""
        acks_path = self.root / "acks.json"
        if not acks_path.exists():
            return {}
        try:
            data = json.loads(acks_path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and engagement_id in data:
                return {engagement_id: data[engagement_id]}
        except (OSError, json.JSONDecodeError):
            pass
        return {}

    def _notes_slice(self, engagement_id: str) -> dict[str, Any]:
        notes_path = self.root / "notes.json"
        if not notes_path.exists():
            return {}
        try:
            data = json.loads(notes_path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and engagement_id in data:
                return {engagement_id: data[engagement_id]}
        except (OSError, json.JSONDecodeError):
            pass
        return {}

    # ----- main entry -------------------------------------------------

    def write(self, engagement_id: str, *,
               op_id: str = "anonymous",
               note: str = "",
               plenith_version: str = "v1.0.1") -> dict[str, Any]:
        """Build a `.tar.gz` for the engagement.  Returns a manifest dict
        with `path`, `size`, `sha256` of the archive itself so the API
        can echo it back to the caller and the dashboard can list it.

        Even if the engagement has no persistence or logs (which would
        be weird but possible for a freshly-created entry), still
        produces a valid tarball with at least the manifest so the
        operator gets feedback.
        """
        if not engagement_id:
            raise ValueError("engagement_id required")

        # Millisecond precision so two snapshots within the same second
        # (operator double-clicks the button, automation calls twice in
        # quick succession) get unique filenames.  Integer seconds would
        # collide and the second write would overwrite the first.
        ts_ms = int(time.time() * 1000)
        ts = ts_ms / 1000.0
        archive_name = f"{engagement_id}-{ts_ms}.tar.gz"
        archive_path = self.snapshot_dir / archive_name

        persistence_files = self._persistence_files_for(engagement_id)
        log_files         = self._log_files_for(engagement_id)
        acks_slice        = self._acks_slice(engagement_id)
        notes_slice       = self._notes_slice(engagement_id)

        # Build manifest as we go — every member gets its sha256 listed
        # so a downstream consumer can verify integrity without
        # re-extracting the archive.
        manifest: dict[str, Any] = {
            "engagement_id":   engagement_id,
            "captured_at":     time.time(),
            "captured_by":     op_id or "anonymous",
            "note":            note or "",
            "plenith_version": plenith_version,
            "members":         [],   # filled below
        }

        # Use the in-memory archive pattern: write the body to a
        # BytesIO so we can append the manifest *last* (after computing
        # all the member hashes), then flush to disk.  Avoids needing
        # two passes over the file.
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            def _add_bytes(arcname: str, content: bytes) -> None:
                info = tarfile.TarInfo(name=arcname)
                info.size = len(content)
                info.mtime = ts
                info.mode = 0o644
                tar.addfile(info, io.BytesIO(content))
                manifest["members"].append({
                    "path":   arcname,
                    "size":   len(content),
                    "sha256": _sha256_bytes(content),
                })

            for f in persistence_files:
                _add_bytes(f"persistence/{f.name}", f.read_bytes())
            for f in log_files:
                # Preserve hostname/<file> layout
                host = f.parent.name
                _add_bytes(f"logs/{host}/{f.name}", f.read_bytes())
            if acks_slice:
                _add_bytes("acks.json",
                            json.dumps(acks_slice, indent=2, default=str)
                                .encode("utf-8"))
            if notes_slice:
                _add_bytes("notes.json",
                            json.dumps(notes_slice, indent=2, default=str)
                                .encode("utf-8"))
            # Manifest goes last so it can list every other member's
            # sha256.  The manifest's own hash is the file-level
            # sha256 returned to the caller.
            manifest_bytes = json.dumps(
                manifest, indent=2, default=str, sort_keys=True,
            ).encode("utf-8")
            info = tarfile.TarInfo(name="manifest.json")
            info.size = len(manifest_bytes)
            info.mtime = ts
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(manifest_bytes))

        archive_bytes = buf.getvalue()
        archive_path.write_bytes(archive_bytes)
        archive_sha = _sha256_bytes(archive_bytes)
        return {
            "engagement_id": engagement_id,
            "path":          str(archive_path),
            "name":          archive_name,
            "size":          len(archive_bytes),
            "sha256":        archive_sha,
            "captured_at":   manifest["captured_at"],
            "captured_by":   manifest["captured_by"],
            "members":       len(manifest["members"]),
            "note":          note or "",
        }

    # ----- listing for the dashboard ----------------------------------

    def list_for(self, engagement_id: str) -> list[dict[str, Any]]:
        """Return existing snapshots for an engagement, newest first.
        Each entry has `name`, `path`, `size`, `mtime` — enough for the
        dashboard's snapshot-list footer panel without parsing the
        archive itself."""
        out: list[dict[str, Any]] = []
        prefix = f"{engagement_id}-"
        if not self.snapshot_dir.exists():
            return out
        for p in self.snapshot_dir.glob(f"{prefix}*.tar.gz"):
            try:
                stat = p.stat()
            except OSError:
                continue
            out.append({
                "name":  p.name,
                "path":  str(p),
                "size":  stat.st_size,
                "mtime": stat.st_mtime,
            })
        out.sort(key=lambda d: d["mtime"], reverse=True)
        return out

# --- default singleton --------------------------------------------------

_DEFAULT_WRITER: SnapshotWriter | None = None

def default_writer() -> SnapshotWriter:
    global _DEFAULT_WRITER
    if _DEFAULT_WRITER is None:
        root = Path(__file__).resolve().parent.parent
        if (root / "state-docker").exists():
            base = root / "state-docker"
        else:
            base = root / "state"
        _DEFAULT_WRITER = SnapshotWriter(base)
    return _DEFAULT_WRITER

def reset_default_writer_for_tests(root: Path | str) -> SnapshotWriter:
    global _DEFAULT_WRITER
    _DEFAULT_WRITER = SnapshotWriter(root)
    return _DEFAULT_WRITER
