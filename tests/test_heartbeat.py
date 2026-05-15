"""Tests for the agent heartbeat back-channel."""
import asyncio
import json
import time
from pathlib import Path

import pytest

from plenith.heartbeat import (
    AgentHealth,
    HeartbeatWriter,
    _classify,
    read_all_heartbeats,
)

# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------

class TestHeartbeatWriter:
    def test_write_once_creates_file(self, tmp_path):
        w = HeartbeatWriter(
            state_dir=tmp_path,
            hostname="bastion-prod",
            persona="agarcia",
            deployment_id="dep-1",
            content_epoch="2026Q2",
        )
        w.write_once()
        p = tmp_path / "heartbeats" / "bastion-prod.json"
        assert p.exists()
        data = json.loads(p.read_text(encoding="utf-8"))
        assert data["hostname"] == "bastion-prod"
        assert data["persona"] == "agarcia"
        assert "last_beat" in data
        assert "started_at" in data

    def test_atomic_write_uses_tmp_rename(self, tmp_path):
        """We rename a .tmp file in place — no partial writes visible."""
        w = HeartbeatWriter(state_dir=tmp_path, hostname="x")
        w.write_once()
        # After the rename, no .tmp file should remain
        assert not any(tmp_path.glob("heartbeats/*.tmp"))

    @pytest.mark.asyncio
    async def test_run_loop_writes_periodically(self, tmp_path):
        w = HeartbeatWriter(
            state_dir=tmp_path, hostname="db-prod-01",
            interval_seconds=0.05,
        )
        await w.start()
        await asyncio.sleep(0.18)   # ~3 beats
        await w.stop()
        p = tmp_path / "heartbeats" / "db-prod-01.json"
        assert p.exists()

    @pytest.mark.asyncio
    async def test_stop_writes_stopping_status(self, tmp_path):
        w = HeartbeatWriter(state_dir=tmp_path, hostname="x",
                              interval_seconds=0.1)
        await w.start()
        await asyncio.sleep(0.12)
        await w.stop()
        data = json.loads((tmp_path / "heartbeats" / "x.json").read_text(
            encoding="utf-8"))
        assert data.get("status") == "stopping"

# ---------------------------------------------------------------------------
# Reader
# ---------------------------------------------------------------------------

class TestReader:
    def test_empty_dir_returns_empty(self, tmp_path):
        assert read_all_heartbeats(tmp_path) == []

    def test_no_heartbeats_subdir(self, tmp_path):
        assert read_all_heartbeats(tmp_path / "nonexistent") == []

    def test_reads_synthetic_beat(self, tmp_path):
        hb_dir = tmp_path / "heartbeats"
        hb_dir.mkdir()
        now = time.time()
        (hb_dir / "bastion.json").write_text(json.dumps({
            "hostname":   "bastion",
            "persona":    "agarcia",
            "version":    "1.0.0",
            "started_at": now - 60,
            "last_beat":  now - 5,
            "engagements_open": 2,
            "engagements_total_since_start": 7,
            "deployment_id": "dep-1",
            "content_epoch": "2026Q2",
        }), encoding="utf-8")
        records = read_all_heartbeats(tmp_path, now=now)
        assert len(records) == 1
        r = records[0]
        assert r.hostname == "bastion"
        assert r.status == "healthy"      # 5s old < 30s stale threshold
        assert r.engagements_open == 2

    def test_stale_beat_marked_degraded(self, tmp_path):
        hb_dir = tmp_path / "heartbeats"
        hb_dir.mkdir()
        now = time.time()
        (hb_dir / "x.json").write_text(json.dumps({
            "hostname": "x", "last_beat": now - 45,    # > 30s stale
        }), encoding="utf-8")
        records = read_all_heartbeats(tmp_path, now=now)
        assert records[0].status == "degraded"

    def test_very_stale_beat_marked_down(self, tmp_path):
        hb_dir = tmp_path / "heartbeats"
        hb_dir.mkdir()
        now = time.time()
        (hb_dir / "x.json").write_text(json.dumps({
            "hostname": "x", "last_beat": now - 120,   # > 90s down
        }), encoding="utf-8")
        records = read_all_heartbeats(tmp_path, now=now)
        assert records[0].status == "down"

    def test_stopping_status_preserved(self, tmp_path):
        hb_dir = tmp_path / "heartbeats"
        hb_dir.mkdir()
        now = time.time()
        (hb_dir / "x.json").write_text(json.dumps({
            "hostname": "x", "last_beat": now - 5, "status": "stopping",
        }), encoding="utf-8")
        records = read_all_heartbeats(tmp_path, now=now)
        assert records[0].status == "stopping"

    def test_corrupt_file_skipped(self, tmp_path):
        hb_dir = tmp_path / "heartbeats"
        hb_dir.mkdir()
        (hb_dir / "good.json").write_text(
            json.dumps({"hostname": "good", "last_beat": time.time()}),
            encoding="utf-8",
        )
        (hb_dir / "bad.json").write_text("not json", encoding="utf-8")
        records = read_all_heartbeats(tmp_path)
        # Bad file silently skipped; good file makes it through
        assert len(records) == 1
        assert records[0].hostname == "good"

    def test_to_dict_round_trip(self, tmp_path):
        ah = AgentHealth(
            hostname="x", persona="y", version="z", started_at=0,
            last_beat=0, age_seconds=0, status="healthy",
            engagements_open=0, engagements_total_since_start=0,
            deployment_id="", content_epoch="",
        )
        d = ah.to_dict()
        assert d["hostname"] == "x"
        assert d["status"] == "healthy"

class TestClassify:
    def test_thresholds(self):
        assert _classify(0,   None, stale=30, down=90) == "healthy"
        assert _classify(15,  None, stale=30, down=90) == "healthy"
        assert _classify(35,  None, stale=30, down=90) == "degraded"
        assert _classify(100, None, stale=30, down=90) == "down"

    def test_stopping_overrides(self):
        # A "stopping" status flag always wins
        assert _classify(0, "stopping", stale=30, down=90) == "stopping"
