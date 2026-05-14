"""Tests for `plenith.kill_queue.KillRequestQueue` — Phase 3 of UI_WIRING.md.

The queue is the contract between the dashboard/API (which records a
kill request) and the orchestrator (which polls + acts on it).  These
tests lock both sides of that contract.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from plenith.kill_queue import KillRequestQueue


def test_request_kill_adds_pending_entry(tmp_path):
    q = KillRequestQueue(tmp_path / "kill.json")
    entry = q.request_kill("eng-001", requested_by="mwilson",
                            reason="active reverse shell")
    assert entry["status"] == "pending"
    assert entry["requested_by"] == "mwilson"
    assert entry["reason"] == "active reverse shell"
    assert "eng-001" in q.pending()


def test_request_kill_is_idempotent(tmp_path):
    """Re-requesting a pending kill must not duplicate the entry or
    reset the requested_at timestamp (the dashboard's 'pending for X
    seconds' counter would jump back to 0)."""
    q = KillRequestQueue(tmp_path / "kill.json")
    first = q.request_kill("eng-001", requested_by="mwilson")
    time.sleep(0.05)
    second = q.request_kill("eng-001", requested_by="agarcia",
                              reason="updated reason")
    # requested_at preserved from the first call
    assert second["requested_at"] == first["requested_at"]
    # but the operator + reason are updated
    assert second["requested_by"] == "agarcia"
    assert second["reason"] == "updated reason"


def test_cancel_removes_pending_request(tmp_path):
    q = KillRequestQueue(tmp_path / "kill.json")
    q.request_kill("eng-001", requested_by="x")
    assert q.cancel("eng-001") is True
    assert "eng-001" not in q.pending()


def test_cancel_returns_false_when_no_pending(tmp_path):
    q = KillRequestQueue(tmp_path / "kill.json")
    assert q.cancel("eng-never-requested") is False


def test_cancel_does_not_remove_killed_entries(tmp_path):
    """Once an entry is 'killed', it stays in the file for ~24h so the
    dashboard can show 'killed 3m ago'.  cancel() on a killed entry is
    a no-op."""
    q = KillRequestQueue(tmp_path / "kill.json")
    q.request_kill("eng-001", requested_by="x")
    q.mark_killed("eng-001")
    assert q.cancel("eng-001") is False
    entry = q.get("eng-001")
    assert entry is not None
    assert entry["status"] == "killed"


def test_mark_killed_flips_status_and_records_killed_at(tmp_path):
    q = KillRequestQueue(tmp_path / "kill.json")
    q.request_kill("eng-001", requested_by="x")
    assert q.mark_killed("eng-001") is True
    entry = q.get("eng-001")
    assert entry["status"]    == "killed"
    assert entry["killed_at"] >= entry["requested_at"]
    # No longer in the pending list
    assert "eng-001" not in q.pending()


def test_mark_killed_returns_false_for_unknown_engagement(tmp_path):
    q = KillRequestQueue(tmp_path / "kill.json")
    assert q.mark_killed("eng-unknown") is False


def test_pending_returns_only_pending_status_entries(tmp_path):
    q = KillRequestQueue(tmp_path / "kill.json")
    q.request_kill("eng-001", requested_by="x")
    q.request_kill("eng-002", requested_by="x")
    q.request_kill("eng-003", requested_by="x")
    q.mark_killed("eng-002")
    pending = q.pending()
    assert set(pending) == {"eng-001", "eng-003"}


def test_gc_drops_killed_entries_older_than_24h(tmp_path):
    """The file is garbage-collected on every mutation: completed kill
    requests older than the TTL drop off the end.  Forces a fresh
    operator never sees stale entries from last week."""
    path = tmp_path / "kill.json"
    q = KillRequestQueue(path)
    # Manually plant a stale killed entry
    long_ago = time.time() - 90000   # ~25h
    path.write_text(json.dumps({
        "eng-stale": {
            "requested_at": long_ago,
            "requested_by": "ghost",
            "status":       "killed",
            "killed_at":    long_ago + 1,
        },
        "eng-fresh": {
            "requested_at": time.time(),
            "requested_by": "mwilson",
            "status":       "pending",
        },
    }), encoding="utf-8")
    # Any mutation triggers GC
    q.request_kill("eng-new", requested_by="x")
    raw = q.all()
    assert "eng-stale" not in raw          # GC'd
    assert "eng-fresh" in raw              # still pending
    assert "eng-new"   in raw              # newly requested


def test_pending_is_empty_when_no_requests(tmp_path):
    q = KillRequestQueue(tmp_path / "kill.json")
    assert q.pending() == []


def test_missing_file_treated_as_empty_queue(tmp_path):
    q = KillRequestQueue(tmp_path / "missing.json")
    assert q.pending() == []
    assert q.get("any-eng") is None


def test_corrupt_file_treated_as_empty(tmp_path):
    path = tmp_path / "kill.json"
    path.write_text("not json", encoding="utf-8")
    q = KillRequestQueue(path)
    assert q.pending() == []
    # And the next request still succeeds
    q.request_kill("eng-001", requested_by="x")
    assert "eng-001" in q.pending()


def test_persisted_file_is_valid_json(tmp_path):
    """Operators may grep / parse this file directly to debug an
    apparently-stuck orchestrator."""
    path = tmp_path / "kill.json"
    q = KillRequestQueue(path)
    q.request_kill("eng-001", requested_by="mwilson",
                    reason="ngrok exfil in progress")
    raw = json.loads(path.read_text(encoding="utf-8"))
    assert raw["eng-001"]["requested_by"] == "mwilson"
    assert raw["eng-001"]["reason"] == "ngrok exfil in progress"
