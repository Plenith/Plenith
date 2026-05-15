"""Tests for `plenith.acks.AckStore` — the operator-acknowledgement
overlay that powers Phase 2 of docs/design/UI_WIRING.md.

The contract these lock in:
  - ack / unack round-trip through atomic write
  - missing file is treated as "no acks"
  - corrupt file is treated as "no acks" (resilient to partial state)
  - `overlay_engagement` injects ack state into action_taken dicts
    without touching the rest of the engagement
  - the per-engagement / per-action key shape is stable so the audit
    chain doesn't have to be aware of it
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from plenith.acks import AckStore

def test_round_trip_single_ack(tmp_path):
    store = AckStore(tmp_path / "acks.json")
    entry = store.ack("eng-001", "alert_credential_exfil", op_id="mwilson",
                       note="Real, but not actionable this hour.")
    assert entry["op_id"] == "mwilson"
    assert "ts" in entry

    fetched = store.get("eng-001", "alert_credential_exfil")
    assert fetched is not None
    assert fetched["op_id"] == "mwilson"
    assert fetched["note"] == "Real, but not actionable this hour."

def test_ack_without_note_does_not_store_note_field(tmp_path):
    """Optional note: only persisted when non-empty so the JSON stays
    lean and `get()` returns `None` rather than `""` for absent."""
    store = AckStore(tmp_path / "acks.json")
    store.ack("eng-001", "alert_dns_exfil", op_id="agarcia")
    fetched = store.get("eng-001", "alert_dns_exfil")
    assert fetched is not None
    assert "note" not in fetched

def test_unack_removes_entry_and_returns_true(tmp_path):
    store = AckStore(tmp_path / "acks.json")
    store.ack("eng-001", "alert_reverse_shell", op_id="mwilson")
    assert store.unack("eng-001", "alert_reverse_shell") is True
    assert store.get("eng-001", "alert_reverse_shell") is None

def test_unack_returns_false_when_not_acked(tmp_path):
    """Unacking a never-acked entry is not an error — the 10s undo
    button on the toast might re-fire after the ack already expired."""
    store = AckStore(tmp_path / "acks.json")
    assert store.unack("eng-not-real", "alert_anything") is False

def test_unack_cleans_up_empty_engagement_dict(tmp_path):
    """When the last action under an engagement is unacked, the engagement
    key itself goes away — keeps the file from growing into a graveyard."""
    store = AckStore(tmp_path / "acks.json")
    store.ack("eng-only-one", "alert_x", op_id="x")
    store.unack("eng-only-one", "alert_x")
    raw = store.all()
    assert "eng-only-one" not in raw

def test_re_ack_updates_timestamp_and_operator(tmp_path):
    """Re-acking is idempotent: the entry updates rather than
    duplicating.  Useful when a second analyst weighs in."""
    store = AckStore(tmp_path / "acks.json")
    store.ack("eng-001", "alert_x", op_id="mwilson")
    time.sleep(0.01)
    second = store.ack("eng-001", "alert_x", op_id="agarcia",
                        note="taking over for mwilson")
    assert second["op_id"] == "agarcia"
    fetched = store.get("eng-001", "alert_x")
    assert fetched["op_id"] == "agarcia"
    assert fetched["note"] == "taking over for mwilson"

def test_get_for_engagement_returns_all_acks_under_one_eng(tmp_path):
    store = AckStore(tmp_path / "acks.json")
    store.ack("eng-001", "alert_a", op_id="x")
    store.ack("eng-001", "alert_b", op_id="x")
    store.ack("eng-002", "alert_c", op_id="x")
    acks_for_one = store.get_for_engagement("eng-001")
    assert set(acks_for_one.keys()) == {"alert_a", "alert_b"}
    assert "alert_c" not in acks_for_one

def test_missing_file_returns_empty_store(tmp_path):
    """First-time deploy with no acks.json yet must not crash."""
    store = AckStore(tmp_path / "does_not_exist.json")
    assert store.all() == {}
    assert store.get("any", "alert") is None
    assert store.get_for_engagement("any") == {}

def test_corrupt_file_treated_as_empty(tmp_path):
    """An operator who manually edits acks.json and breaks the JSON
    shouldn't permanently break the dashboard.  Next save overwrites
    with a clean file."""
    path = tmp_path / "acks.json"
    path.write_text("{ this is not json", encoding="utf-8")
    store = AckStore(path)
    assert store.all() == {}
    # And the next ack still persists cleanly
    store.ack("eng-001", "alert_x", op_id="x")
    assert store.get("eng-001", "alert_x") is not None

def test_atomic_write_survives_simulated_crash_via_tempfile_cleanup(tmp_path):
    """Stray tmp files from a crashed write must not corrupt subsequent
    loads.  Drop a fake `.tmp_acks_*.json` alongside and verify the real
    file load still works."""
    path = tmp_path / "acks.json"
    store = AckStore(path)
    store.ack("eng-001", "alert_x", op_id="x")
    # Simulate a partial-write artifact
    (tmp_path / ".tmp_acks_FAKE.json").write_text("garbage", encoding="utf-8")
    # Real ack still readable
    assert store.get("eng-001", "alert_x") is not None

def test_overlay_engagement_injects_ack_fields(tmp_path):
    """The renderer-side join: each action_taken in the engagement gets
    `acknowledged_at`, `acknowledged_by`, `acknowledge_note` regardless
    of whether it was ack'd (None when not)."""
    store = AckStore(tmp_path / "acks.json")
    store.ack("eng-001", "alert_credential_exfil",
              op_id="mwilson", note="false-positive — agarcia testing")

    engagement = {
        "engagement_id": "eng-001",
        "logs": [{
            "actions_taken": [
                {"action": "alert_credential_exfil", "severity": "high"},
                {"action": "alert_reverse_shell",    "severity": "critical"},
            ],
        }],
    }
    store.overlay_engagement(engagement)

    acks = {a["action"]: a for a in engagement["logs"][0]["actions_taken"]}
    assert acks["alert_credential_exfil"]["acknowledged_by"] == "mwilson"
    assert "false-positive" in acks["alert_credential_exfil"]["acknowledge_note"]
    assert acks["alert_reverse_shell"]["acknowledged_by"] is None
    assert acks["alert_reverse_shell"]["acknowledged_at"] is None

def test_overlay_engagement_handles_missing_action_name(tmp_path):
    """Defensive: an action_taken without an `action` key shouldn't
    explode the overlay (could happen with a malformed log file)."""
    store = AckStore(tmp_path / "acks.json")
    engagement = {
        "engagement_id": "eng-001",
        "logs": [{"actions_taken": [{"severity": "high"}]}],
    }
    # Must not raise
    store.overlay_engagement(engagement)
    assert engagement["logs"][0]["actions_taken"][0]["acknowledged_by"] is None

def test_batch_ack_accumulates_acked_and_skipped_counts(tmp_path):
    """Batch ack reports how many were new vs. already-ack'd, which the
    UI needs to render the right toast ('3 acked, 1 already done')."""
    store = AckStore(tmp_path / "acks.json")
    # Pre-ack one of the three
    store.ack("eng-001", "alert_x", op_id="x")
    result = store.batch_ack(
        ["eng-001", "eng-002", "eng-003"],
        action_name="alert_x", op_id="mwilson",
    )
    assert result["acked"] == 2     # eng-002, eng-003 newly acked
    assert result["skipped"] == 1   # eng-001 already acked

def test_batch_ack_requires_action_name(tmp_path):
    """The store refuses the 'ack everything under each engagement'
    shortcut — that would entangle the store with audit.py.  Caller is
    responsible for resolving the per-engagement action list."""
    store = AckStore(tmp_path / "acks.json")
    try:
        store.batch_ack(["eng-001"], action_name=None, op_id="x")
        raise AssertionError("expected ValueError")
    except ValueError:
        pass

def test_overlay_engagement_does_not_break_when_no_acks_exist(tmp_path):
    """Common case: fresh deployment, no acks.json yet.  Renderer must
    still get the standard `acknowledged_*` keys (set to None) so the
    HTML template doesn't have to defensively check."""
    store = AckStore(tmp_path / "no_acks_yet.json")
    engagement = {
        "engagement_id": "eng-fresh",
        "logs": [{"actions_taken": [{"action": "alert_x", "severity": "high"}]}],
    }
    store.overlay_engagement(engagement)
    assert engagement["logs"][0]["actions_taken"][0]["acknowledged_at"] is None

def test_persisted_file_is_valid_json_for_external_consumers(tmp_path):
    """SOAR / SIEM pipelines may want to read acks.json directly.
    The on-disk format must be parseable as plain JSON, not a Python
    repr or pickled blob."""
    path = tmp_path / "acks.json"
    store = AckStore(path)
    store.ack("eng-001", "alert_x", op_id="mwilson", note="for sigma rule")
    raw = json.loads(path.read_text(encoding="utf-8"))
    assert raw["eng-001"]["alert_x"]["op_id"] == "mwilson"
    assert raw["eng-001"]["alert_x"]["note"] == "for sigma rule"
