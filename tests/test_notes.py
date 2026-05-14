"""Tests for `plenith.notes.NotesStore` — Phase 3 of UI_WIRING.md.

Same contract approach as test_acks.py:
  - round-trip add/list/delete through atomic write
  - missing or corrupt file = empty store, never crash
  - notes are append-only (no edit operation) — deletion by uuid only
  - newest-first ordering for the dashboard's note list
  - the overlay_engagement join shape the dashboard depends on
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from plenith.notes import NotesStore


def test_add_returns_note_with_uuid_and_timestamp(tmp_path):
    store = NotesStore(tmp_path / "notes.json")
    note = store.add("eng-001", "Watching this one, not urgent.",
                      author="mwilson")
    assert note["author"] == "mwilson"
    assert note["body"] == "Watching this one, not urgent."
    assert isinstance(note["id"], str) and len(note["id"]) >= 16
    assert note["ts"] > 0


def test_add_strips_whitespace_in_body(tmp_path):
    store = NotesStore(tmp_path / "notes.json")
    note = store.add("eng-001", "  trailing space  \n",
                      author="mwilson")
    assert note["body"] == "trailing space"


def test_add_rejects_empty_body(tmp_path):
    """Empty notes are an operator typo, not a real note.  Refuse
    rather than persist garbage."""
    store = NotesStore(tmp_path / "notes.json")
    with pytest.raises(ValueError):
        store.add("eng-001", "", author="mwilson")
    with pytest.raises(ValueError):
        store.add("eng-001", "   \n  ", author="mwilson")


def test_add_defaults_author_to_anonymous(tmp_path):
    """Open-mode deployments have no analyst identity; notes still work."""
    store = NotesStore(tmp_path / "notes.json")
    note = store.add("eng-001", "spotted by IDS-anon")
    assert note["author"] == "anonymous"


def test_list_returns_newest_first(tmp_path):
    store = NotesStore(tmp_path / "notes.json")
    first  = store.add("eng-001", "first note",  author="agarcia")
    time.sleep(0.01)
    second = store.add("eng-001", "second note", author="mwilson")
    notes = store.list("eng-001")
    assert len(notes) == 2
    assert notes[0]["id"] == second["id"]
    assert notes[1]["id"] == first["id"]


def test_list_empty_for_engagement_with_no_notes(tmp_path):
    """Renderer iterates over `store.list(eid)` directly; must be a list
    (so a for-loop works), never None."""
    store = NotesStore(tmp_path / "notes.json")
    assert store.list("eng-never-noted") == []


def test_delete_by_id_returns_true_when_found(tmp_path):
    store = NotesStore(tmp_path / "notes.json")
    note = store.add("eng-001", "to delete", author="x")
    assert store.delete("eng-001", note["id"]) is True
    assert store.list("eng-001") == []


def test_delete_returns_false_when_not_found(tmp_path):
    store = NotesStore(tmp_path / "notes.json")
    assert store.delete("eng-001", "nonexistent-uuid") is False


def test_delete_keeps_sibling_notes_intact(tmp_path):
    store = NotesStore(tmp_path / "notes.json")
    keeper  = store.add("eng-001", "keep me", author="x")
    deleter = store.add("eng-001", "delete me", author="x")
    store.delete("eng-001", deleter["id"])
    remaining = store.list("eng-001")
    assert len(remaining) == 1
    assert remaining[0]["id"] == keeper["id"]


def test_delete_cleans_up_empty_engagement_dict(tmp_path):
    """Last note removed → the engagement key disappears from the
    overlay file."""
    store = NotesStore(tmp_path / "notes.json")
    note = store.add("eng-only-one", "lone note", author="x")
    store.delete("eng-only-one", note["id"])
    raw = store.all()
    assert "eng-only-one" not in raw


def test_count_returns_right_number(tmp_path):
    store = NotesStore(tmp_path / "notes.json")
    assert store.count("eng-001") == 0
    store.add("eng-001", "a", author="x")
    store.add("eng-001", "b", author="x")
    assert store.count("eng-001") == 2


def test_missing_file_treated_as_empty(tmp_path):
    store = NotesStore(tmp_path / "does_not_exist.json")
    assert store.list("any") == []
    assert store.count("any") == 0


def test_corrupt_file_treated_as_empty(tmp_path):
    path = tmp_path / "notes.json"
    path.write_text("{ this is not json", encoding="utf-8")
    store = NotesStore(path)
    assert store.all() == {}
    # And the next add still persists
    store.add("eng-001", "after corruption", author="x")
    assert store.count("eng-001") == 1


def test_overlay_engagement_attaches_notes_list(tmp_path):
    store = NotesStore(tmp_path / "notes.json")
    store.add("eng-001", "first",  author="agarcia")
    store.add("eng-001", "second", author="mwilson")
    engagement = {"engagement_id": "eng-001"}
    store.overlay_engagement(engagement)
    assert isinstance(engagement["notes"], list)
    assert len(engagement["notes"]) == 2
    assert engagement["notes"][0]["author"] in ("agarcia", "mwilson")


def test_overlay_engagement_handles_missing_engagement_id(tmp_path):
    """Defensive: malformed engagement dict shouldn't crash the overlay
    (the renderer might be mid-update when SSE fires)."""
    store = NotesStore(tmp_path / "notes.json")
    engagement = {"no_id": "weird"}
    store.overlay_engagement(engagement)
    assert engagement["notes"] == []


def test_persisted_file_is_valid_json(tmp_path):
    """SOAR or compliance audit may read notes.json directly."""
    path = tmp_path / "notes.json"
    store = NotesStore(path)
    store.add("eng-001", "**bold** note with `code`", author="mwilson")
    raw = json.loads(path.read_text(encoding="utf-8"))
    assert raw["eng-001"][0]["body"] == "**bold** note with `code`"
    assert raw["eng-001"][0]["author"] == "mwilson"


def test_notes_persist_across_store_instances(tmp_path):
    """Two store instances pointing at the same file must see each
    other's writes — this is the dashboard ↔ API cross-process case."""
    path = tmp_path / "notes.json"
    store_a = NotesStore(path)
    store_b = NotesStore(path)
    note = store_a.add("eng-001", "from A", author="agarcia")
    assert store_b.list("eng-001")[0]["id"] == note["id"]
    store_b.delete("eng-001", note["id"])
    assert store_a.list("eng-001") == []
