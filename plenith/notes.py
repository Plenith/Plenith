"""Operator-note overlay — Phase 3 of docs/design/UI_WIRING.md.

Analysts can pin markdown notes to an engagement so the next analyst on
shift has context.  Like `plenith.acks`, the notes live in a separate
overlay file (`state-docker/notes.json`) rather than mutating the
forensic engagement logs.

Schema (multiple notes per engagement, ordered newest-first):

    {
      "<engagement_id>": [
        {
          "id":      "<uuid4>",
          "author":  "<op_id, default 'anonymous'>",
          "ts":      <utc epoch float>,
          "body":    "<markdown text>"
        },
        ...
      ],
      ...
    }

Notes are immutable once posted — there's no "edit" operation, only
add and delete-by-id.  This keeps the forensic record append-only and
avoids the "who changed what when" complications that a mutable note
would require.

Atomic write-then-rename, same pattern as `acks.py` and `state_store.py`.
Reads are best-effort: missing/corrupt files yield an empty store.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any
import builtins

class NotesStore:
    """Single-file notes overlay.

    Append-only via `add()`; the only mutation that removes data is
    `delete()` keyed by note id.  This shape matches the prototype's
    note-list-on-the-detail-page UX and keeps note history compact.
    """

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    # ----- raw load/save ----------------------------------------------

    def _load_raw(self) -> dict[str, builtins.list[dict[str, Any]]]:
        if not self.path.exists():
            return {}
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                # Normalize: every value must be a list
                return {k: (v if isinstance(v, list) else [])
                        for k, v in data.items()}
            return {}
        except (OSError, json.JSONDecodeError):
            return {}

    def _atomic_write(self, data: dict[str, Any]) -> None:
        fd, tmp_path = tempfile.mkstemp(
            prefix=".tmp_notes_", suffix=".json",
            dir=str(self.path.parent),
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str, sort_keys=True)
            os.replace(tmp_path, str(self.path))
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    # ----- public API -------------------------------------------------

    def add(self, engagement_id: str, body: str,
             author: str = "anonymous") -> dict[str, Any]:
        """Append a note.  Returns the recorded note shape with a fresh
        UUID so the caller can echo back to the operator (and use as the
        delete-key)."""
        body = (body or "").strip()
        if not body:
            raise ValueError("note body must be non-empty")
        note = {
            "id":     uuid.uuid4().hex,
            "author": author or "anonymous",
            "ts":     time.time(),
            "body":   body,
        }
        data = self._load_raw()
        data.setdefault(engagement_id, []).append(note)
        self._atomic_write(data)
        return note

    def list(self, engagement_id: str) -> builtins.list[dict[str, Any]]:
        """Return all notes for one engagement, newest first.  Empty
        list when none exist — never None."""
        notes = list(self._load_raw().get(engagement_id, []))
        notes.sort(key=lambda n: n.get("ts", 0), reverse=True)
        return notes

    def delete(self, engagement_id: str, note_id: str) -> bool:
        """Remove a note by id.  Returns True if found+removed, False
        otherwise (idempotent — re-delete is a no-op)."""
        data = self._load_raw()
        notes = data.get(engagement_id, [])
        new_notes = [n for n in notes if n.get("id") != note_id]
        if len(new_notes) == len(notes):
            return False
        if new_notes:
            data[engagement_id] = new_notes
        else:
            data.pop(engagement_id, None)
        self._atomic_write(data)
        return True

    def all(self) -> dict[str, builtins.list[dict[str, Any]]]:
        """Full overlay — snapshot, caller can mutate without affecting
        the store."""
        return self._load_raw()

    def count(self, engagement_id: str) -> int:
        """Cheap count without loading the full list into the caller."""
        return len(self._load_raw().get(engagement_id, []))

    # ----- render-time overlay join -----------------------------------

    def overlay_engagement(self, engagement: dict[str, Any]) -> dict[str, Any]:
        """Attach the notes list to an engagement dict for the renderer.
        Adds the `notes` key (a list, sorted newest-first), mutates the
        dict in place, and returns it for chaining."""
        eid = engagement.get("engagement_id")
        if not eid:
            engagement["notes"] = []
            return engagement
        engagement["notes"] = self.list(eid)
        return engagement

# --- default singleton --------------------------------------------------

_DEFAULT_STORE: NotesStore | None = None

def default_store() -> NotesStore:
    """Process-wide NotesStore at the conventional location.  Same
    fallback rule as `plenith.acks.default_store` — `state-docker/`
    when it exists, `state/` otherwise."""
    global _DEFAULT_STORE
    if _DEFAULT_STORE is None:
        root = Path(__file__).resolve().parent.parent
        if (root / "state-docker").exists():
            base = root / "state-docker"
        else:
            base = root / "state"
        _DEFAULT_STORE = NotesStore(base / "notes.json")
    return _DEFAULT_STORE

def reset_default_store_for_tests(path: Path | str) -> NotesStore:
    global _DEFAULT_STORE
    _DEFAULT_STORE = NotesStore(path)
    return _DEFAULT_STORE
