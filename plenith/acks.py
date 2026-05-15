"""Operator-acknowledgement overlay.

When an analyst clicks "Acknowledge" on an alert, we DON'T mutate the
per-engagement session log (`state-docker/logs/<host>/<id>.json`) —
those files are the forensic record and a separate audit-chain
(`plenith/audit_chain.py`) hashes them.  Mutation breaks integrity and
undermines the "tamper-evident logs" claim.

Instead we keep a single overlay file (`state-docker/acks.json` by
default) keyed by `(engagement_id, action_name)`.  The audit/dashboard
renderers join engagement logs with the overlay at read time and surface
ack state per action.

Schema:

    {
      "<engagement_id>": {
        "<action_name>": {
          "ts":     <utc epoch float>,
          "op_id":  "<analyst id, e.g. mwilson, or 'anonymous' in open-mode>",
          "note":   "<optional context, markdown allowed>"
        },
        ...
      },
      ...
    }

Operations are atomic write-then-rename (same pattern as
`state_store.py`).  Reads are best-effort: a missing or corrupt file is
treated as "no acks yet" — the dashboard renders cleanly and the next
ack/unack rewrites a fresh file.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any

class AckStore:
    """Single-file ack overlay.

    Thread-safe for the common pattern (one Python process per dashboard
    or API server) because every mutation goes through `_atomic_write`.
    Two processes mutating the same file simultaneously is undefined —
    operators running both `dashboard.py` and `api/server.py` against
    the same `state-docker/` should be aware of last-writer-wins.

    The store is intentionally tolerant of partial / corrupt state so
    an analyst's mistype can't lock them out: load returns `{}` on any
    parse error, and the next save overwrites cleanly.
    """

    def __init__(self, path: Path | str):
        self.path = Path(path)
        # Create parent directory if missing so `save` always succeeds
        # on a fresh deployment.
        self.path.parent.mkdir(parents=True, exist_ok=True)

    # ----- raw load/save ----------------------------------------------

    def _load_raw(self) -> dict[str, dict[str, dict[str, Any]]]:
        """Return the raw nested dict, or `{}` if the file is missing
        or unreadable."""
        if not self.path.exists():
            return {}
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
            return {}
        except (OSError, json.JSONDecodeError):
            return {}

    def _atomic_write(self, data: dict[str, Any]) -> None:
        """Write-then-rename atomic save to `self.path`."""
        fd, tmp_path = tempfile.mkstemp(
            prefix=".tmp_acks_", suffix=".json",
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

    def ack(self, engagement_id: str, action_name: str,
             op_id: str = "anonymous", note: str = "") -> dict[str, Any]:
        """Record an acknowledgement.  Idempotent — re-acking the same
        (engagement, action) updates the timestamp + operator + note.

        Returns the recorded entry shape so callers can echo it back
        to the operator as confirmation."""
        data = self._load_raw()
        entry = {
            "ts":    time.time(),
            "op_id": op_id or "anonymous",
        }
        if note:
            entry["note"] = note
        data.setdefault(engagement_id, {})[action_name] = entry
        self._atomic_write(data)
        return entry

    def unack(self, engagement_id: str, action_name: str) -> bool:
        """Remove an acknowledgement.  Returns True if anything was
        removed, False if the (engagement, action) wasn't ack'd to
        begin with — both are valid, callers shouldn't error on
        unack-of-not-acked.

        Used by the 10-second undo button on the toast pop-up."""
        data = self._load_raw()
        eng = data.get(engagement_id)
        if not eng or action_name not in eng:
            return False
        del eng[action_name]
        # Tidy: drop the engagement entry if it's now empty
        if not eng:
            data.pop(engagement_id, None)
        self._atomic_write(data)
        return True

    def get(self, engagement_id: str,
             action_name: str) -> dict[str, Any] | None:
        """Return the ack entry for (engagement, action), or None."""
        return self._load_raw().get(engagement_id, {}).get(action_name)

    def get_for_engagement(self, engagement_id: str) -> dict[str, dict[str, Any]]:
        """All acks for one engagement, keyed by action_name."""
        return dict(self._load_raw().get(engagement_id, {}))

    def all(self) -> dict[str, dict[str, dict[str, Any]]]:
        """Full nested overlay.  Snapshot — caller can mutate without
        affecting the store."""
        return self._load_raw()

    # ----- batch ------------------------------------------------------

    def batch_ack(self, engagement_ids: list[str],
                   action_name: str | None = None,
                   op_id: str = "anonymous", note: str = "") -> dict[str, int]:
        """Ack many engagements at once.  If `action_name` is None,
        acknowledges *every* action currently recorded under each
        engagement (caller is responsible for joining with the session
        logs first so we know which actions exist).

        This signature accepts the action_name=None form for the
        "Acknowledge all" batch button on the engagement list popout;
        the dashboard pre-resolves the per-engagement action list and
        passes specific names to keep the API self-contained.

        Returns `{acked: int, skipped: int}` so the UI can show a
        confirmation toast with the actual count."""
        if action_name is None:
            # Callers must specify the action.  Otherwise the store
            # would have to walk every session log itself, which
            # entangles it with audit.py.  Fail loudly.
            raise ValueError(
                "batch_ack requires an explicit action_name; the caller "
                "is responsible for resolving per-engagement actions "
                "from the session logs."
            )
        data = self._load_raw()
        acked = 0
        skipped = 0
        for eid in engagement_ids:
            existing = data.get(eid, {}).get(action_name)
            entry = {"ts": time.time(), "op_id": op_id or "anonymous"}
            if note:
                entry["note"] = note
            data.setdefault(eid, {})[action_name] = entry
            if existing is None:
                acked += 1
            else:
                skipped += 1   # already ack'd; we still update ts
        self._atomic_write(data)
        return {"acked": acked, "skipped": skipped}

    # ----- render-time overlay join -----------------------------------

    def overlay_engagement(self, engagement: dict[str, Any]) -> dict[str, Any]:
        """Mutate an engagement dict (as returned by
        `audit.load_engagements`) to inject ack state on each
        action_taken across all logs.

        Adds three keys to each action: `acknowledged_at`,
        `acknowledged_by`, `acknowledge_note`.  Missing acks → all None.

        Returns the same dict for chaining; mutation is in-place because
        the dashboard already passes mutable copies through several
        render functions and copying again costs without benefit."""
        eid = engagement.get("engagement_id")
        if not eid:
            return engagement
        eng_acks = self._load_raw().get(eid, {})
        for log in engagement.get("logs", []) or []:
            for action in log.get("actions_taken", []):
                name = action.get("action")
                ack = eng_acks.get(name) if name else None
                if ack:
                    action["acknowledged_at"]   = ack["ts"]
                    action["acknowledged_by"]   = ack["op_id"]
                    action["acknowledge_note"]  = ack.get("note") or None
                else:
                    action.setdefault("acknowledged_at",   None)
                    action.setdefault("acknowledged_by",   None)
                    action.setdefault("acknowledge_note",  None)
        return engagement

# --- default singleton --------------------------------------------------

_DEFAULT_STORE: AckStore | None = None

def default_store() -> AckStore:
    """Return a process-wide AckStore pointed at the conventional
    location.  Created lazily so importing this module doesn't write to
    disk (matters for tests + read-only environments).

    Path convention: `<repo>/state-docker/acks.json` on docker
    deployments, `<repo>/state/acks.json` for dev mode.  This helper
    picks `state-docker/` if it exists, falling back to `state/`."""
    global _DEFAULT_STORE
    if _DEFAULT_STORE is None:
        root = Path(__file__).resolve().parent.parent
        if (root / "state-docker").exists():
            base = root / "state-docker"
        else:
            base = root / "state"
        _DEFAULT_STORE = AckStore(base / "acks.json")
    return _DEFAULT_STORE

def reset_default_store_for_tests(path: Path | str) -> AckStore:
    """Tests use this to point the default at a tmp path.  Importing
    this name is the test-only entry; production code should never call
    it."""
    global _DEFAULT_STORE
    _DEFAULT_STORE = AckStore(path)
    return _DEFAULT_STORE
