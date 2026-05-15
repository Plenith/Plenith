"""Engagement kill-request queue — Phase 3 of docs/design/UI_WIRING.md.

Design choice: a queue, not a synchronous call.  When an analyst clicks
"Kill session", the API records a kill request to
`state-docker/kill_requests.json`; the orchestrator picks it up on its
next loop tick and closes the matching SSH connection(s).

Why a queue rather than direct termination:
  - The API process (`plenith/api/server.py`) and the dashboard
    (`tools/dashboard.py`) live in *separate* processes from the
    orchestrator/SSH server.  Direct termination would require IPC
    plumbing (socket / signal / shared memory) that's invasive and
    OS-specific.
  - A file-based queue is observable.  An operator can `cat
    kill_requests.json` and see exactly what's pending.
  - SOAR / external automation gets the same shape — POST a kill
    request, poll the engagement, see when the connections drop.

Latency: bounded by the orchestrator's poll interval (~1s) plus the
time SSH takes to actually drop.  Practical kill-to-disconnect: 2-5s.
Documented in `docs/RUNBOOK.md` so analysts know what to expect.

The orchestrator-side consumer lives in `plenith/ssh_server.py`:
`HoneypotSession` checks this queue both per-command and via an
independent idle poller, closes the SSH channel, and calls
`mark_killed()`.  This file only owns the queue contract.

Schema:

    {
      "<engagement_id>": {
        "requested_at": <utc epoch float>,
        "requested_by": "<op_id>",
        "reason":       "<optional context>",
        "status":       "pending" | "killed" | "expired"
      }
    }

Once status flips to "killed" or "expired" the entry stays for ~24h so
the dashboard can show "killed 12m ago" before being garbage-collected.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any

# Garbage-collect entries older than 24h whose status isn't "pending".
_GC_TTL_SECONDS = 86400

class KillRequestQueue:
    """Single-file queue of pending engagement-kill requests."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    # ----- raw load/save ----------------------------------------------

    def _load_raw(self) -> dict[str, dict[str, Any]]:
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
        fd, tmp_path = tempfile.mkstemp(
            prefix=".tmp_kill_", suffix=".json",
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

    def request_kill(self, engagement_id: str, *,
                      requested_by: str = "anonymous",
                      reason: str = "") -> dict[str, Any]:
        """Enqueue a kill request.  Idempotent — calling twice on a
        pending request updates the requested_by and reason without
        creating a duplicate.  Returns the current entry shape so the
        caller can show 'will terminate on next orchestrator tick'."""
        data = self._gc(self._load_raw())
        existing = data.get(engagement_id)
        entry = {
            "requested_at": time.time(),
            "requested_by": requested_by or "anonymous",
            "reason":       reason or "",
            "status":       "pending",
        }
        # If the prior entry was already pending, keep the original
        # requested_at so dashboard "X seconds ago" doesn't reset.
        if existing and existing.get("status") == "pending":
            entry["requested_at"] = existing.get("requested_at", entry["requested_at"])
        data[engagement_id] = entry
        self._atomic_write(data)
        return entry

    def cancel(self, engagement_id: str) -> bool:
        """Remove a pending kill request.  Used by an "undo" button on
        the dashboard or by the orchestrator if it can't find a matching
        live connection.  Returns True if anything was cancelled."""
        data = self._gc(self._load_raw())
        existing = data.get(engagement_id)
        if not existing or existing.get("status") != "pending":
            return False
        del data[engagement_id]
        self._atomic_write(data)
        return True

    def mark_killed(self, engagement_id: str) -> bool:
        """Orchestrator marks a request as fulfilled once SSH connections
        are closed.  Status flips to 'killed' with the timestamp; the
        entry stays in the file for ~24h so the dashboard can show
        'killed 3m ago'."""
        data = self._load_raw()
        existing = data.get(engagement_id)
        if not existing:
            return False
        existing["status"] = "killed"
        existing["killed_at"] = time.time()
        self._atomic_write(data)
        return True

    def pending(self) -> list[str]:
        """Engagement IDs with a pending kill request.  Used by the
        orchestrator's poll loop."""
        data = self._load_raw()
        return [eid for eid, entry in data.items()
                if entry.get("status") == "pending"]

    def get(self, engagement_id: str) -> dict[str, Any] | None:
        return self._load_raw().get(engagement_id)

    def all(self) -> dict[str, dict[str, Any]]:
        return self._gc(self._load_raw())

    # ----- internals --------------------------------------------------

    def _gc(self, data: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
        """Drop completed entries older than the TTL.  Run on every
        mutation — keeps the file from growing forever."""
        now = time.time()
        cutoff = now - _GC_TTL_SECONDS
        keep: dict[str, dict[str, Any]] = {}
        for eid, entry in data.items():
            status = entry.get("status", "pending")
            if status == "pending":
                keep[eid] = entry
                continue
            ts = entry.get("killed_at", entry.get("requested_at", 0))
            if ts >= cutoff:
                keep[eid] = entry
        return keep

# --- default singleton --------------------------------------------------

_DEFAULT_QUEUE: KillRequestQueue | None = None

def default_queue() -> KillRequestQueue:
    global _DEFAULT_QUEUE
    if _DEFAULT_QUEUE is None:
        root = Path(__file__).resolve().parent.parent
        if (root / "state-docker").exists():
            base = root / "state-docker"
        else:
            base = root / "state"
        _DEFAULT_QUEUE = KillRequestQueue(base / "kill_requests.json")
    return _DEFAULT_QUEUE

def reset_default_queue_for_tests(path: Path | str) -> KillRequestQueue:
    global _DEFAULT_QUEUE
    _DEFAULT_QUEUE = KillRequestQueue(path)
    return _DEFAULT_QUEUE
