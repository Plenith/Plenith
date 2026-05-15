"""On-disk persistence for engagement state.

Keys are `(source_ip, claimed_user)` pairs. Each key maps to one JSON file
under `state/persistence/` containing:

    {
      "engagement_id":      "<uuid>",
      "first_seen_at":      <epoch>,
      "last_seen_at":       <epoch>,
      "connection_count":   <int>,
      "claimed_user":       "<name>",
      "source_ip":          "<ip>",
      "cwd":                "<path>",
      "vfs":                {"files": {...}, "deleted": [...]},
      "observed":           {... session observations ...}
    }

The store does atomic writes (write-then-rename) so a crash mid-save can't
corrupt prior state. Reads are best-effort: any missing/corrupt file is
treated as "no prior state."
"""
import json
import os
import re
import tempfile
import time
from pathlib import Path

def _safe_key(ip, user):
    """Turn (ip, user) into a filesystem-safe basename. IPv6 colons and
    Windows-reserved chars get replaced with underscore."""
    raw = f"{ip}__{user}"
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", raw)

class StateStore:
    def __init__(self, base_dir):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _path_for(self, ip, user):
        return self.base_dir / f"{_safe_key(ip, user)}.json"

    def load(self, ip, user):
        """Return the saved dict for (ip, user), or None if not present /
        unreadable."""
        path = self._path_for(ip, user)
        if not path.exists():
            return None
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return None

    def save(self, ip, user, state):
        """Write `state` to the (ip, user) file atomically."""
        path = self._path_for(ip, user)
        state = dict(state)  # shallow copy so we can stamp
        state["last_seen_at"] = time.time()
        # Atomic write: write to tmp in the same directory, then rename.
        fd, tmp_path = tempfile.mkstemp(
            prefix=".tmp_", suffix=".json", dir=str(self.base_dir)
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2, default=str)
            os.replace(tmp_path, path)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
