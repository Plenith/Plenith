"""Agent registration + heartbeat back-channel.

Currently the dashboard infers agent liveness by shelling out to
`docker ps` and counting which containers are Up. That works for the
docker-compose dev fabric but fails for k8s deploys (no docker socket
inside the API pod), bare-metal deploys (no docker at all), and any
case where the agent runs outside an orchestrator that the API can
introspect.

This module is the back-channel: each agent periodically writes a
small heartbeat JSON file to a shared state dir; the API reads them
and exposes the roster via `/agents` (or surfaces it on the dashboard).

The heartbeat file is intentionally tiny (~400 bytes) so writing one
every 10s is cheap. We use the same shared `/mnt/state` volume the
agents already mount.

Heartbeat file layout:
    /mnt/state/heartbeats/<hostname>.json
    {
      "hostname":    "bastion-prod",
      "persona":     "agarcia",
      "version":     "1.0.0",
      "started_at":  1778600000.0,
      "last_beat":   1778600145.7,
      "engagements_open": 2,
      "engagements_total_since_start": 17,
      "deployment_id": "...",
      "content_epoch": "2026Q2"
    }

Stale heartbeats (last_beat > N seconds ago) are surfaced as
"unhealthy" in the API. After M missed beats the agent is "down."
"""
from __future__ import annotations

import asyncio
import json
import os
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_INTERVAL_SECONDS  = 10.0      # write every 10s
DEFAULT_STALE_SECONDS     = 30.0      # > 30s = degraded
DEFAULT_DOWN_SECONDS      = 90.0      # > 90s = down

# ---------------------------------------------------------------------------
# Writer (runs in each agent)
# ---------------------------------------------------------------------------

@dataclass
class HeartbeatWriter:
    """Periodic heartbeat publisher. Each agent starts one of these
    alongside the SSH server; it lives in the same asyncio loop and
    writes a tiny JSON every `interval_seconds`."""
    state_dir:    Path                # /mnt/state or equivalent
    hostname:     str
    persona:      str = ""
    version:      str = "1.0.0"
    deployment_id: str = ""
    content_epoch: str = ""
    interval_seconds: float = DEFAULT_INTERVAL_SECONDS

    started_at: float = field(default_factory=time.time)
    engagements_open: int = 0
    engagements_total: int = 0
    _task: asyncio.Task | None = None
    _stopped: asyncio.Event = field(default_factory=asyncio.Event)

    def file_path(self) -> Path:
        return self.state_dir / "heartbeats" / f"{self.hostname}.json"

    def write_once(self) -> None:
        """Synchronous write — called once at startup so the heartbeat
        appears in the dashboard immediately, before the first tick."""
        payload = {
            "hostname":        self.hostname,
            "persona":         self.persona,
            "version":         self.version,
            "started_at":      self.started_at,
            "last_beat":       time.time(),
            "engagements_open": self.engagements_open,
            "engagements_total_since_start": self.engagements_total,
            "deployment_id":   self.deployment_id,
            "content_epoch":   self.content_epoch,
            "pid":             os.getpid(),
        }
        p = self.file_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        tmp.replace(p)   # atomic on POSIX, near-atomic on Windows

    async def _run(self) -> None:
        try:
            while not self._stopped.is_set():
                self.write_once()
                try:
                    await asyncio.wait_for(
                        self._stopped.wait(), timeout=self.interval_seconds,
                    )
                except TimeoutError:
                    pass
        except asyncio.CancelledError:
            return

    async def start(self) -> None:
        if self._task is not None:
            return
        self.write_once()                        # immediate first beat
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        self._stopped.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        # On graceful shutdown, leave one final "stopping" beat so the
        # dashboard can distinguish "agent left cleanly" from "crashed".
        try:
            p = self.file_path()
            if p.exists():
                data = json.loads(p.read_text(encoding="utf-8"))
                data["last_beat"] = time.time()
                data["status"] = "stopping"
                p.write_text(json.dumps(data), encoding="utf-8")
        except (OSError, json.JSONDecodeError):
            pass

# ---------------------------------------------------------------------------
# Reader (runs in the API / dashboard process)
# ---------------------------------------------------------------------------

@dataclass
class AgentHealth:
    hostname:         str
    persona:          str
    version:          str
    started_at:       float
    last_beat:        float
    age_seconds:      float
    status:           str      # "healthy" | "degraded" | "down" | "stopping"
    engagements_open: int
    engagements_total_since_start: int
    deployment_id:    str
    content_epoch:    str

    def to_dict(self) -> dict[str, Any]:
        return {
            "hostname":        self.hostname,
            "persona":         self.persona,
            "version":         self.version,
            "started_at":      self.started_at,
            "last_beat":       self.last_beat,
            "age_seconds":     self.age_seconds,
            "status":          self.status,
            "engagements_open": self.engagements_open,
            "engagements_total_since_start": self.engagements_total_since_start,
            "deployment_id":   self.deployment_id,
            "content_epoch":   self.content_epoch,
        }

def _classify(age_seconds: float, recorded_status: str | None,
              *, stale: float, down: float) -> str:
    if recorded_status == "stopping":
        return "stopping"
    if age_seconds > down:
        return "down"
    if age_seconds > stale:
        return "degraded"
    return "healthy"

def read_all_heartbeats(
    state_dir: Path,
    *,
    stale_seconds: float = DEFAULT_STALE_SECONDS,
    down_seconds: float = DEFAULT_DOWN_SECONDS,
    now: float | None = None,
) -> list[AgentHealth]:
    """Walk every heartbeat file under `state_dir/heartbeats/` and
    return a list of AgentHealth records sorted by hostname."""
    now = now if now is not None else time.time()
    hb_dir = state_dir / "heartbeats"
    if not hb_dir.exists():
        return []
    out: list[AgentHealth] = []
    for p in sorted(hb_dir.glob("*.json")):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        last_beat = float(data.get("last_beat") or 0)
        age = max(0.0, now - last_beat)
        out.append(AgentHealth(
            hostname=        str(data.get("hostname", p.stem)),
            persona=         str(data.get("persona", "")),
            version=         str(data.get("version", "?")),
            started_at=      float(data.get("started_at") or 0),
            last_beat=       last_beat,
            age_seconds=     age,
            status=          _classify(age, data.get("status"),
                                        stale=stale_seconds, down=down_seconds),
            engagements_open=int(data.get("engagements_open") or 0),
            engagements_total_since_start=int(
                data.get("engagements_total_since_start") or 0),
            deployment_id=   str(data.get("deployment_id", "")),
            content_epoch=   str(data.get("content_epoch", "")),
        ))
    return out
