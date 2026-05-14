"""Bucketed aggregations — Phase 5 of docs/design/UI_WIRING.md.

Single source of truth for the time-series + heatmap + DNS-stat numbers
the dashboard charts (and the matching REST endpoints) consume.  Both
runtimes — `tools/dashboard.py` and `plenith/api/server.py` — call into
this module so the charts the operator sees match the JSON a SOAR
integration pulls.

Design constraints:
  - Pure functions over file inputs.  No singletons, no caching.
    Tests inject a fake state-docker root; production code uses the
    real one.  If perf becomes a concern, add caching at the call site.
  - Reads engagement logs at `<state_docker>/logs/<host>/*.json` plus
    the optional `<state_docker>/acks.json` overlay.
  - No I/O ordering assumptions — the agent containers write logs
    independently; bucket computation tolerates out-of-order timestamps
    and best-effort handles missing/partial logs.
  - `compare_to="previous"` returns a second series for the
    same-width prior window so the chart can overlay a dashed line.
    Same shape as the main series, just shifted.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


_SEV_ORDER = ("critical", "high", "medium", "info")
_SEV_RANK = {s: i for i, s in enumerate(_SEV_ORDER)}


# ---------------------------------------------------------------------------
# Helpers — walk the log files
# ---------------------------------------------------------------------------

def _iter_session_logs(state_docker_root: Path) -> Iterable[Dict[str, Any]]:
    """Yield every session log file's parsed JSON.  Tolerates missing
    dirs / corrupt files (best-effort)."""
    logs_dir = state_docker_root / "logs"
    if not logs_dir.exists():
        return
    for host_dir in logs_dir.iterdir():
        if not host_dir.is_dir():
            continue
        for f in host_dir.glob("*.json"):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    yield data
            except (OSError, json.JSONDecodeError):
                continue


def _iter_actions(state_docker_root: Path) -> Iterable[Dict[str, Any]]:
    """Yield every `action_taken` entry from every session log, with the
    parent log's `started_at` injected so timestamps can be reconstructed
    even when an action stores only `ts_offset_s`."""
    for log in _iter_session_logs(state_docker_root):
        started = log.get("started_at") or 0
        for a in log.get("actions_taken", []) or []:
            ts = a.get("ts") or started + (a.get("ts_offset_s") or 0)
            yield {**a, "_ts": ts,
                   "_engagement_id": log.get("engagement_id", "")}


# ---------------------------------------------------------------------------
# /alerts/rate — bucketed alert counts by severity
# ---------------------------------------------------------------------------

def alert_rate(state_docker_root: Path | str, *,
                since: float,
                until: Optional[float] = None,
                bucket_seconds: int = 300,
                severities: Optional[List[str]] = None,
                compare_to: Optional[str] = None,
                ) -> Dict[str, Any]:
    """Bucketed alert counts by severity over `[since, until]`.

    Returns:
        {
          "since":          <epoch>,
          "until":          <epoch>,
          "bucket_seconds": <int>,
          "series":  [{"ts": <bucket_start>, "critical": N, "high": N, ...}],
          "totals":  {"critical": N, "high": N, "medium": N, "info": N},
          "compare": <same shape as series> | None,  # only if compare_to set
        }

    `compare_to="previous"` adds a second series for the equal-width
    window immediately preceding `since` — the chart overlays it as a
    dashed line.  No other compare modes are supported in this phase.
    """
    root = Path(state_docker_root)
    until = until if until is not None else time.time()
    wanted_sevs = severities or list(_SEV_ORDER)

    def _bucket(start: float, end: float) -> List[Dict[str, Any]]:
        n_buckets = max(1, int((end - start) / bucket_seconds))
        buckets = [
            {"ts": start + i * bucket_seconds,
             **{s: 0 for s in _SEV_ORDER}}
            for i in range(n_buckets)
        ]
        for a in _iter_actions(root):
            ts = a["_ts"]
            if ts < start or ts >= end:
                continue
            sev = a.get("severity", "info")
            if sev not in wanted_sevs or sev not in _SEV_ORDER:
                continue
            idx = min(n_buckets - 1, int((ts - start) / bucket_seconds))
            buckets[idx][sev] = buckets[idx].get(sev, 0) + 1
        return buckets

    series = _bucket(since, until)
    totals = {s: sum(b[s] for b in series) for s in _SEV_ORDER}

    compare = None
    if compare_to == "previous":
        width = until - since
        compare = _bucket(since - width, since)

    return {
        "since":          since,
        "until":          until,
        "bucket_seconds": bucket_seconds,
        "series":         series,
        "totals":         totals,
        "compare":        compare,
    }


# ---------------------------------------------------------------------------
# /alerts/top — most common alert types in the window, with sparklines
# ---------------------------------------------------------------------------

def alert_top(state_docker_root: Path | str, *,
               since: float,
               until: Optional[float] = None,
               limit: int = 10,
               sparkline_buckets: int = 8,
               ) -> Dict[str, Any]:
    """Per-alert-type aggregation for the "Top alerts in window" panel.

    Each entry includes a tiny sparkline (count per bucket across the
    window) so the chart can render a per-row trend without a second
    round trip.
    """
    root = Path(state_docker_root)
    until = until if until is not None else time.time()
    width = until - since
    if width <= 0:
        return {"since": since, "until": until, "alerts": []}
    bw = max(1.0, width / sparkline_buckets)

    by_name: Dict[str, Dict[str, Any]] = {}
    for a in _iter_actions(root):
        ts = a["_ts"]
        if ts < since or ts >= until:
            continue
        name = a.get("action") or "?"
        rec = by_name.setdefault(name, {
            "name":      name,
            "severity":  a.get("severity", "info"),
            "count":     0,
            "sparkline": [0] * sparkline_buckets,
            "first_at":  ts,
            "last_at":   ts,
        })
        rec["count"] += 1
        rec["first_at"] = min(rec["first_at"], ts)
        rec["last_at"]  = max(rec["last_at"],  ts)
        idx = min(sparkline_buckets - 1, int((ts - since) / bw))
        rec["sparkline"][idx] += 1
        # Keep the highest severity if multiple severities seen for one name
        if _SEV_RANK.get(a.get("severity", "info"), 9) < \
                _SEV_RANK.get(rec["severity"], 9):
            rec["severity"] = a["severity"]

    out = sorted(by_name.values(),
                  key=lambda r: (_SEV_RANK.get(r["severity"], 9),
                                  -r["count"]))[:limit]
    return {"since": since, "until": until, "alerts": out}


# ---------------------------------------------------------------------------
# /activity/heatmap — host × hour-of-day grid
# ---------------------------------------------------------------------------

def activity_heatmap(state_docker_root: Path | str, *,
                       since: float,
                       until: Optional[float] = None,
                       host: Optional[str] = None,
                       kind: str = "all",
                       ) -> Dict[str, Any]:
    """Per-host hourly activity grid.

    Each host gets a list of 24 ints — the count of events that fell in
    each hour-of-day bucket in local time.  Optional `host=` narrows to
    one decoy; `kind` selects which events are counted:

      ``all``      (default) — commands AND alerts (actions_taken)
      ``commands`` — only attacker commands (where they hit)
      ``alerts``   — only alerts the engine fired (where detections lit)

    Splitting the two surfaces is useful when triaging detection
    coverage vs. attacker spread.

    Returns:
        {
          "since":  <epoch>,
          "until":  <epoch>,
          "hosts":  {hostname: [c0, c1, ..., c23]},
          "peak_hour":   int | None,
          "busiest_host": str | None,
          "total": int,
        }
    """
    root = Path(state_docker_root)
    until = until if until is not None else time.time()
    logs_dir = root / "logs"
    grid: Dict[str, List[int]] = {}
    if kind not in ("all", "commands", "alerts"):
        kind = "all"
    count_alerts   = kind in ("all", "alerts")
    count_commands = kind in ("all", "commands")

    if not logs_dir.exists():
        return {"since": since, "until": until, "hosts": {},
                "peak_hour": None, "busiest_host": None, "total": 0}

    for host_dir in logs_dir.iterdir():
        if not host_dir.is_dir():
            continue
        h = host_dir.name
        if host and h != host:
            continue
        grid.setdefault(h, [0] * 24)
        for f in host_dir.glob("*.json"):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            started = data.get("started_at") or 0
            if count_alerts:
                for a in data.get("actions_taken", []) or []:
                    ts = a.get("ts") or started + (a.get("ts_offset_s") or 0)
                    if ts < since or ts >= until: continue
                    grid[h][time.localtime(ts).tm_hour] += 1
            if count_commands:
                for c in data.get("commands", []) or []:
                    ts = c.get("ts", 0)
                    if ts < since or ts >= until: continue
                    grid[h][time.localtime(ts).tm_hour] += 1

    # Headline stats for the popout-panel summary tiles
    peak_hour: Optional[int] = None
    busiest_host: Optional[str] = None
    if grid:
        # Peak hour is the hour-of-day with the maximum sum across all hosts
        hour_totals = [
            sum(grid[h][hr] for h in grid)
            for hr in range(24)
        ]
        if any(hour_totals):
            peak_hour = hour_totals.index(max(hour_totals))
        # Busiest host: the one with the largest total
        host_totals = {h: sum(grid[h]) for h in grid}
        if any(host_totals.values()):
            busiest_host = max(host_totals, key=host_totals.get)

    return {
        "since":        since,
        "until":        until,
        "hosts":        grid,
        "peak_hour":    peak_hour,
        "busiest_host": busiest_host,
        "total":        sum(sum(row) for row in grid.values()),
    }


def activity_cell_engagements(
    state_docker_root: Path | str,
    *,
    host: str,
    hour: int,
    since: float,
    until: Optional[float] = None,
    kind: str = "all",
    limit: int = 20,
) -> Dict[str, Any]:
    """Drill-in for the activity heatmap: which engagements contributed
    to events at (host, hour-of-day) inside [since, until]?

    Returned per-engagement counts split commands / alerts so the cell
    modal can show "X commands, Y alerts" instead of one opaque total.
    """
    if hour < 0 or hour > 23:
        return {"host": host, "hour": hour, "engagements": []}
    if kind not in ("all", "commands", "alerts"):
        kind = "all"
    root = Path(state_docker_root)
    until = until if until is not None else time.time()
    host_dir = root / "logs" / host
    if not host_dir.exists():
        return {"host": host, "hour": hour, "engagements": []}
    by_eng: Dict[str, Dict[str, Any]] = {}
    count_alerts   = kind in ("all", "alerts")
    count_commands = kind in ("all", "commands")
    for f in host_dir.glob("*.json"):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        eid = data.get("engagement_id") or ""
        if not eid:
            continue
        started = data.get("started_at") or 0
        bucket = by_eng.setdefault(eid, {
            "engagement_id":   eid,
            "claimed_user":    data.get("claimed_user", "?"),
            "source_ip":       data.get("source_ip", "?"),
            "commands":        0,
            "alerts":          0,
        })
        if count_alerts:
            for a in data.get("actions_taken", []) or []:
                ts = a.get("ts") or started + (a.get("ts_offset_s") or 0)
                if ts < since or ts >= until: continue
                if time.localtime(ts).tm_hour != hour: continue
                bucket["alerts"] += 1
        if count_commands:
            for c in data.get("commands", []) or []:
                ts = c.get("ts", 0)
                if ts < since or ts >= until: continue
                if time.localtime(ts).tm_hour != hour: continue
                bucket["commands"] += 1
    rows = [v for v in by_eng.values()
            if (v["commands"] + v["alerts"]) > 0]
    rows.sort(key=lambda r: -(r["commands"] + r["alerts"]))
    return {
        "host":         host,
        "hour":         hour,
        "since":        since,
        "until":        until,
        "kind":         kind,
        "engagements":  rows[:limit],
    }


# ---------------------------------------------------------------------------
# /dns/stats and /dns/top
# ---------------------------------------------------------------------------

_DNS_LINE_RE = re.compile(
    r"\[(?P<ts>[\d:.]+)\].*?(?P<host>[\w.-]+)\.\s+(?P<qtype>A|AAAA|PTR)\s+"
    r"(?P<result>NOERROR|NXDOMAIN|REFUSED)?",
    re.IGNORECASE,
)

_EXFIL_TOKENS = (
    "oast", "burpcoll", "interactsh", "ngrok.io", "dnslog.cn", ".oast.live",
    "shadowsrv", "evil.", ".attacker.", "pipedream.net",
)


def _classify_dns(host: str, result: str) -> str:
    low = (host or "").lower()
    if any(tok in low for tok in _EXFIL_TOKENS):
        return "blocked"
    if (result or "").upper() == "NXDOMAIN":
        return "nxdomain"
    return "resolved"


def parse_dns_lines(lines: Iterable[str]) -> List[Dict[str, str]]:
    """Parse raw CoreDNS log lines into structured dicts.  Exposed for
    the dashboard's inline rendering and for tests."""
    out: List[Dict[str, str]] = []
    for line in lines:
        m = _DNS_LINE_RE.search(line or "")
        if not m:
            continue
        host = m.group("host") or "?"
        result = m.group("result") or "NOERROR"
        out.append({
            "ts":     m.group("ts") or "",
            "host":   host,
            "qtype":  (m.group("qtype") or "A").upper(),
            "result": _classify_dns(host, result),
        })
    return out


def dns_stats(parsed_lines: List[Dict[str, str]]) -> Dict[str, Any]:
    """Aggregate counts across the in-memory parsed DNS feed.  The
    docker-log fetch lives in `tools/dashboard.py` (since the API
    server doesn't have a `docker` CLI handy in every deployment)."""
    n_resolved = sum(1 for p in parsed_lines if p["result"] == "resolved")
    n_blocked  = sum(1 for p in parsed_lines if p["result"] == "blocked")
    n_nxd      = sum(1 for p in parsed_lines if p["result"] == "nxdomain")
    return {
        "total":    len(parsed_lines),
        "resolved": n_resolved,
        "blocked":  n_blocked,
        "nxdomain": n_nxd,
    }


def dns_top(parsed_lines: List[Dict[str, str]], *,
              result_type: str = "blocked",
              limit: int = 10,
              ) -> List[Dict[str, Any]]:
    """Most-frequent hosts by result type."""
    if result_type not in ("resolved", "blocked", "nxdomain"):
        raise ValueError(f"unknown result_type: {result_type!r}")
    counts: Dict[str, int] = {}
    for p in parsed_lines:
        if p["result"] != result_type:
            continue
        counts[p["host"]] = counts.get(p["host"], 0) + 1
    return [
        {"host": h, "count": c}
        for h, c in sorted(counts.items(), key=lambda kv: -kv[1])[:limit]
    ]
