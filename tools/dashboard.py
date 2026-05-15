"""Live SOC dashboard — v2 design (Phase 1 of UI_WIRING.md option B).

Plain stdlib http.server.  Reads `state-docker/{persistence,logs}/`
plus the plenith-dns container log, renders the new dark-by-default
(auto-detects prefers-color-scheme) dashboard.  CSS + JS live in
sibling files for tractability:

  tools/dashboard.py            — server + render functions  (this file)
  tools/dashboard_styles.py     — design tokens + component CSS
  tools/dashboard_scripts.py    — theme/TV/layouts/filter/SSE client JS

URL surface:

  /                              main dashboard
  /panel/engagements             full engagement list (popout)
  /panel/engagement/<id>         single engagement detail (popout)
  /panel/alert-rate              alert-rate chart (popout)
  /panel/dns-feed                DNS query feed (popout)
  /panel/activity                activity heatmap (popout)
  /api/state.json                raw JSON dump of the gathered state
  /api/stream[?panel=<name>]     SSE — pushes panel HTML every <refresh>s

Phase 1 wires the visual surface + every client-side behavior:

  - dark / light themes (auto-detect + manual toggle, persists)
  - TV mode with 30s auto-rotation across sections
  - named saved layouts (open multiple panel windows in one click)
  - client-side engagement filter (`/` to focus)
  - multi-select state (batch-bar appears; handlers ship in Phase 2-3)
  - pop-out → opens /panel/<name> in a sized window
  - per-panel SSE filtering (popout windows don't pay for main-dash data)

Things deferred to later phases (visible in the UI as inert until
their phase ships):
  - Acknowledge / un-acknowledge      — Phase 2
  - Snapshot / Kill / Escalate / Notes — Phase 3
  - Audit / Sigma / IoC URL aliases   — Phase 4
  - Bucketed aggregation endpoints    — Phase 5
  - SSE alert-push + browser toasts   — Phase 6

Usage:
    python tools/dashboard.py                   # serve http://127.0.0.1:8765
    python tools/dashboard.py --port 9000
    python tools/dashboard.py --refresh 5
"""
from __future__ import annotations

import argparse
import html
import importlib.util
import io
import json
import re
import socket
import subprocess
import sys
import time
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlparse

# Sibling modules in tools/ — not on sys.path when this file is run
# directly or side-loaded via importlib (as the test suite does).
sys.path.insert(0, str(Path(__file__).resolve().parent))
from dashboard_styles import CSS                    # noqa: E402
from dashboard_scripts import JS                    # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent
# Phase 2: ack overlay.  The dashboard reads/writes the same acks.json
# the FastAPI service reads/writes, so an ack made via the dashboard
# is immediately visible via /api and vice versa.
sys.path.insert(0, str(_ROOT))
from plenith.acks      import default_store  as _ack_store      # noqa: E402
from plenith.notes     import default_store  as _notes_store    # noqa: E402
from plenith.snapshots import default_writer as _snap_writer    # noqa: E402
from plenith.kill_queue import default_queue as _kill_queue     # noqa: E402
from plenith.escalate  import escalate_sync   as _escalate_sync # noqa: E402
_STATE_DIR = _ROOT / "state-docker" / "persistence"
_LOGS_BASE = _ROOT / "state-docker" / "logs"
_PERSONAS  = _ROOT / "personas"

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError, OSError):
    pass


def _load_audit():
    """Side-load tools/audit.py without making it a package."""
    spec = importlib.util.spec_from_file_location(
        "audit", _ROOT / "tools" / "audit.py",
    )
    audit = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(audit)
    return audit


# Severity ordering — used for sorting and color mapping.
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "info": 3}


# ===========================================================================
# Data gathering
# ===========================================================================

def _gather() -> dict:
    """Walk state + logs dirs once and return a render-ready dict.

    The shape is documented in UI_WIRING.md §G.  Keys consumed by the
    new render functions:

        engagements        list[engagement-dict]   newest-activity-first
        actions_by_eng     {eng_id: list[action]}
        sev_totals         {critical, high, medium, info}
        containers         list[{name, status}]
        dns_lines          list[str]               recent CoreDNS log lines
        dns_parsed         list[{ts, host, qtype, result}]
        rotation           {corp_name, corp_domain, industry, subnet, signature}
        kpis               {active, alerts_24h, alerts_24h_delta, ...}
        host_activity      {hostname: [counts_per_hour]}
        alert_rate_buckets list[{ts, by_severity}]    bucketed counts
        now                "HH:MM:SS"
    """
    sys.path.insert(0, str(_ROOT))
    audit = _load_audit()

    # Multi-host logs layout: state-docker/logs/<hostname>/*.json
    logs_dirs = [d for d in _LOGS_BASE.iterdir() if d.is_dir()] \
                  if _LOGS_BASE.exists() else []
    raw_engagements: list[dict] = []
    for d in logs_dirs:
        for e in audit.load_engagements(_STATE_DIR, d, _PERSONAS):
            e["_host"] = d.name
            raw_engagements.append(e)

    # Dedupe by engagement_id — the same engagement can appear under
    # multiple host log dirs (attacker pivots host-to-host, or fixture
    # has the same id seeded across hosts).  Merge their logs and keep
    # an ordered _hosts list so the renderer can show "host (+N)".
    by_eid: dict[str, dict] = {}
    for e in raw_engagements:
        eid = e.get("engagement_id")
        if not eid:
            by_eid[f"__unkeyed_{id(e)}"] = e
            e.setdefault("_hosts", [e.get("_host", "?")])
            continue
        if eid not in by_eid:
            e["_hosts"] = [e.get("_host", "?")]
            by_eid[eid] = e
            continue
        prev = by_eid[eid]
        prev_hosts = prev.get("_hosts") or []
        new_host = e.get("_host", "?")
        if new_host not in prev_hosts:
            prev_hosts.append(new_host)
        prev["_hosts"] = prev_hosts
        # Merge logs (each is a session log dict with actions_taken)
        prev["logs"] = (prev.get("logs") or []) + (e.get("logs") or [])
        # Latest seen / earliest first-seen
        if (e.get("last_seen_at") or 0) > (prev.get("last_seen_at") or 0):
            prev["last_seen_at"] = e["last_seen_at"]
            prev["_host"] = new_host    # primary = most-recent host
        new_first = e.get("first_seen_at") or 0
        prev_first = prev.get("first_seen_at") or 0
        if new_first and (prev_first == 0 or new_first < prev_first):
            prev["first_seen_at"] = new_first
        # Prefer the more-confident observed bundle if it has signal
        new_obs = e.get("observed") or {}
        prev_obs = prev.get("observed") or {}
        if (new_obs.get("attacker_llm_confidence") or 0) > \
                (prev_obs.get("attacker_llm_confidence") or 0):
            prev["observed"] = new_obs
    engagements: list[dict] = list(by_eid.values())
    engagements.sort(key=lambda e: e.get("last_seen_at", 0), reverse=True)

    # Phase 2: fold the ack overlay into every action_taken across all
    # engagements.  Mutates in-place so subsequent rendering sees the
    # acknowledged_at / acknowledged_by / acknowledge_note fields.
    ack_store = _ack_store()
    notes_store = _notes_store()
    kill_queue = _kill_queue()
    snap_writer = _snap_writer()
    for e in engagements:
        ack_store.overlay_engagement(e)
        # Phase 3: notes overlay (sets e["notes"])
        notes_store.overlay_engagement(e)
        # Phase 3: kill-request state (pending? killed? not requested?)
        eid = e.get("engagement_id")
        if eid:
            kreq = kill_queue.get(eid)
            e["_kill_request"] = kreq
            # Phase 3: snapshot list per engagement for the detail panel
            e["_snapshots"] = snap_writer.list_for(eid)

    # Severity totals + per-engagement actions.  Read from the already-
    # overlaid engagement.logs so acks/notes/etc. propagate to renderers
    # that pull from actions_by_eng (alert rows, count badges).
    sev_totals = {"critical": 0, "high": 0, "medium": 0, "info": 0}
    actions_by_eng: dict[str, list[dict]] = {}
    for e in engagements:
        eid = e.get("engagement_id")
        for log in e.get("logs", []) or []:
            for a in log.get("actions_taken", []) or []:
                sev = a.get("severity", "info")
                sev_totals[sev] = sev_totals.get(sev, 0) + 1
                if eid:
                    actions_by_eng.setdefault(eid, []).append(a)

    # Container roster (defensive — docker may not be installed in dev).
    containers: list[dict] = []
    try:
        ps = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}|{{.Status}}"],
            capture_output=True, text=True, timeout=4,
        )
        for line in ps.stdout.strip().split("\n"):
            if "|" in line:
                name, status = line.split("|", 1)
                containers.append({"name": name, "status": status})
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # CoreDNS log slice — keep both raw lines (legacy) and parsed shape.
    dns_lines: list[str] = []
    dns_parsed: list[dict] = []
    try:
        dlog = subprocess.run(
            ["docker", "logs", "--tail", "200", "plenith-dns"],
            capture_output=True, text=True, timeout=4,
        )
        for line in (dlog.stdout + dlog.stderr).splitlines():
            if "172.30.0." not in line and "NOERROR" not in line \
                    and "REFUSED" not in line and "NXDOMAIN" not in line:
                continue
            dns_lines.append(line)
            parsed = _parse_dns_line(line)
            if parsed:
                dns_parsed.append(parsed)
        dns_lines = dns_lines[-50:]
        dns_parsed = dns_parsed[-50:]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Content rotator signature.  Falls back gracefully if rotation isn't
    # configured for this deployment.
    rotation = {
        "corp_name": "unknown", "corp_domain": "", "industry": "",
        "subnet": "", "signature": "------",
    }
    try:
        from plenith.rotation import ContentRotator, DeploymentSeed
        rot = ContentRotator.from_seed(
            DeploymentSeed("mc-demo-installation-001", "2026Q2"),
        )
        rotation = {
            "corp_name":   rot.corp.corp_name,
            "corp_domain": rot.corp.corp_domain,
            "industry":    rot.corp.industry_long,
            "subnet":      rot.corp.prod_subnet,
            "signature":   rot.signature(),
        }
    except Exception:
        pass

    kpis = _compute_kpis(engagements, actions_by_eng)
    # Phase 5: route through plenith.aggregations so the dashboard's
    # inline charts and the REST endpoints share one source of truth.
    from plenith.aggregations import (
        alert_rate as _agg_alert_rate,
        activity_heatmap as _agg_heatmap,
    )
    state_docker = _ROOT / "state-docker"
    _now = time.time()
    _rate = _agg_alert_rate(state_docker,
                              since=_now - 21600, until=_now,
                              bucket_seconds=300,
                              compare_to="previous")
    alert_rate_buckets = _rate["series"]
    alert_rate_compare = _rate["compare"]   # may be None
    _heat = _agg_heatmap(state_docker, since=_now - 86400, until=_now)
    host_activity = _heat["hosts"]

    return {
        "engagements":         engagements,
        "actions_by_eng":      actions_by_eng,
        "sev_totals":          sev_totals,
        "containers":          containers,
        "dns_lines":           dns_lines,
        "dns_parsed":          dns_parsed,
        "rotation":            rotation,
        "kpis":                kpis,
        "host_activity":       host_activity,
        "alert_rate_buckets":  alert_rate_buckets,
        "alert_rate_compare":  alert_rate_compare,
        "now":                 datetime.now().strftime("%H:%M:%S"),
    }


_DNS_RE = re.compile(
    r"\[(?P<ts>[\d:.]+)\].*?(?P<host>[\w.-]+)\.\s+(?P<qtype>A|AAAA|PTR)\s+"
    r"(?P<result>NOERROR|NXDOMAIN|REFUSED)?",
    re.IGNORECASE,
)


def _parse_dns_line(line: str) -> dict | None:
    """Extract a structured row from a CoreDNS log line. Best-effort."""
    m = _DNS_RE.search(line)
    if not m:
        return None
    result = m.group("result") or "NOERROR"
    return {
        "ts":     m.group("ts") or "",
        "host":   m.group("host") or "?",
        "qtype":  (m.group("qtype") or "A").upper(),
        "result": _classify_dns_result(m.group("host") or "", result),
    }


_EXFIL_DOMAIN_TOKENS = (
    "oast", "burpcoll", "interactsh", "ngrok.io", "dnslog.cn", ".oast.live",
    "shadowsrv", "evil.", ".attacker.", "pipedream.net",
)


def _classify_dns_result(host: str, raw: str) -> str:
    """Map raw CoreDNS result + hostname → semantic class for the UI."""
    low = host.lower()
    if any(tok in low for tok in _EXFIL_DOMAIN_TOKENS):
        return "blocked"
    if raw.upper() == "NXDOMAIN":
        return "nxdomain"
    return "resolved"


def _compute_kpis(engagements: list[dict],
                   actions_by_eng: dict[str, list[dict]]) -> dict:
    """Compute the six KPI-strip values.  Stays inline here in Phase 1;
    Phase 5 moves this to a dedicated endpoint."""
    now = time.time()
    active = [e for e in engagements if now - e.get("last_seen_at", 0) < 3600]
    last_24h = now - 86400
    last_48h = now - 172800
    alerts_24h = 0
    alerts_prev_24h = 0
    llm_detected = 0
    proof_by_trap = 0
    for e in engagements:
        obs = e.get("observed") or {}
        if obs.get("attacker_likely_llm"):
            llm_detected += 1
        if obs.get("attacker_llm_proven_via_trap"):
            proof_by_trap += 1
        for a in actions_by_eng.get(e["engagement_id"], []):
            ts = a.get("ts") or a.get("ts_offset_s", 0) + e.get("first_seen_at", 0)
            if ts >= last_24h:
                alerts_24h += 1
            elif ts >= last_48h:
                alerts_prev_24h += 1
    delta_pct = 0
    if alerts_prev_24h > 0:
        delta_pct = int(round((alerts_24h - alerts_prev_24h) * 100 / alerts_prev_24h))
    # Dwell p50 across all open engagements
    dwells = sorted([
        (e.get("last_seen_at", 0) - e.get("first_seen_at", 0))
        for e in active
        if e.get("last_seen_at") and e.get("first_seen_at")
    ])
    dwell_p50_s = int(dwells[len(dwells) // 2]) if dwells else 0
    # Decoy stats
    decoys_planted = 0
    decoys_swallowed = 0
    for e in engagements:
        obs = e.get("observed") or {}
        decoys_planted   += len(obs.get("decoys_planted") or [])
        decoys_swallowed += len(obs.get("decoys_swallowed") or [])
    return {
        "active":           len(active),
        "alerts_24h":       alerts_24h,
        "alerts_24h_delta": delta_pct,
        "llm_detected":     llm_detected,
        "llm_total":        len(engagements),
        "proof_by_trap":    proof_by_trap,
        "dwell_p50_s":      dwell_p50_s,
        "decoys_planted":   decoys_planted,
        "decoys_swallowed": decoys_swallowed,
    }


def _compute_host_activity(engagements: list[dict],
                            logs_dirs: list[Path]) -> dict[str, list[int]]:
    """24-hour-per-host activity grid for the heatmap panel.  Hour buckets
    in local time.  Each host gets a list of 24 ints (count of events)."""
    grid: dict[str, list[int]] = {}
    now = time.time()
    day_start = now - 86400
    for d in logs_dirs:
        host = d.name
        grid.setdefault(host, [0] * 24)
        for log_file in d.glob("*.json"):
            try:
                data = json.loads(log_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            for a in data.get("actions_taken", []):
                ts = a.get("ts") or a.get("ts_offset_s", 0) + data.get("started_at", 0)
                if ts < day_start:
                    continue
                hour = time.localtime(ts).tm_hour
                grid[host][hour] += 1
            for c in data.get("commands", []):
                ts = c.get("ts", 0)
                if ts < day_start:
                    continue
                hour = time.localtime(ts).tm_hour
                grid[host][hour] += 1
    return grid


def _compute_alert_rate_buckets(logs_dirs: list[Path]) -> list[dict]:
    """5-minute buckets of alert counts by severity, for the last 6h.
    Used by the alert-rate panel until Phase 5 ships the dedicated
    /alerts/rate endpoint with proper compare-to support."""
    now = time.time()
    horizon = now - 21600          # 6 hours
    bucket_size = 300              # 5 minutes
    bucket_count = 72              # 6h / 5min
    buckets = [
        {"ts": horizon + i * bucket_size,
         "critical": 0, "high": 0, "medium": 0, "info": 0}
        for i in range(bucket_count)
    ]
    for d in logs_dirs:
        for log_file in d.glob("*.json"):
            try:
                data = json.loads(log_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            for a in data.get("actions_taken", []):
                ts = a.get("ts") or a.get("ts_offset_s", 0) + data.get("started_at", 0)
                if ts < horizon or ts > now:
                    continue
                idx = min(bucket_count - 1, int((ts - horizon) // bucket_size))
                sev = a.get("severity", "info")
                if sev in buckets[idx]:
                    buckets[idx][sev] += 1
    return buckets


# ===========================================================================
# Render helpers (SVG sparklines, gauges, severity pills)
# ===========================================================================

def _svg_sparkline(values: list[float], color: str = "var(--fg-3)",
                    width: int = 80, height: int = 22) -> str:
    """Inline SVG line chart.  Empty values renders a flat baseline."""
    if not values or len(values) < 2:
        return (f'<svg viewBox="0 0 {width} {height}" preserveAspectRatio="none">'
                f'<line x1="0" x2="{width}" y1="{height - 2}" y2="{height - 2}" '
                f'stroke="{color}" stroke-width="1.2"/></svg>')
    vmin = min(values)
    vmax = max(values)
    span = vmax - vmin if vmax > vmin else 1
    n = len(values)
    pts = []
    for i, v in enumerate(values):
        x = (i / (n - 1)) * width
        y = height - 2 - ((v - vmin) / span) * (height - 4)
        pts.append(f"{x:.1f},{y:.1f}")
    return (f'<svg viewBox="0 0 {width} {height}" preserveAspectRatio="none">'
            f'<polyline fill="none" stroke="{color}" stroke-width="1.2" '
            f'points="{" ".join(pts)}"/></svg>')


def _svg_gauge(value: float, threshold_low: float = 0.55,
                threshold_high: float = 0.70, size: int = 110) -> str:
    """Counter-AI radial gauge.  value ∈ [0, 1].  Threshold ticks at low/high."""
    value = max(0.0, min(1.0, value))
    r = 42
    circumference = 2 * 3.14159 * r
    dash = value * circumference
    color = "var(--conf-low)" if value < threshold_low else \
            "var(--conf-mid)" if value < threshold_high else "var(--conf-high)"
    return f'''
    <svg viewBox="0 0 {size} {size}" preserveAspectRatio="none">
      <circle cx="{size/2}" cy="{size/2}" r="{r}" fill="none"
              stroke="var(--surface-2)" stroke-width="10"/>
      <circle cx="{size/2}" cy="{size/2}" r="{r}" fill="none"
              stroke="{color}" stroke-width="10"
              stroke-dasharray="{dash:.1f} {circumference:.1f}"
              stroke-linecap="round"/>
    </svg>'''


def _severity_class(actions: list[dict]) -> str:
    """Return the CSS class for the highest-severity action in the list."""
    sevs = {a.get("severity", "info") for a in actions}
    for sev in ("critical", "high", "medium", "low", "info"):
        if sev in sevs:
            return sev
    return "info"


def _format_dwell(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60:02d}s"
    if seconds < 86400:
        return f"{seconds // 3600}h {(seconds % 3600) // 60:02d}m"
    return f"{seconds // 86400}d {(seconds % 86400) // 3600:02d}h"


def _format_ago(ts: float) -> str:
    if not ts:
        return "—"
    delta = max(0, int(time.time() - ts))
    if delta < 60:    return f"{delta}s ago"
    if delta < 3600:  return f"{delta // 60}m ago"
    if delta < 86400: return f"{delta // 3600}h ago"
    return f"{delta // 86400}d ago"


# ===========================================================================
# Shared HTML chrome
# ===========================================================================

def _render_topbar(state: dict, *, sse_label: str = "live (SSE)") -> str:
    """The top strip — brand, deployment id, TV/Notify/Layout toggles,
    LLM status + uptime on the right."""
    rot = state["rotation"]
    kpis = state["kpis"]
    # Count unacked critical alerts directly from the overlaid actions —
    # state["sev_totals"]["critical"] is the *total* count and doesn't
    # subtract acks.  JS keeps this in sync on every SSE tick via the
    # plenith:critical-count CustomEvent.
    crit_unacked = 0
    for actions in state.get("actions_by_eng", {}).values():
        for a in actions:
            if a.get("severity") == "critical" and not a.get("acknowledged_at"):
                crit_unacked += 1
    hide = "" if crit_unacked else ' hidden'
    notify_badge = (f'<span class="badge" data-notify-badge{hide}>'
                    f'{crit_unacked}</span>')
    return f'''
<div class="top">
  <div class="brand">
    <div class="brand-mark"></div>
    <span class="brand-name">PLENITH</span>
    <span class="brand-sep">·</span>
    <span class="brand-meta">deployment <b>{html.escape(rot["corp_name"])}</b>
      <span class="dim2">{html.escape(rot["corp_domain"])}</span>
      <span class="dim2">sig {html.escape(rot["signature"])}</span>
    </span>
    <div class="top-actions">
      <button type="button" class="top-action" data-tv-toggle
              aria-label="Toggle TV mode" aria-pressed="false"
              title="TV mode — wall display with auto-rotation every 30s">
        <span class="ico" aria-hidden="true">▣</span> TV mode
      </button>
      <button type="button" class="top-action active" data-theme-toggle
              aria-label="Toggle light or dark theme"
              title="Toggle light / dark theme (auto-detects OS preference)">
        <span class="ico" aria-hidden="true" data-theme-icon>☾</span>
        <span data-theme-name>Dark</span>
      </button>
      <button type="button" class="top-action" data-layout-toggle
              aria-haspopup="true" aria-expanded="false"
              aria-label="Open saved arrangements menu"
              title="Saved arrangements of the main dashboard grid">
        <span class="ico" aria-hidden="true">▦</span> Layout
      </button>
      <button type="button" class="top-action" data-notify-toggle
              aria-label="Toggle desktop notifications for critical alerts"
              title="Click to allow browser notifications — desktop pops for critical alerts when the tab is unfocused">
        <span class="ico" aria-hidden="true">◉</span> Notify
        {notify_badge}
      </button>
    </div>
  </div>
  <div class="top-right">
    <span class="dim"><span class="pulse-dot"></span>{sse_label}</span>
    <span class="dim">last refresh <span id="ts">{state["now"]}</span></span>
    <span class="dim">prod {html.escape(rot["subnet"])}</span>
  </div>
</div>
'''


def _render_kpi_strip(state: dict) -> str:
    """The 6-tile KPI strip at the top of the main dashboard."""
    k = state["kpis"]
    sev = state["sev_totals"]
    # Build a sparkline series for alerts from the rate buckets
    rate = state.get("alert_rate_buckets") or []
    alert_series = [b["critical"] + b["high"] + b["medium"] + b["info"]
                     for b in rate[-24:]]  # last ~2h
    crit_series = [b["critical"] for b in rate[-24:]]
    delta = k["alerts_24h_delta"]
    delta_cls = "up" if delta > 0 else "down" if delta < 0 else ""
    delta_sym = "▲" if delta > 0 else "▼" if delta < 0 else "="
    dwell_label = _format_dwell(k["dwell_p50_s"]) if k["dwell_p50_s"] else "—"
    swallowed_pct = (k["decoys_swallowed"] * 100 // max(1, k["decoys_planted"])) \
                      if k["decoys_planted"] else 0
    return f'''
<div class="kpis">
  <div class="kpi">
    <div class="kpi-label">Active engagements</div>
    <div class="kpi-value">{k["active"]}</div>
    {_svg_sparkline([1, 2, 1, 3, 2, 4, 3, 5, k["active"] or 1], "var(--fg-3)")
                    .replace("<svg ", '<svg class="kpi-spark" ')}
  </div>
  <div class="kpi">
    <div class="kpi-label">Alerts (24h)</div>
    <div class="kpi-value">{k["alerts_24h"]}
      <span class="kpi-delta {delta_cls}">{delta_sym} {abs(delta)}%</span></div>
    {_svg_sparkline(alert_series or [0], "var(--sev-medium)")
                    .replace("<svg ", '<svg class="kpi-spark" ')}
  </div>
  <div class="kpi">
    <div class="kpi-label">Counter-AI detected</div>
    <div class="kpi-value">{k["llm_detected"]}
      <span class="kpi-delta">of {k["llm_total"]}</span></div>
    {_svg_sparkline(crit_series or [0], "var(--brand)")
                    .replace("<svg ", '<svg class="kpi-spark" ')}
  </div>
  <div class="kpi">
    <div class="kpi-label">Proof-by-trap</div>
    <div class="kpi-value">{k["proof_by_trap"]}</div>
  </div>
  <div class="kpi">
    <div class="kpi-label">Dwell p50</div>
    <div class="kpi-value">{html.escape(dwell_label)}</div>
  </div>
  <div class="kpi">
    <div class="kpi-label">Decoys swallowed</div>
    <div class="kpi-value">{k["decoys_swallowed"]} / {k["decoys_planted"]}
      <span class="kpi-delta">{swallowed_pct}%</span></div>
  </div>
</div>
'''


_POPOUT_ICON = '''
<span class="icon-btn" data-popout="{name}"
      title="Open in new window (multi-display SOC support)">
  <svg viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.5">
    <path d="M7 1H11V5"/><path d="M11 1L5.5 6.5"/><path d="M9 7V11H1V3H5"/>
  </svg>
</span>
'''


# ===========================================================================
# Main dashboard panels — engagement list + detail + bottom row
# ===========================================================================

def _render_engagement_row(eng: dict, actions: list[dict], *,
                            selected: bool = False) -> str:
    """One row in the engagement list."""
    eid = eng.get("engagement_id", "?")
    obs = eng.get("observed") or {}
    sev = _severity_class(actions)
    if obs.get("attacker_llm_proven_via_trap"):
        sev = "proven"
    conf = float(obs.get("attacker_llm_confidence") or 0.0)
    conf_color = "var(--conf-low)" if conf < 0.55 else \
                  "var(--conf-mid)" if conf < 0.70 else "var(--conf-high)"

    # Deduped action pills, severity-sorted, top 4
    seen: dict[str, str] = {}
    for a in actions:
        seen.setdefault(a["action"], a.get("severity", "info"))
    if obs.get("attacker_llm_proven_via_trap"):
        seen["alert_attacker_llm_proven"] = "critical"
    sorted_actions = sorted(seen.items(),
                             key=lambda kv: (_SEV_RANK.get(kv[1], 9), kv[0]))
    pill_html = []
    for name, s in sorted_actions[:3]:
        cls = "crit" if s == "critical" else \
              "high" if s == "high" else \
              "med" if s == "medium" else "info"
        if name == "alert_attacker_llm_proven":
            cls = "proven"
            name = "LLM PROVEN"
        pill_html.append(f'<span class="pill {cls}">{html.escape(name)}</span>')
    if len(sorted_actions) > 3:
        pill_html.append(f'<span class="pill info">+{len(sorted_actions) - 3}</span>')
    if not pill_html:
        pill_html.append('<span class="dim2">no alerts</span>')

    user = eng.get("claimed_user", "?")
    ip = eng.get("source_ip", "?")
    hosts = eng.get("_hosts") or [eng.get("_host", "?")]
    primary_host = hosts[0]
    host_suffix = f' <span class="dim2">(+{len(hosts) - 1} host{"s" if len(hosts) > 2 else ""})</span>' \
                    if len(hosts) > 1 else ""
    dwell = (eng.get("last_seen_at", 0) or 0) - (eng.get("first_seen_at", 0) or 0)
    n_cmds = sum(len(log.get("commands", [])) for log in eng.get("logs", []))
    last_seen = eng.get("last_seen_at", 0)
    last_ago = _format_ago(last_seen)
    last_ts = datetime.fromtimestamp(last_seen).strftime("%H:%M:%S") if last_seen else "—"
    hay = " ".join([eid, user, ip] + hosts + list(seen.keys())).lower()
    selected_cls = " selected" if selected else ""
    # Filter-chip facets: data-eng-crit (any critical/proven alert),
    # data-eng-llm (LLM-detected attacker), data-eng-last (unix ts).
    # Read by applyFilter() to honor the active filter chip.
    is_crit = "1" if (sev in ("critical", "proven")
                       or any(a.get("severity") == "critical" for a in actions)) else "0"
    is_llm = "1" if (obs.get("attacker_likely_llm")
                      or obs.get("attacker_llm_proven_via_trap")
                      or obs.get("counter_ai_trap_armed")) else "0"

    n_sessions = len(eng.get("logs") or [])
    sessions_suffix = (f' · <span class="dim2 mono" style="font-size: 10px;">'
                       f'{n_sessions} session{"s" if n_sessions != 1 else ""}'
                       f'</span>') if n_sessions > 1 else ""
    n_alerts_total = sum(1 for a in actions)
    # Dormant if last activity is older than 24 hours.  The class is
    # CSS-only (50% opacity); the row is still in the DOM and visible
    # so the operator can scroll and select it.  Use 0 as "never seen"
    # rather than dormant — empty engagements stay full-color so they
    # don't visually disappear.
    age_s = (time.time() - last_seen) if last_seen else 0
    dormant_cls = " dormant" if last_seen and age_s > 86400 else ""
    return f'''
<div class="eng {sev}{selected_cls}{dormant_cls}" data-eng-row data-eng-id="{html.escape(eid)}"
     data-eng-hay="{html.escape(hay)}"
     data-eng-crit="{is_crit}" data-eng-llm="{is_llm}"
     data-eng-last="{int(last_seen) if last_seen else 0}"
     data-eng-first="{int(eng.get('first_seen_at') or 0)}"
     data-eng-dwell="{int(dwell) if dwell else 0}"
     data-eng-conf="{conf:.4f}"
     data-eng-cmds="{n_cmds}"
     data-eng-alerts="{n_alerts_total}"
     data-eng-sessions="{n_sessions}">
  <div class="eng-check" data-eng-check="{html.escape(eid)}"
       title="Multi-select for batch actions"></div>
  <div class="eng-sev-bar"></div>
  <div class="eng-id">{html.escape(eid[:8])}</div>
  <div class="eng-who">
    <span class="who">{html.escape(user)}@{html.escape(ip)}</span>
    <span class="host" title="{html.escape(', '.join(hosts))}">via {html.escape(primary_host)}{host_suffix}{sessions_suffix}</span>
  </div>
  <div class="eng-dwell"><span class="big">{_format_dwell(dwell)}</span>
    <span class="eng-conf-value">dwell</span></div>
  <div class="eng-cmds"><span class="big">{n_cmds}</span>
    <span class="eng-conf-value">commands</span></div>
  <div class="eng-conf">
    <span class="eng-conf-value mono">{conf:.2f}</span>
    <div class="eng-conf-bar">
      <div class="fill" style="width: {conf*100:.0f}%; background: {conf_color};"></div>
    </div>
  </div>
  <div class="pills">{"".join(pill_html)}</div>
  <div class="eng-last"><span class="ago">{last_ago}</span><span class="ts">{last_ts}</span></div>
</div>
'''


_BATCH_BAR_HTML = (
    '<div class="batch-bar" data-batch-bar style="display:none;">'
      '<span><span class="batch-count" data-batch-count>0</span> selected</span>'
      '<button data-batch-action="snapshot" '
              'title="POST /snapshot for each selected engagement">'
        '📸 Snapshot</button>'
      '<button data-batch-action="escalate" '
              'title="POST /escalate for each selected engagement">'
        '↗ Escalate</button>'
      '<span class="batch-spacer"></span>'
      '<button class="batch-clear" data-batch-action="clear" '
              'title="Deselect all">Clear</button>'
    '</div>'
)


def _render_export_links(eid: str) -> str:
    """Compact set of footer-style links for the engagement detail
    panel header.  Each one hits a real /api/engagements/<id>/<kind>
    route — Phase 4 of UI_WIRING.md."""
    safe = html.escape(eid)
    short = html.escape(eid[:8])
    return (
        f'<a class="filter" href="/api/engagements/{safe}/audit" target="_blank" '
        f'title="Plaintext audit rendering ({short})">→ audit</a>'
        f'<a class="filter" href="/api/engagements/{safe}/narrate" target="_blank" '
        f'title="Narrative summary">→ narrate</a>'
        f'<a class="filter" href="/api/engagements/{safe}/ioc.csv" download '
        f'title="IoC bundle as CSV (download)">→ IoC csv</a>'
        f'<a class="filter" href="/api/engagements/{safe}/ioc.json" target="_blank" '
        f'title="IoC bundle as JSON">→ json</a>'
        f'<a class="filter" href="/api/engagements/{safe}/ioc.stix" target="_blank" '
        f'title="STIX 2.1 bundle">→ stix</a>'
        f'<a class="filter" href="/api/engagements/{safe}/sigma.yaml" download '
        f'title="Sigma rule(s) as YAML (download)">→ sigma</a>'
    )


def _render_engagement_detail(eng: dict, actions: list[dict]) -> str:
    """Right-hand engagement detail panel.  Used both in-page and in the
    /panel/engagement/<id> popout (the popout wraps this in chrome)."""
    eid = eng.get("engagement_id", "?")
    obs = eng.get("observed") or {}
    user = eng.get("claimed_user", "?")
    ip = eng.get("source_ip", "?")
    hosts = eng.get("_hosts") or [eng.get("_host", "?")]
    host = ", ".join(hosts)
    first_seen = eng.get("first_seen_at", 0)
    last_seen = eng.get("last_seen_at", 0)
    sev_cls = _severity_class(actions).upper()
    sev_badge_cls = "crit" if sev_cls == "CRITICAL" else \
                     "high" if sev_cls == "HIGH" else \
                     "med" if sev_cls == "MEDIUM" else "info"
    sev_label = "CRIT" if sev_cls == "CRITICAL" else sev_cls[:4]
    conf = float(obs.get("attacker_llm_confidence") or 0.0)
    sigs = obs.get("attacker_llm_signals") or {}
    timing = float(sigs.get("timing") or 0.0)
    lex_avg = float(sigs.get("lexical_avg") or 0.0)
    inj = float(min(1.0, (sigs.get("injections") or 0.0) / 2.0))
    llm_fired = bool(obs.get("attacker_likely_llm"))
    trap_armed = bool(obs.get("counter_ai_trap_armed"))
    llm_gate_cls = "fired" if llm_fired else ""
    trap_gate_cls = "fired" if trap_armed else ""

    # Alert rows (deduped per action name, severity-sorted, top 6).
    # For each name, keep the MOST-RECENT firing as the canonical row
    # so the ack-state + trigger snippet reflect the latest event, and
    # track how many times the name has fired in this engagement.
    seen: dict[str, dict] = {}
    hit_counts: dict[str, int] = {}
    for a in actions:
        nm = a.get("action") or "?"
        hit_counts[nm] = hit_counts.get(nm, 0) + 1
        prev = seen.get(nm)
        if prev is None or (a.get("ts_offset_s") or 0) >= (prev.get("ts_offset_s") or 0):
            seen[nm] = a
    alert_rows = []
    eid = eng.get("engagement_id", "")
    total_firings = sum(hit_counts.values())
    for name, a in sorted(seen.items(),
                           key=lambda kv: (_SEV_RANK.get(kv[1].get("severity", "info"), 9), kv[0]))[:6]:
        s = a.get("severity", "info")
        cls = "crit" if s == "critical" else "high" if s == "high" else "med"
        trig = a.get("triggered_by", "")[:100]
        # Correlation timestamp for "click alert → scroll to command".
        # Alerts store ts_offset_s relative to first_seen_at; the command
        # row uses absolute unix ts, so we resolve here.
        alert_ts = int(round((a.get("ts_offset_s") or 0) + (first_seen or 0)))
        # Per-name hit count — show "× N" on the row when the same
        # detection has fired more than once in this engagement.
        hits = hit_counts.get(name, 1)
        hits_badge = (f' <span class="dim2 mono" style="font-size: 10px;'
                      f' margin-left: 4px;">× {hits}</span>') if hits > 1 else ""
        # Phase 2: render ack state.  Ack'd alerts get a dimmed look + a
        # small "ack'd by X" annotation and the action button flips to
        # "Un-ack" (so the 10s undo and explicit-revert both work).
        acked_at = a.get("acknowledged_at")
        acked_by = a.get("acknowledged_by")
        ack_meta = ""
        ack_btn_label = "Acknowledge"
        row_extra_cls = ""
        if acked_at and acked_by:
            ack_meta = (f' <span class="dim2 mono" style="margin-left:6px;">'
                        f'· ack’d by {html.escape(acked_by)} '
                        f'{_format_ago(acked_at)}</span>')
            ack_btn_label = "Un-ack"
            row_extra_cls = " acked"
        alert_rows.append(f'''
        <div class="alert{row_extra_cls}" data-alert-row
             data-alert-ts="{alert_ts}"
             title="Click to scroll to the matching command in the timeline">
          <span class="alert-sev {cls}">{s[:4].upper()}</span>
          <span class="alert-name">{html.escape(name)}{hits_badge}{ack_meta}</span>
          <span class="alert-ts">
            <button class="ack-btn" data-ack-eng="{html.escape(eid)}"
                    data-ack-action="{html.escape(name)}"
                    data-ack-state="{'acked' if acked_at else 'pending'}">
              {ack_btn_label}
            </button>
          </span>
          <div class="alert-trigger">{html.escape(trig)}</div>
        </div>
        ''')
    if not alert_rows:
        alert_rows.append('<div class="dim" style="padding: 10px 0;">No alerts fired in this engagement.</div>')

    # Phase 3: quick-action row above the alerts list
    kill_req = eng.get("_kill_request")
    kill_state = "pending" if (kill_req and kill_req.get("status") == "pending") else \
                  "killed" if (kill_req and kill_req.get("status") == "killed") else \
                  "ready"
    kill_label = ("Kill pending…" if kill_state == "pending"
                   else "Killed" if kill_state == "killed"
                   else "Kill session")
    snapshots = eng.get("_snapshots") or []
    snap_count_badge = f' <span class="dim2">({len(snapshots)})</span>' if snapshots else ""
    # Pending alerts (Ack-all enabled) and source IP for Isolate.
    pending_actions = [n for n, a in seen.items() if not a.get("acknowledged_at")]
    pending_badge = (f' <span class="dim2">({len(pending_actions)})</span>'
                      if pending_actions else "")
    ack_all_disabled = "" if pending_actions else " disabled"
    ack_all_title = (f"Ack {len(pending_actions)} pending alert(s) in this engagement"
                      if pending_actions
                      else "No pending alerts to acknowledge")
    pending_attr = " ".join(html.escape(n) for n in pending_actions)
    src_ip = (eng.get("source_ip") or "").strip()
    # Disable Isolate unless source_ip is a literal address (the FastAPI
    # /mfa/decisions/<ip> route validates it before writing).
    try:
        import ipaddress as _ipaddr
        _ipaddr.ip_address(src_ip)
        ip_ok = True
    except (ValueError, TypeError):
        ip_ok = False
    isolate_disabled = "" if ip_ok else " disabled"
    isolate_title = (f"Write state-docker/mfa/{src_ip}.fail — "
                     f"orchestrator's routing layer treats this IP as untrusted on next decision"
                     if ip_ok
                     else "Source IP missing or not a literal address; cannot isolate")
    quick_actions_html = f'''
    <div class="quick-actions">
      <button class="action-btn primary" data-quick-action="ack-all"
              data-eng="{html.escape(eid)}"
              data-pending-actions="{pending_attr}"
              title="{html.escape(ack_all_title)}"{ack_all_disabled}>
        ✓ Acknowledge all{pending_badge}
      </button>
      <button class="action-btn" data-quick-action="snapshot"
              data-eng="{html.escape(eid)}" title="Tarball persistence + logs + acks + notes to state-docker/snapshots/">
        📋 Snapshot{snap_count_badge}
      </button>
      <button class="action-btn" data-quick-action="escalate"
              data-eng="{html.escape(eid)}" title="Fire configured chatops connectors (Slack / Teams / PagerDuty)">
        ↗ Escalate L2
      </button>
      <button class="action-btn" data-quick-action="isolate"
              data-eng="{html.escape(eid)}" data-ip="{html.escape(src_ip)}"
              title="{html.escape(isolate_title)}"{isolate_disabled}>
        ⌫ Isolate IP
      </button>
      <button class="action-btn danger" data-quick-action="kill"
              data-eng="{html.escape(eid)}" data-kill-state="{kill_state}"
              aria-label="Kill SSH session — hold for 1 second to confirm"
              title="Queue a kill request; orchestrator drops the SSH connection on next poll. Hold (mouse / touch / Space) for 1 second to confirm.">
        <span class="hold-fill" aria-hidden="true"></span>
        ⏹ {kill_label}
      </button>
    </div>
    '''

    # Phase 3: operator notes section (existing notes + composer)
    notes = eng.get("notes") or []
    notes_html = []
    for n in notes:
        body_safe = html.escape(n.get("body", ""))
        body_safe = body_safe.replace("\n", "<br>")
        # Bare-minimum markdown: **bold** and `code`
        body_safe = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", body_safe)
        body_safe = re.sub(r"`([^`]+)`", r"<code>\1</code>", body_safe)
        notes_html.append(f'''
        <div class="note-item">
          <div class="note-header">
            <span class="note-author">{html.escape(n.get("author", "anonymous"))}</span>
            <span class="note-ts">{_format_ago(n.get("ts", 0))}</span>
            <button class="note-delete" data-note-delete="{html.escape(n.get("id", ""))}"
                    data-eng="{html.escape(eid)}" title="Remove this note">×</button>
          </div>
          <div class="note-body">{body_safe}</div>
        </div>
        ''')
    if not notes_html:
        notes_html.append('<div class="dim" style="padding: 6px 0;">No notes yet — add one for the next analyst on shift.</div>')

    # Command timeline (last 20)
    all_cmds: list[dict] = []
    for log in eng.get("logs", []):
        all_cmds.extend(log.get("commands", []))
    all_cmds.sort(key=lambda c: c.get("ts", 0))
    cmd_rows = []
    alert_times = {round(a.get("ts_offset_s", 0) + first_seen) for a in actions}
    for c in all_cmds[-20:]:
        ts = c.get("ts", 0)
        ts_str = datetime.fromtimestamp(ts).strftime("%H:%M:%S") if ts else "—"
        ts_full = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC") if ts else "—"
        src = (c.get("response_source", "?") or "?").split("+")[0]
        src_cls = src if src in ("cache", "vfs", "sim-bot", "llm", "find", "error") else ""
        if src.startswith("vfs-"):
            src_cls = "vfs"
        full_cmd = c.get("cmd", "") or ""
        cmd_text = full_cmd[:80]
        full_resp_src = c.get("response_source", "?") or "?"
        resp_preview = c.get("response_preview") or ""
        alerted = round(ts) in alert_times
        row_cls = "cmd alerted" if alerted else "cmd"
        src_text = "!ALERT" if alerted else src
        src_render_cls = "alert" if alerted else src_cls
        cmd_rows.append(f'''
        <div class="{row_cls}" data-cmd-row
             data-cmd-ts="{int(round(ts))}"
             data-cmd-ts-display="{html.escape(ts_full)}"
             data-cmd-src="{html.escape(full_resp_src)}"
             data-cmd-text="{html.escape(full_cmd)}"
             data-cmd-resp="{html.escape(resp_preview)}"
             title="Click to inspect full command + response">
          <span class="cmd-ts">{ts_str}</span>
          <span class="cmd-src {src_render_cls}">{html.escape(src_text)}</span>
          <span class="cmd-text">{html.escape(cmd_text)}</span>
        </div>
        ''')
    if not cmd_rows:
        cmd_rows.append('<div class="dim" style="padding: 10px 0;">No commands yet.</div>')

    # ------- Files modified (UI_WIRING §B.6) -----------------------------
    # Surface every VFS path the attacker has written to or deleted,
    # with size deltas vs the planted baseline.  Click → /file-diff
    # modal showing the full before/after.  Tampered list is bounded by
    # session scope, so even a busy session keeps this small (~20).
    vfs_blob = eng.get("vfs") or {}
    tampered = list(vfs_blob.get("tampered") or [])
    vfs_files = vfs_blob.get("files") or {}
    vfs_baseline = vfs_blob.get("baseline") or {}
    vfs_deleted = set(vfs_blob.get("deleted") or [])
    files_rows = []
    for path in sorted(tampered)[:30]:
        cur = vfs_files.get(path)
        base = vfs_baseline.get(path)
        if path in vfs_deleted:
            cur_label = "deleted"
            cur_size = 0
        elif cur is None:
            cur_label = "—"
            cur_size = 0
        else:
            cur_size = len(cur)
            cur_label = f"{cur_size} B"
        base_size = len(base) if base is not None else 0
        base_label = f"{base_size} B" if base is not None else "(none planted)"
        delta = cur_size - base_size
        delta_cls = "delta-up" if delta > 0 else "delta-down" if delta < 0 else "delta-zero"
        delta_label = f"{delta:+d} B" if delta else "0 B"
        is_del = "deleted" if path in vfs_deleted else ""
        files_rows.append(
            f'<li class="file-mod-row{(" deleted" if is_del else "")}" '
            f'data-file-mod-row data-eng="{html.escape(eid)}" '
            f'data-file-path="{html.escape(path)}" '
            'title="Click to view baseline vs current diff">'
              f'<span class="file-mod-path mono">{html.escape(path)}</span>'
              f'<span class="file-mod-base mono dim2">baseline: {html.escape(base_label)}</span>'
              f'<span class="file-mod-cur mono">→ {html.escape(cur_label)}</span>'
              f'<span class="file-mod-delta mono {delta_cls}">{html.escape(delta_label)}</span>'
            '</li>'
        )
    files_section = ""
    if files_rows:
        files_section = (
            '<div class="panel-header" style="border-bottom: 1px solid var(--border-2);">'
              '<span>Files modified</span>'
              f'<span class="count">{len(tampered)}</span>'
            '</div>'
            f'<ul class="file-mod-list">{"".join(files_rows)}</ul>'
        )

    # ------- Proof-by-trap banner (UI_WIRING §B.9) -----------------------
    # When `counter_ai_trap_proof` is present, the counter-AI detector
    # has CAPTURED the attacker echoing a planted trap marker back at
    # us — that's irrefutable evidence the attacker is an LLM consuming
    # our planted content.  Show the proof inline above the gauge so
    # the operator sees it before anything else.
    trap_proof = obs.get("counter_ai_trap_proof") or {}
    proof_banner = ""
    if trap_proof.get("command"):
        proof_at = trap_proof.get("at") or 0
        proof_at_str = datetime.fromtimestamp(proof_at).strftime("%Y-%m-%d %H:%M:%S UTC") if proof_at else "—"
        proof_banner = (
            '<div class="proof-banner" role="status" '
            'aria-label="Counter-AI proof — attacker echoed planted trap marker">'
              '<div class="proof-head">'
                '<span class="proof-icon" aria-hidden="true">🎯</span>'
                '<span class="proof-title">LLM ATTACKER PROVEN VIA TRAP</span>'
                f'<span class="proof-ts mono dim2">{html.escape(proof_at_str)}</span>'
              '</div>'
              '<div class="proof-body">'
                '<span class="dim2 mono" style="font-size: 10px;">'
                'Attacker echoed planted trap marker '
                f'<code>{html.escape(trap_proof.get("marker", "?"))}</code> '
                'in this command:</span>'
                f'<pre class="proof-cmd mono">$ {html.escape(trap_proof.get("command", ""))}</pre>'
              '</div>'
            '</div>'
        )

    # ------- Real confidence-history trend (UI_WIRING §B.3) --------------
    # Server-rendered delta label over the actual per-command history
    # captured by the counter-AI detector.  Replaces the client-side
    # localStorage approximation.  (We tried a tiny inline sparkline
    # inside .gauge-center but it stretched in the flex column and
    # produced a vertical artifact; the text delta is enough.)
    history = obs.get("attacker_llm_history") or []
    trend_label = ""
    trend_spark = ""
    if history and len(history) >= 2:
        recent = history[-min(40, len(history)):]
        first_v = float(recent[0].get("conf", 0) or 0)
        last_v  = float(recent[-1].get("conf", 0) or 0)
        delta = last_v - first_v
        first_ts = float(recent[0].get("ts", 0) or 0)
        last_ts  = float(recent[-1].get("ts", 0) or 0)
        span_min = max(0, int((last_ts - first_ts) / 60))
        span_label = (f"{span_min}m" if span_min >= 1 else f"{int(last_ts - first_ts)}s")
        if abs(delta) >= 0.02:
            arrow = "▲" if delta > 0 else "▼"
            cls   = "up" if delta > 0 else "down"
            trend_label = (
                f'<span class="{cls}">{arrow} {first_v:.2f} → {last_v:.2f}</span>'
                f' <span class="dim2">· {span_label}</span>'
            )
        else:
            trend_label = '<span class="dim">steady</span>'

    return f'''
<div class="detail-header">
  <div class="detail-id">
    <span class="badge-sev {sev_badge_cls}">{sev_label}</span>
    <span class="eid">{html.escape(eid)}</span>
  </div>
  <div class="detail-meta">
    <div class="k">User</div>      <div class="v">{html.escape(user)} <span class="dim">(claimed)</span></div>
    <div class="k">Source IP</div> <div class="v">{html.escape(ip)}</div>
    <div class="k">First seen</div><div class="v">{datetime.fromtimestamp(first_seen).strftime("%Y-%m-%d %H:%M:%S UTC") if first_seen else "—"}</div>
    <div class="k">Last seen</div> <div class="v">{datetime.fromtimestamp(last_seen).strftime("%Y-%m-%d %H:%M:%S UTC") if last_seen else "—"} <span class="dim">({_format_ago(last_seen)})</span></div>
    <div class="k">Decoy host</div><div class="v">{html.escape(host)}</div>
  </div>
</div>
{proof_banner}
<div class="gauge-wrap">
  <div class="gauge">{_svg_gauge(conf)}
    <div class="gauge-center">
      <div class="gauge-val">{conf:.2f}</div>
      <div class="gauge-label">composite</div>
      <div class="gauge-trend gauge-trend-server"
           data-trend-eid="{html.escape(eid)}"
           data-trend-conf="{conf:.4f}">
        {trend_spark}{trend_label}
      </div>
    </div>
  </div>
  <div class="signals">
    <div class="signal">
      <span class="signal-name">timing</span>
      <div class="signal-bar"><div class="signal-fill timing" style="width: {timing*100:.0f}%;"></div></div>
      <span class="signal-val">{timing:.2f}</span>
    </div>
    <div class="signal">
      <span class="signal-name">lexical</span>
      <div class="signal-bar"><div class="signal-fill lex" style="width: {lex_avg*100:.0f}%;"></div></div>
      <span class="signal-val">{lex_avg:.2f}</span>
    </div>
    <div class="signal">
      <span class="signal-name">injection</span>
      <div class="signal-bar"><div class="signal-fill inj" style="width: {inj*100:.0f}%;"></div></div>
      <span class="signal-val">{inj:.2f}</span>
    </div>
    <div class="gate-pills">
      <span class="gate-pill {llm_gate_cls}">LLM ≥ 0.55 {("FIRED" if llm_fired else "held")}</span>
      <span class="gate-pill {trap_gate_cls}">TRAP ≥ 0.70 {("ARMED" if trap_armed else "held")}</span>
    </div>
  </div>
</div>

<div class="panel-header" style="border-bottom: 1px solid var(--border-2);">
  <span>Quick actions</span>
</div>
{quick_actions_html}

<div class="panel-header" style="border-bottom: 1px solid var(--border-2);">
  <span>Alerts</span>
  <span class="count">
    <span data-alerts-pending data-eng="{html.escape(eid)}">{len(pending_actions)}</span>
    <span class="dim2 mono" style="font-size: 10px;"> pending · {len(seen)} unique · {total_firings} total firings</span>
  </span>
</div>
<div class="alerts-list">{"".join(alert_rows)}</div>

{files_section}

<div class="panel-header" style="border-bottom: 1px solid var(--border-2);">
  <span>Operator notes</span>
  <span class="count">{len(notes)}</span>
</div>
<div class="notes-list">{"".join(notes_html)}</div>
<div class="note-composer">
  <div class="note-toolbar" data-note-toolbar="{html.escape(eid)}"
       role="toolbar" aria-label="Markdown formatting">
    <button type="button" class="note-tb-btn" data-md="bold"
            title="Bold (Ctrl+B) — wraps selection in **…**"
            aria-label="Bold"><b>B</b></button>
    <button type="button" class="note-tb-btn" data-md="italic"
            title="Italic (Ctrl+I) — wraps selection in *…*"
            aria-label="Italic"><i>I</i></button>
    <button type="button" class="note-tb-btn" data-md="code"
            title="Inline code (Ctrl+E) — wraps selection in `…`"
            aria-label="Inline code"><span class="mono">`</span>c<span class="mono">`</span></button>
    <button type="button" class="note-tb-btn" data-md="list"
            title="Bullet list — prepends &quot;- &quot; to selected lines"
            aria-label="Bullet list">•&nbsp;</button>
    <button type="button" class="note-tb-btn" data-md="quote"
            title="Block quote — prepends &quot;&gt; &quot; to selected lines"
            aria-label="Block quote">❝</button>
  </div>
  <textarea class="note-input" placeholder="Add a note for the next analyst…  **bold** and `code` work."
            id="note-input-{html.escape(eid)}" name="note-input-{html.escape(eid)}"
            data-note-input="{html.escape(eid)}"></textarea>
  <div class="note-composer-foot">
    <span class="dim2 mono" style="font-size: 10px;">markdown stored · **bold** `code` supported</span>
    <button class="note-save" data-note-save="{html.escape(eid)}">Save note</button>
  </div>
</div>

<div class="panel-header" style="border-bottom: 1px solid var(--border-2);">
  <span>Command timeline (last 20)</span>
  <span class="count">{len(all_cmds)}</span>
</div>
<div class="timeline">{"".join(cmd_rows)}</div>
'''


def _render_dns_feed_html(
    state: dict,
    *,
    max_rows: int = 30,
    result_filter: str | None = None,
) -> str:
    """Compact DNS feed used on the main dashboard bottom row + as the
    body of the /panel/dns-feed popout (which sizes it up via TV mode).

    `result_filter` restricts to 'resolved' / 'blocked' / 'nxdomain';
    None (or 'all') keeps every result type.  Filter happens BEFORE
    the `max_rows` tail so the popout's "show me only blocked" view
    isn't dominated by older resolved queries pushing them out."""
    entries = state.get("dns_parsed") or []
    if result_filter and result_filter != "all":
        entries = [e for e in entries if e.get("result") == result_filter]
    entries = entries[-max_rows:]
    rows = []
    for entry in entries:
        cls = entry["result"]   # 'blocked' / 'nxdomain' / 'resolved'
        rows.append(f'''
        <div class="dns-row">
          <span class="dns-ts">{html.escape(entry["ts"][:8])}</span>
          <span class="dns-host">{html.escape(entry["host"])}</span>
          <span class="dns-type">{html.escape(entry["qtype"])}</span>
          <span class="dns-result {cls}">{cls.upper()}</span>
        </div>
        ''')
    if not rows:
        rows.append('<div class="dim" style="padding: 12px 0;">No DNS queries yet.</div>')
    return f'<div class="dns-feed">{"".join(rows)}</div>'


def _render_dns_top_list(top: list, *, kind: str) -> str:
    """Right-side list for the DNS popout: top blocked / top NXDOMAIN
    hosts in the current docker-log window.  `kind` selects the pill
    class so the row colour matches its result-type."""
    if not top:
        return (f'<div class="dim" style="padding: 10px 12px;">'
                f'No {html.escape(kind)} queries in the window.</div>')
    pill_cls = "crit" if kind == "blocked" else "med"
    rows = []
    for row in top:
        rows.append(
            '<li class="dns-top-row">'
            f'<span class="pill {pill_cls}">{html.escape(kind[:4].upper())}</span>'
            f'<span class="dns-top-host mono">{html.escape(row.get("host", "?"))}</span>'
            f'<span class="dns-top-count mono">{int(row.get("count", 0))}</span>'
            '</li>'
        )
    return '<ul class="dns-top-list">' + "".join(rows) + '</ul>'


def _render_dns_kpi_tiles(state: dict) -> str:
    """Four KPI tiles: Total / Resolved / Blocked / NXDOMAIN.  Computed
    in dashboard.py rather than calling /api/dns/stats so the popout's
    initial paint doesn't need a round trip."""
    from plenith.aggregations import dns_stats
    stats = dns_stats(state.get("dns_parsed") or [])
    return (
        '<div class="dns-kpis" data-dns-kpis>'
          '<div class="dns-kpi">'
            f'<div class="dns-kpi-v" data-dns-kpi="total">{stats["total"]}</div>'
            '<div class="dns-kpi-l">total</div>'
          '</div>'
          '<div class="dns-kpi resolved">'
            f'<div class="dns-kpi-v" data-dns-kpi="resolved">{stats["resolved"]}</div>'
            '<div class="dns-kpi-l">resolved</div>'
          '</div>'
          '<div class="dns-kpi blocked">'
            f'<div class="dns-kpi-v" data-dns-kpi="blocked">{stats["blocked"]}</div>'
            '<div class="dns-kpi-l">blocked / exfil</div>'
          '</div>'
          '<div class="dns-kpi nxdomain">'
            f'<div class="dns-kpi-v" data-dns-kpi="nxdomain">{stats["nxdomain"]}</div>'
            '<div class="dns-kpi-l">nxdomain</div>'
          '</div>'
        '</div>'
    )


_ALERT_SEVERITIES = ("critical", "high", "medium", "info")
_SEV_COLOR_VAR = {
    "critical": "var(--sev-critical)",
    "high":     "var(--sev-high)",
    "medium":   "var(--sev-medium)",
    "info":     "var(--sev-info)",
}


def _render_alert_rate_chart_svg(
    buckets: list,
    *,
    compare: list | None = None,
    height: int = 80,
    severities: list[str] | None = None,
    mode: str = "stacked",
    range_label: str = "6h",
) -> str:
    """Bucketed alert-rate chart as SVG.  Supports two modes:

    - ``stacked`` — stacked bars by severity (legacy behaviour).
    - ``line``    — one polyline per severity, no fill.

    `severities` restricts which severity layers are drawn.  When
    `compare` is supplied (same shape as `buckets`, the prior-window
    series), it's overlaid as a dashed polyline so the operator can see
    above/below-trend at a glance.
    """
    if not buckets:
        return '<div class="dim" style="padding: 18px;">No alert-rate data yet.</div>'
    sev_filter = list(severities) if severities else list(_ALERT_SEVERITIES)
    width = 600
    bar_w = max(2, (width - 40) // max(1, len(buckets)))

    def _bucket_total(b: dict) -> int:
        return sum(int(b.get(s, 0) or 0) for s in sev_filter)

    cur_totals = [_bucket_total(b) for b in buckets]
    cmp_totals = []
    if compare and len(compare) == len(buckets):
        cmp_totals = [_bucket_total(b) for b in compare]
    max_total = max([1] + cur_totals + cmp_totals) or 1
    parts: list[str] = []

    if mode == "line":
        # One polyline per visible severity — no fill, color-keyed.
        for sev in sev_filter:
            color = _SEV_COLOR_VAR[sev]
            pts: list[str] = []
            for i, b in enumerate(buckets):
                n = int(b.get(sev, 0) or 0)
                x = 20 + i * bar_w + bar_w / 2
                y = (height - 4) - int((n / max_total) * (height - 12))
                pts.append(f"{x:.1f},{y:.1f}")
            parts.append(
                f'<polyline fill="none" stroke="{color}" stroke-width="1.4" '
                f'opacity="0.9" points="{" ".join(pts)}"/>'
            )
    else:
        # Stacked bars — same draw order as legacy renderer
        # (medium → high → critical → info) so the visual stays familiar.
        layer_order = [s for s in ("medium", "high", "critical", "info")
                       if s in sev_filter]
        for i, b in enumerate(buckets):
            x = 20 + i * bar_w
            y_base = height - 4
            for sev in layer_order:
                n = int(b.get(sev, 0) or 0)
                if n == 0:
                    continue
                bar_h = int((n / max_total) * (height - 12))
                parts.append(
                    f'<rect x="{x}" y="{y_base - bar_h}" '
                    f'width="{bar_w - 1}" height="{bar_h}" '
                    f'fill="{_SEV_COLOR_VAR[sev]}" opacity="0.85"/>'
                )
                y_base -= bar_h

    if cmp_totals:
        pts = []
        for i, total in enumerate(cmp_totals):
            x = 20 + i * bar_w + bar_w / 2
            y = (height - 4) - int((total / max_total) * (height - 12))
            pts.append(f"{x:.1f},{y:.1f}")
        parts.append(
            f'<polyline fill="none" stroke="var(--fg-3)" stroke-width="1.2" '
            f'stroke-dasharray="4 3" opacity="0.6" '
            f'points="{" ".join(pts)}"/>'
        )
        parts.append(
            f'<text x="{width - 110}" y="14" fill="var(--fg-3)" '
            f'font-family="monospace" font-size="9" opacity="0.8">'
            f'- - prior {html.escape(range_label)}</text>'
        )

    # Time axis ticks — three labels: left edge, mid, now.
    label_left = "-" + range_label
    label_mid  = "-" + range_label[:-1] + "/2" if len(range_label) > 1 else ""
    parts.append(f'<text x="20" y="{height - 0}" fill="var(--fg-4)" '
                 f'font-family="monospace" font-size="9">{html.escape(label_left)}</text>')
    if label_mid:
        parts.append(f'<text x="{width // 2}" y="{height - 0}" fill="var(--fg-4)" '
                     f'font-family="monospace" font-size="9">{html.escape(label_mid)}</text>')
    parts.append(f'<text x="{width - 40}" y="{height - 0}" fill="var(--fg-4)" '
                 f'font-family="monospace" font-size="9">now</text>')
    return (f'<svg class="sparkline-large" viewBox="0 0 {width} {height}" '
            f'preserveAspectRatio="none">{"".join(parts)}</svg>')


def _render_alert_rate_chart(state: dict, *, height: int = 80) -> str:
    """Back-compat wrapper used by the main dashboard render path."""
    return _render_alert_rate_chart_svg(
        state.get("alert_rate_buckets") or [],
        compare=state.get("alert_rate_compare"),
        height=height,
    )


def _render_top_alerts_list(top: dict) -> str:
    """Right-side list for /panel/alert-rate: top N alert names within
    the chosen window, with a severity chip + count + inline sparkline."""
    alerts = top.get("alerts") or []
    if not alerts:
        return ('<div class="dim" style="padding: 14px 18px;">'
                'No alerts in the selected window.</div>')
    rows = []
    for a in alerts:
        sev = a.get("severity", "info")
        cls = "crit" if sev == "critical" else \
              "high" if sev == "high" else \
              "med"  if sev == "medium" else "info"
        spark = a.get("sparkline") or []
        spark_svg = ""
        if spark:
            vmax = max(spark) or 1
            sw = 80
            sh = 20
            bw = max(1, (sw - 2) / max(1, len(spark)))
            bars = []
            for i, v in enumerate(spark):
                if v == 0:
                    continue
                bh = int((v / vmax) * (sh - 2))
                bx = 1 + i * bw
                by = sh - 1 - bh
                bars.append(
                    f'<rect x="{bx:.1f}" y="{by}" width="{bw - 0.4:.1f}" '
                    f'height="{bh}" fill="{_SEV_COLOR_VAR.get(sev, "var(--sev-info)")}" '
                    f'opacity="0.85"/>'
                )
            spark_svg = (
                f'<svg class="alert-top-spark" viewBox="0 0 {sw} {sh}" '
                f'preserveAspectRatio="none" width="{sw}" height="{sh}" '
                f'aria-hidden="true">{"".join(bars)}</svg>'
            )
        rows.append(
            '<li class="alert-top-row">'
            f'<span class="pill {cls}">{html.escape(sev[:4].upper())}</span>'
            f'<span class="alert-top-name mono">{html.escape(a.get("name", "?"))}</span>'
            f'{spark_svg}'
            f'<span class="alert-top-count mono">{int(a.get("count", 0))}</span>'
            '</li>'
        )
    return '<ul class="alert-top-list">' + "".join(rows) + '</ul>'


# Maps each time-range key to (seconds_back, bucket_seconds, n_buckets).
_ALERT_RANGES = {
    "15m": (900,      30,    None),
    "1h":  (3600,     120,   None),
    "6h":  (21600,    300,   None),
    "24h": (86400,    900,   None),
    "7d":  (604800,   7200,  None),
    "30d": (2592000,  43200, None),
}


def _render_heatmap_grid(grid: dict) -> str:
    """Activity heatmap, one row per host × 24 hour-of-day cells.

    Takes the grid dict directly (mapping hostname → [c0..c23]) so the
    fragment endpoint can hand in fresh aggregation results without
    rewriting them into a `state` dict shape.  Each cell carries
    data-host + data-hour so the click handler can drill in."""
    if not grid:
        return '<div class="dim" style="padding: 18px;">No host activity yet.</div>'
    # Bucket counts to color classes
    vmax = max((max(row) for row in grid.values()), default=0) or 1
    def cell_class(v: int) -> str:
        if v == 0:           return "hcell"
        r = v / vmax
        if r >= 0.85:        return "hcell c5"
        if r >= 0.65:        return "hcell c4"
        if r >= 0.45:        return "hcell h5"
        if r >= 0.30:        return "hcell h4"
        if r >= 0.15:        return "hcell h3"
        if r >= 0.05:        return "hcell h2"
        return "hcell h1"
    rows = []
    for host in sorted(grid.keys()):
        cells = "".join(
            f'<div class="{cell_class(v)}" data-heatmap-cell '
            f'data-host="{html.escape(host)}" data-hour="{hr}" '
            f'title="{html.escape(host)} · hour {hr:02d} · {v} event(s)">'
            f'</div>'
            for hr, v in enumerate(grid[host])
        )
        rows.append(f'''
        <div class="heatmap-row">
          <span class="heatmap-label">{html.escape(host)}</span>
          <div class="heatmap-cells">{cells}</div>
        </div>
        ''')
    return f'<div class="heatmap">{"".join(rows)}</div>'


def _render_heatmap(state: dict) -> str:
    """Back-compat wrapper used by the main dashboard render path."""
    return _render_heatmap_grid(state.get("host_activity") or {})


def _render_activity_summary(result: dict) -> str:
    """Three KPI tiles below the heatmap header: peak hour, busiest
    decoy, total event count.  Takes an activity_heatmap() result."""
    grid = result.get("hosts") or {}
    total = result.get("total")
    if total is None:
        total = sum(sum(row) for row in grid.values())
    peak_hour    = result.get("peak_hour")
    busiest_host = result.get("busiest_host")
    n_hosts = len(grid)
    peak_str = f"{int(peak_hour):02d}:00" if peak_hour is not None else "—"
    busy_str = busiest_host or "—"
    return (
        '<div class="activity-summary" data-activity-summary>'
          '<div class="activity-stat">'
            f'<div class="activity-stat-v">{total}</div>'
            '<div class="activity-stat-l">events</div>'
          '</div>'
          '<div class="activity-stat">'
            f'<div class="activity-stat-v">{n_hosts}</div>'
            '<div class="activity-stat-l">hosts</div>'
          '</div>'
          '<div class="activity-stat">'
            f'<div class="activity-stat-v mono">{peak_str}</div>'
            '<div class="activity-stat-l">peak hour</div>'
          '</div>'
          '<div class="activity-stat">'
            f'<div class="activity-stat-v mono">{html.escape(busy_str)}</div>'
            '<div class="activity-stat-l">busiest decoy</div>'
          '</div>'
        '</div>'
    )


_ACTIVITY_RANGES = {
    "24h":  86400,
    "7d":   604800,
    "30d":  2592000,
    "90d":  7776000,
}


# ===========================================================================
# Page-level renderers
# ===========================================================================

def _render_main_panels(state: dict, *, selected_eid_hint: str = "") -> str:
    """The dynamic subtree that SSE swaps every <refresh> seconds.

    `selected_eid_hint` lets the SSE caller pin a specific engagement as
    the rendered selection so the detail panel doesn't flip-flop between
    engs[0] and the operator's pick when a new engagement arrives — the
    race that produces the visible jitter when sessions update mid-tick.

    Backward-compat surface: callers (tests) expect a string of HTML
    containing the engagement-count header ("Engagements (N)"), the
    placeholder for empty state, and the topbar-free shape.  We keep
    those guarantees while emitting the new design.
    """
    engs = state["engagements"]
    actions_by_eng = state["actions_by_eng"]
    n = len(engs)

    # Build engagement rows (or the empty-state placeholder).  We still
    # render the KPI strip + bottom row (DNS / alert rate / heatmap) so
    # the operator gets ambient awareness even when no attacker is
    # currently active.
    row_html = []
    detail_pop_name = "engagements"
    detail_html = ('<div class="dim" style="padding: 18px;">'
                    'No engagements yet — connect with '
                    '<code>ssh -p 22000 jdoe@127.0.0.1</code> in another '
                    'terminal.</div>')
    if n > 0:
        # Honor the operator's pick when it's still in the list; fall
        # back to engs[0] otherwise.  Accepts an 8-char prefix or full id.
        sel_eng = engs[0]
        if selected_eid_hint:
            match = next((e for e in engs
                          if e.get("engagement_id", "").startswith(selected_eid_hint)),
                         None)
            if match is not None:
                sel_eng = match
        selected_eid = sel_eng["engagement_id"]
        for e in engs:
            actions = actions_by_eng.get(e["engagement_id"], [])
            row_html.append(_render_engagement_row(
                e, actions, selected=(e["engagement_id"] == selected_eid),
            ))
        sel_actions = actions_by_eng.get(selected_eid, [])
        detail_html = _render_engagement_detail(sel_eng, sel_actions)
        detail_pop_name = "engagement/" + html.escape(selected_eid)
    else:
        row_html.append('<div class="dim" style="padding: 18px;">'
                         'No engagements yet — connect with '
                         '<code>ssh -p 22000 jdoe@127.0.0.1</code> in another '
                         'terminal.</div>')

    # Bottom row: alert rate + DNS feed + heatmap
    chart_svg = _render_alert_rate_chart(state)
    dns_html = _render_dns_feed_html(state)
    heatmap_html = _render_heatmap(state)

    # Drag handle inserted at the start of each panel-header.  Lets the
    # operator rearrange the main dashboard grid; JS persists arrangement
    # in localStorage and re-applies after every SSE swap.
    # Drag handle works two ways: mouse/touch HTML5 drag-and-drop OR
    # keyboard (focus the handle, press Enter/Space to open a "move to"
    # picker, pick a destination panel).  tabindex=0 + role=button makes
    # it discoverable to assistive tech.
    drag = ('<span class="drag-handle" data-drag-handle draggable="true"'
            ' tabindex="0" role="button"'
            ' title="Drag (mouse) or press Enter (keyboard) to rearrange panels"'
            ' aria-label="Rearrange panel — drag, or press Enter for a destination picker">'
            '⋮⋮</span>')
    return f'''
{_render_kpi_strip(state)}
<div class="main" data-grid-row="main">
  <div class="panel" data-tv-section data-panel-id="engagements">
    <div class="panel-header">
      {drag}
      <span>Engagements ({n})</span>
      <div class="actions">
        <button type="button" class="filter active" data-filter-chip="all"
                aria-pressed="true"
                title="Show all engagements">all <span class="dim2 mono">({n})</span></button>
        <button type="button" class="filter" data-filter-chip="critical"
                aria-pressed="false"
                title="Only engagements with a critical or proven alert">critical</button>
        <button type="button" class="filter" data-filter-chip="llm"
                aria-pressed="false"
                title="Only engagements where the attacker is LLM-detected or LLM-proven">llm-detected</button>
        {_POPOUT_ICON.format(name="engagements")}
      </div>
    </div>
    <div class="search-bar">
      <input class="search-input" data-eng-search
             id="eng-filter-main" name="eng-filter"
             autocomplete="off"
             placeholder="Filter by user, IP, alert, host…  / to focus"/>
      <span class="dim mono" data-filter-count style="font-size:11px;">
        {n} total
      </span>
      <span class="kbd">/</span>
    </div>
    <div class="time-bucket-strip" data-time-bucket-strip>
      <span class="dim2 mono" style="font-size: 10px;">when</span>
      <button type="button" class="filter active" data-filter-time="any"
              aria-pressed="true"
              title="No time filter — show every engagement">any</button>
      <button type="button" class="filter" data-filter-time="active"
              aria-pressed="false"
              title="Last seen within 5 minutes">active</button>
      <button type="button" class="filter" data-filter-time="1h"
              aria-pressed="false"
              title="Last seen within 1 hour">1h</button>
      <button type="button" class="filter" data-filter-time="today"
              aria-pressed="false"
              title="Last seen within the last 24 hours">today</button>
      <button type="button" class="filter" data-filter-time="week"
              aria-pressed="false"
              title="Last seen within the last 7 days">week</button>
      <button type="button" class="filter" data-filter-time="older"
              aria-pressed="false"
              title="Last seen more than 7 days ago — archive view">older</button>
    </div>
    {_BATCH_BAR_HTML}
    <div class="engagements">{"".join(row_html)}</div>
  </div>
  <div class="panel" data-tv-section data-detail-panel
       data-panel-id="engagement-detail"
       data-current-eid="{html.escape(engs[0]["engagement_id"]) if engs else ""}">
    <div class="panel-header">
      {drag}
      <span>Engagement detail</span>
      <div class="actions" data-export-host>
        {_render_export_links(engs[0]["engagement_id"]) if engs else ""}
        {_POPOUT_ICON.format(name=detail_pop_name)}
      </div>
    </div>
    {detail_html}
  </div>
</div>
<div class="bottom" data-grid-row="bottom">
  <div class="panel" data-tv-section data-panel-id="alert-rate">
    <div class="panel-header">
      {drag}
      <span>Alert rate</span>
      <div class="actions" data-alert-rate-toolbar>
        <button type="button" class="filter" data-ar-range="15m" aria-pressed="false">15m</button>
        <button type="button" class="filter" data-ar-range="1h"  aria-pressed="false">1h</button>
        <button type="button" class="filter active" data-ar-range="6h"  aria-pressed="true">6h</button>
        <button type="button" class="filter" data-ar-range="24h" aria-pressed="false">24h</button>
        <button type="button" class="filter" data-ar-range="7d"  aria-pressed="false">7d</button>
        <button type="button" class="filter" data-ar-range="30d" aria-pressed="false">30d</button>
        <span class="dim2" style="margin: 0 4px;">·</span>
        <button type="button" class="filter active" data-ar-mode="stacked" aria-pressed="true"
                title="Stacked bars">bars</button>
        <button type="button" class="filter" data-ar-mode="line" aria-pressed="false"
                title="One line per severity">line</button>
        <span class="count">{sum(state["sev_totals"].values())}</span>
        {_POPOUT_ICON.format(name="alert-rate")}
      </div>
    </div>
    <div data-alert-chart class="chart-wrap">{chart_svg}</div>
  </div>
  <div class="panel" data-tv-section data-panel-id="dns-feed">
    <div class="panel-header">
      {drag}
      <span>DNS query feed</span>
      <div class="actions" data-dns-toolbar>
        <button type="button" class="filter active" data-dns-filter="all"
                aria-pressed="true">all</button>
        <button type="button" class="filter" data-dns-filter="blocked"
                aria-pressed="false">blocked</button>
        <button type="button" class="filter" data-dns-filter="nxdomain"
                aria-pressed="false">nxdomain</button>
        <span class="count" data-dns-feed-count>{len(state["dns_parsed"])}</span>
        {_POPOUT_ICON.format(name="dns-feed")}
      </div>
    </div>
    <div data-dns-feed-host>{dns_html}</div>
  </div>
  <div class="panel" data-tv-section data-panel-id="activity">
    <div class="panel-header">
      {drag}
      <span>Activity · last 24h</span>
      <div class="actions">
        {_POPOUT_ICON.format(name="activity")}
      </div>
    </div>
    {heatmap_html}
  </div>
</div>
'''


def _render(state: dict, refresh: int, sse: bool = True) -> str:
    """Full main-dashboard page assembly.

    Preserves the v1 signature (state, refresh, sse) so existing tests
    keep working. The body shape changed; tests have been updated in
    `tests/test_dashboard_sse.py` to match.
    """
    if sse:
        refresh_meta = ""
        sse_label = "live (SSE)"
    else:
        refresh_meta = f'<meta http-equiv="refresh" content="{refresh}">'
        sse_label = f"auto-refresh {refresh}s"
    panel_html = _render_main_panels(state)
    return f'''<!doctype html>
<html><head>
<meta charset="utf-8">
{refresh_meta}
<title>Plenith SOC</title>
<style>{CSS}</style>
</head><body>
{_render_topbar(state, sse_label=sse_label)}
<div id="panels">{panel_html}</div>
<div class="footer">
  <div class="row">
    <span>plenith v1.0.1</span>
    <span class="sep">·</span>
    <span>Apache 2.0</span>
  </div>
  <div class="row">
    <span class="pulse-dot" style="margin-right: 0;"></span>
    <span>{sse_label}</span>
  </div>
</div>
{'<script>' + JS + '</script>' if sse else ''}
</body></html>'''


def _render_popout_chrome(eid_or_label: str, *, url_path: str) -> str:
    """The minimal top bar used on every /panel/<name> popout page."""
    return f'''
<div class="chrome">
  <div class="chrome-left">
    <a href="/" class="back">← Dashboard</a>
    <span class="crumb-sep">/</span>
    <span class="eid-short">{html.escape(eid_or_label)}</span>
  </div>
  <div class="chrome-right">
    <span class="chrome-btn" data-theme-toggle>
      <span class="ico" data-theme-icon>☾</span>
      <span data-theme-name>Dark</span>
    </span>
    <span class="chrome-btn" data-tv-toggle><span class="ico">▣</span> TV mode</span>
    <span class="chrome-btn" title="Close window"
           onclick="window.close()"><span class="ico">×</span></span>
  </div>
</div>
'''


def _wrap_popout(title: str, chrome: str, body: str, *,
                  panel_filter: str = "") -> str:
    """Wrap a popout body in a full HTML document."""
    pf_attr = f' data-panel-filter="{html.escape(panel_filter)}"' if panel_filter else ""
    return f'''<!doctype html>
<html><head>
<meta charset="utf-8">
<title>{html.escape(title)} — Plenith SOC</title>
<style>{CSS}</style>
</head><body>
{chrome}
<div id="panels"{pf_attr}>{body}</div>
<script>{JS}</script>
</body></html>'''


# ----- /panel/engagements ---------------------------------------------------

def _render_panel_engagements(state: dict) -> str:
    """Full-screen engagement list popout."""
    engs = state["engagements"]
    actions_by_eng = state["actions_by_eng"]
    if not engs:
        body = ('<div class="panel"><div class="panel-header">'
                '<span>Engagements (0)</span></div>'
                '<div class="dim" style="padding: 18px;">No engagements yet.</div></div>')
        return _wrap_popout("Engagements", _render_popout_chrome("engagements", url_path="/panel/engagements"),
                             body, panel_filter="engagements")
    rows = [_render_engagement_row(e, actions_by_eng.get(e["engagement_id"], []))
             for e in engs]
    body = f'''
<div class="panel">
  <div class="panel-header">
    <span>Engagements live ({len(engs)})</span>
    <div class="actions">
      <button type="button" class="filter active" data-filter-chip="all"
              aria-pressed="true"
              title="Show all engagements">all <span class="dim2 mono">({len(engs)})</span></button>
      <button type="button" class="filter" data-filter-chip="critical"
              aria-pressed="false"
              title="Only engagements with a critical or proven alert">critical</button>
      <button type="button" class="filter" data-filter-chip="llm"
              aria-pressed="false"
              title="Only engagements where the attacker is LLM-detected">llm-detected</button>
      <span class="count">{len(engs)}</span>
    </div>
  </div>
  <div class="search-bar">
    <input class="search-input" data-eng-search
           id="eng-filter-popout" name="eng-filter"
           autocomplete="off"
           placeholder="Filter by user, IP, alert, host…  / to focus"/>
    <span class="kbd">/</span>
  </div>
  <div class="time-bucket-strip" data-time-bucket-strip>
    <span class="dim2 mono" style="font-size: 10px;">when</span>
    <button type="button" class="filter active" data-filter-time="any"
            aria-pressed="true" title="No time filter">any</button>
    <button type="button" class="filter" data-filter-time="active"
            aria-pressed="false" title="Last seen within 5 minutes">active</button>
    <button type="button" class="filter" data-filter-time="1h"
            aria-pressed="false" title="Last seen within 1 hour">1h</button>
    <button type="button" class="filter" data-filter-time="today"
            aria-pressed="false" title="Last seen within the last 24 hours">today</button>
    <button type="button" class="filter" data-filter-time="week"
            aria-pressed="false" title="Last seen within the last 7 days">week</button>
    <button type="button" class="filter" data-filter-time="older"
            aria-pressed="false" title="Last seen more than 7 days ago">older</button>
  </div>
  <div class="eng-sort-strip" data-eng-sort-strip>
    <span class="dim2 mono" style="font-size: 10px;">sort</span>
    <button type="button" class="filter active" data-eng-sort="last_seen"
            aria-pressed="true" title="Most recently active first">last seen</button>
    <button type="button" class="filter" data-eng-sort="first_seen"
            aria-pressed="false" title="Earliest first-seen first">first seen</button>
    <button type="button" class="filter" data-eng-sort="dwell"
            aria-pressed="false" title="Longest dwell time first">dwell</button>
    <button type="button" class="filter" data-eng-sort="cmds"
            aria-pressed="false" title="Most commands first">cmds</button>
    <button type="button" class="filter" data-eng-sort="alerts"
            aria-pressed="false" title="Most alerts first">alerts</button>
    <button type="button" class="filter" data-eng-sort="conf"
            aria-pressed="false" title="Highest counter-AI confidence first">conf</button>
    <span class="eng-sort-dir-wrap">
      <button type="button" class="filter" data-eng-sort-dir-toggle
              aria-label="Toggle sort direction"
              title="Toggle ascending / descending">↓</button>
    </span>
    <span class="dim2 mono" style="font-size: 10px; margin-left: 12px;">page size</span>
    <button type="button" class="filter" data-eng-page-size="10"
            aria-pressed="false">10</button>
    <button type="button" class="filter active" data-eng-page-size="25"
            aria-pressed="true">25</button>
    <button type="button" class="filter" data-eng-page-size="50"
            aria-pressed="false">50</button>
    <button type="button" class="filter" data-eng-page-size="all"
            aria-pressed="false">all</button>
  </div>
  {_BATCH_BAR_HTML}
  <div class="engagements" data-eng-list>{"".join(rows)}</div>
  <div class="eng-pagination" data-eng-pagination>
    <span class="dim mono" data-eng-page-info style="font-size: 11px;">
      Showing all {len(engs)}
    </span>
    <span class="eng-pagination-controls">
      <button type="button" class="filter" data-eng-page-prev disabled
              aria-label="Previous page">‹ prev</button>
      <span class="dim mono" data-eng-page-num style="font-size: 11px;">
        page 1
      </span>
      <button type="button" class="filter" data-eng-page-next disabled
              aria-label="Next page">next ›</button>
    </span>
  </div>
</div>
'''
    return _wrap_popout("Engagements",
                         _render_popout_chrome("engagements", url_path="/panel/engagements"),
                         body, panel_filter="engagements")


# ----- /panel/engagement/<id> ----------------------------------------------

def _render_panel_engagement_detail(state: dict, eid: str) -> str:
    """Full-screen single-engagement view."""
    actions_by_eng = state["actions_by_eng"]
    eng = next((e for e in state["engagements"] if e["engagement_id"].startswith(eid)),
                None)
    if eng is None:
        body = (f'<div class="panel"><div class="panel-header">'
                f'<span>Engagement {html.escape(eid)}</span></div>'
                f'<div class="dim" style="padding: 18px;">'
                f'Engagement not found.</div></div>')
        return _wrap_popout(f"Engagement {eid}",
                             _render_popout_chrome(eid[:8],
                                                    url_path=f"/panel/engagement/{eid}"),
                             body)
    actions = actions_by_eng.get(eng["engagement_id"], [])
    # Footer export strip — same set of audit/IoC/sigma/STIX links the
    # main dashboard's detail panel header has.  Popping the engagement
    # out into its own window without these would force the operator
    # back to the main dashboard to grab them.
    body = (
        f'<div class="panel">'
        f'  <div class="panel-header">'
        f'    <span>Engagement {html.escape(eng["engagement_id"][:8])}</span>'
        f'    <div class="actions" data-export-host>'
        f'      {_render_export_links(eng["engagement_id"])}'
        f'    </div>'
        f'  </div>'
        f'  {_render_engagement_detail(eng, actions)}'
        f'</div>'
    )
    return _wrap_popout(f"Engagement {eng['engagement_id'][:8]}",
                         _render_popout_chrome(eng["engagement_id"][:8],
                                                url_path=f"/panel/engagement/{eng['engagement_id']}"),
                         body, panel_filter=f"engagement/{eng['engagement_id']}")


# ----- /panel/alert-rate ----------------------------------------------------

def _render_panel_alert_rate(state: dict) -> str:
    """Full-screen alert-rate chart popout — time-range tabs, severity
    filter chips, line/stacked toggle, and a top-alerts side list.

    State is owned client-side and persisted in sessionStorage; the JS
    re-fetches /api/alerts/chart.html + /api/alerts/top.html on every
    control change.  Server emits a sensible default (6h, all severities,
    stacked) so the popout is useful before any JS runs."""
    chart = _render_alert_rate_chart(state, height=240)
    sev = state["sev_totals"]
    # Render the initial top-alerts list with default 24h window.
    try:
        from plenith.aggregations import alert_top
        initial_top = alert_top(_ROOT / "state-docker",
                                 since=time.time() - 86400,
                                 until=time.time(),
                                 limit=8)
    except Exception:
        initial_top = {"alerts": []}
    top_html = _render_top_alerts_list(initial_top)
    body = f'''
<div class="panel">
  <div class="panel-header">
    <span>Alert rate</span>
    <div class="actions" data-alert-rate-toolbar>
      <span class="dim2 mono" style="font-size: 10px;">range</span>
      <button type="button" class="filter" data-ar-range="15m" aria-pressed="false">15m</button>
      <button type="button" class="filter" data-ar-range="1h"  aria-pressed="false">1h</button>
      <button type="button" class="filter active" data-ar-range="6h"  aria-pressed="true">6h</button>
      <button type="button" class="filter" data-ar-range="24h" aria-pressed="false">24h</button>
      <button type="button" class="filter" data-ar-range="7d"  aria-pressed="false">7d</button>
      <button type="button" class="filter" data-ar-range="30d" aria-pressed="false">30d</button>
      <span class="dim2 mono" style="font-size: 10px; margin-left: 12px;">mode</span>
      <button type="button" class="filter active" data-ar-mode="stacked" aria-pressed="true"
              title="Stacked bars — totals per bucket">stacked</button>
      <button type="button" class="filter" data-ar-mode="line" aria-pressed="false"
              title="Line per severity — easier to compare trends">line</button>
    </div>
  </div>
  <div class="chart-wrap">
    <div class="chart-stats" data-ar-stats>
      <div class="chart-stat"><div class="v" style="color: var(--sev-critical);"
             data-ar-stat="critical">{sev["critical"]}</div><div class="l">critical</div></div>
      <div class="chart-stat"><div class="v" style="color: var(--sev-high);"
             data-ar-stat="high">{sev["high"]}</div><div class="l">high</div></div>
      <div class="chart-stat"><div class="v" style="color: var(--sev-medium);"
             data-ar-stat="medium">{sev["medium"]}</div><div class="l">medium</div></div>
      <div class="chart-stat"><div class="v" data-ar-stat="info">{sev["info"]}</div><div class="l">info</div></div>
    </div>
    <div class="alert-rate-sev-chips" data-ar-sev-chips
         role="group" aria-label="Severity filter">
      <button type="button" class="filter active sev-crit" data-ar-sev="critical"
              aria-pressed="true">critical</button>
      <button type="button" class="filter active sev-high" data-ar-sev="high"
              aria-pressed="true">high</button>
      <button type="button" class="filter active sev-med"  data-ar-sev="medium"
              aria-pressed="true">medium</button>
      <button type="button" class="filter active sev-info" data-ar-sev="info"
              aria-pressed="true">info</button>
    </div>
    <div class="alert-rate-grid">
      <div data-alert-chart class="alert-rate-chart-host">{chart}</div>
      <div class="alert-rate-side">
        <div class="alert-rate-side-head">
          Top alerts <span class="dim2 mono">(window)</span>
        </div>
        <div data-alert-top>{top_html}</div>
      </div>
    </div>
  </div>
</div>
'''
    return _wrap_popout("Alert rate",
                         _render_popout_chrome("alert-rate", url_path="/panel/alert-rate"),
                         body, panel_filter="alert-rate")


# ----- /panel/dns-feed ------------------------------------------------------

def _render_panel_dns_feed(state: dict) -> str:
    """Full-screen DNS feed popout — KPI tiles, result-type filter, top
    blocked + top NXDOMAIN side lists, and the live feed below.  Per
    UI_WIRING.md §E."""
    from plenith.aggregations import dns_top
    parsed = state.get("dns_parsed") or []
    kpis = _render_dns_kpi_tiles(state)
    feed = _render_dns_feed_html(state, max_rows=80)
    top_blocked  = _render_dns_top_list(
        dns_top(parsed, result_type="blocked",  limit=10), kind="blocked")
    top_nxdomain = _render_dns_top_list(
        dns_top(parsed, result_type="nxdomain", limit=10), kind="nxdomain")
    body = f'''
<div class="panel">
  <div class="panel-header">
    <span>DNS query feed · live</span>
    <div class="actions" data-dns-toolbar>
      <span class="dim2 mono" style="font-size: 10px;">filter</span>
      <button type="button" class="filter active" data-dns-filter="all"
              aria-pressed="true">all</button>
      <button type="button" class="filter" data-dns-filter="resolved"
              aria-pressed="false">resolved</button>
      <button type="button" class="filter" data-dns-filter="blocked"
              aria-pressed="false">blocked</button>
      <button type="button" class="filter" data-dns-filter="nxdomain"
              aria-pressed="false">nxdomain</button>
      <span class="count" data-dns-feed-count>{len(parsed)}</span>
    </div>
  </div>
  <div class="dns-popout-wrap">
    {kpis}
    <div class="dns-popout-grid">
      <div data-dns-feed-host class="dns-popout-feed">{feed}</div>
      <div class="dns-popout-side">
        <div class="dns-popout-side-head">
          Top blocked / exfil <span class="dim2 mono">(window)</span>
        </div>
        <div data-dns-top-blocked>{top_blocked}</div>
        <div class="dns-popout-side-head" style="margin-top: 10px;">
          Top NXDOMAIN <span class="dim2 mono">(window)</span>
        </div>
        <div data-dns-top-nxdomain>{top_nxdomain}</div>
      </div>
    </div>
  </div>
</div>
'''
    return _wrap_popout("DNS feed",
                         _render_popout_chrome("dns-feed", url_path="/panel/dns-feed"),
                         body, panel_filter="dns-feed")


# ----- /panel/activity ------------------------------------------------------

def _render_panel_activity(state: dict) -> str:
    """Full-screen heatmap popout — time-range tabs, kind filter
    (all / commands / alerts), summary tiles, and cell-click drill-in.
    Per UI_WIRING.md §F."""
    from plenith.aggregations import activity_heatmap
    until = time.time()
    result = activity_heatmap(
        _ROOT / "state-docker",
        since=until - 86400, until=until, kind="all",
    )
    summary = _render_activity_summary(result)
    grid_html = _render_heatmap_grid(result.get("hosts") or {})
    body = f'''
<div class="panel">
  <div class="panel-header">
    <span>Activity heatmap · per decoy host</span>
    <div class="actions" data-activity-toolbar>
      <span class="dim2 mono" style="font-size: 10px;">range</span>
      <button type="button" class="filter active" data-act-range="24h"
              aria-pressed="true">24h</button>
      <button type="button" class="filter" data-act-range="7d"
              aria-pressed="false">7d</button>
      <button type="button" class="filter" data-act-range="30d"
              aria-pressed="false">30d</button>
      <button type="button" class="filter" data-act-range="90d"
              aria-pressed="false">90d</button>
      <span class="dim2 mono" style="font-size: 10px; margin-left: 12px;">show</span>
      <button type="button" class="filter active" data-act-kind="all"
              aria-pressed="true">all</button>
      <button type="button" class="filter" data-act-kind="alerts"
              aria-pressed="false"
              title="Only count alerts the engine fired">alerts</button>
      <button type="button" class="filter" data-act-kind="commands"
              aria-pressed="false"
              title="Only count attacker commands">commands</button>
    </div>
  </div>
  <div class="activity-popout-wrap">
    <div data-activity-summary-host>{summary}</div>
    <div class="activity-hint dim mono">
      Click any cell to see which engagements contributed to that hour.
    </div>
    <div data-activity-heatmap-host>{grid_html}</div>
  </div>
</div>
'''
    return _wrap_popout("Activity",
                         _render_popout_chrome("activity", url_path="/panel/activity"),
                         body, panel_filter="activity")


# ===========================================================================
# Server
# ===========================================================================

class QuietThreadingHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer that doesn't print a stack trace when a client
    disconnects mid-request.  Browser tabs holding /api/stream long-polls
    drop the socket on close/refresh — on Windows that surfaces as
    ConnectionAbortedError (WinError 10053), on Linux as ConnectionResetError
    or BrokenPipeError.  All three are benign here; only real bugs deserve
    a traceback."""

    _SILENCED = (ConnectionAbortedError, ConnectionResetError, BrokenPipeError)

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, self._SILENCED):
            return
        super().handle_error(request, client_address)


class Handler(BaseHTTPRequestHandler):
    refresh: int = 3
    sse_enabled: bool = True

    def log_message(self, fmt, *args):
        return

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            self.close_connection = True

    # ----- routing -----------------------------------------------------

    def do_GET(self):  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path in ("/", "/index.html"):
            self._send_html(_render(_gather(), Handler.refresh,
                                     sse=Handler.sse_enabled))
        elif path == "/api/state.json":
            self._send_json(_gather())
        elif path == "/api/stream":
            panel = query.get("panel", [""])[0]
            # Pinned engagement-id so the main-dashboard SSE renders
            # the operator's chosen detail panel instead of flipping
            # back to engs[0] every tick.
            selected = query.get("selected", [""])[0]
            self._stream(panel, selected_eid_hint=selected)
        elif path == "/panel/engagements":
            self._send_html(_render_panel_engagements(_gather()))
        elif path == "/panel/alert-rate":
            self._send_html(_render_panel_alert_rate(_gather()))
        elif path == "/panel/dns-feed":
            self._send_html(_render_panel_dns_feed(_gather()))
        elif path == "/panel/activity":
            self._send_html(_render_panel_activity(_gather()))
        elif path.startswith("/panel/engagement/"):
            eid = path[len("/panel/engagement/"):]
            if eid == "__active__":
                state = _gather()
                if state["engagements"]:
                    eid = state["engagements"][0]["engagement_id"]
            self._send_html(_render_panel_engagement_detail(_gather(), eid))
        # Phase 3 read-side endpoints (symmetric with FastAPI service).
        # The dashboard already surfaces all of these via the page render,
        # but exposing them as raw JSON is useful for SOAR + smoke tests.
        elif path.startswith("/api/engagements/") and path.endswith("/notes"):
            eid = path[len("/api/engagements/"):-len("/notes")]
            self._send_json({"engagement_id": eid,
                              "notes": _notes_store().list(eid)})
        elif path.startswith("/api/engagements/") and path.endswith("/snapshots"):
            eid = path[len("/api/engagements/"):-len("/snapshots")]
            self._send_json({"engagement_id": eid,
                              "snapshots": _snap_writer().list_for(eid)})
        elif path.startswith("/api/engagements/") and path.endswith("/kill"):
            eid = path[len("/api/engagements/"):-len("/kill")]
            self._send_json({"engagement_id": eid,
                              "kill_request": _kill_queue().get(eid)})
        # Detail-panel fragment for in-page row-click → detail swap.
        # Returns just the inner HTML of the engagement detail panel so
        # the dashboard's click handler can replace the right-side panel
        # body without a full page reload.
        # /api/engagements/<id>/file-diff?path=<canonical>  — JSON
        # payload with baseline + current content for a single VFS file
        # the attacker has modified.  Drives the file-diff modal.
        elif path.startswith("/api/engagements/") and path.endswith("/file-diff"):
            eid = path[len("/api/engagements/"):-len("/file-diff")]
            target_path = self._q_str(query, "path") or ""
            state = _gather()
            eng = next((e for e in state["engagements"]
                          if e.get("engagement_id", "").startswith(eid)), None)
            if eng is None or not target_path:
                self._send_json({"error": "engagement or path missing"}, status=404)
            else:
                vfs = eng.get("vfs") or {}
                files = vfs.get("files") or {}
                baseline = vfs.get("baseline") or {}
                deleted = set(vfs.get("deleted") or [])
                cur = None if target_path in deleted else files.get(target_path)
                base = baseline.get(target_path)
                self._send_json({
                    "engagement_id": eng["engagement_id"],
                    "path":          target_path,
                    "baseline":      base,
                    "current":       cur,
                    "deleted":       target_path in deleted,
                    "tampered":      target_path in (vfs.get("tampered") or []),
                    "baseline_size": len(base) if base is not None else None,
                    "current_size":  len(cur) if cur is not None else None,
                })
        elif path.startswith("/api/engagements/") and path.endswith("/detail.html"):
            eid = path[len("/api/engagements/"):-len("/detail.html")]
            state = _gather()
            eng = next((e for e in state["engagements"]
                          if e.get("engagement_id", "").startswith(eid)), None)
            if eng is None:
                self._send_json({"error": "engagement not found"}, status=404)
            else:
                full_eid = eng["engagement_id"]
                actions = state["actions_by_eng"].get(full_eid, [])
                body = _render_engagement_detail(eng, actions)
                # Ship the export-link strip alongside the body so the
                # row-click handler can swap BOTH — otherwise audit/IoC/
                # sigma links keep pointing at the previously-rendered
                # engagement.
                prefix = (
                    '<template data-export-strip data-eid="'
                    f'{html.escape(full_eid)}">'
                    f'{_render_export_links(full_eid)}</template>'
                )
                self._send_text(prefix + body, "text/html")
        # Phase 4 export aliases — same shape as plenith/api/server.py
        elif path.startswith("/api/engagements/") and path.endswith("/audit"):
            eid = path[len("/api/engagements/"):-len("/audit")]
            self._serve_export(eid, "audit")
        elif path.startswith("/api/engagements/") and path.endswith("/ioc.json"):
            eid = path[len("/api/engagements/"):-len("/ioc.json")]
            self._serve_export(eid, "ioc.json")
        elif path.startswith("/api/engagements/") and path.endswith("/ioc.csv"):
            eid = path[len("/api/engagements/"):-len("/ioc.csv")]
            self._serve_export(eid, "ioc.csv")
        elif path.startswith("/api/engagements/") and path.endswith("/ioc.stix"):
            eid = path[len("/api/engagements/"):-len("/ioc.stix")]
            self._serve_export(eid, "ioc.stix")
        elif path.startswith("/api/engagements/") and path.endswith("/sigma.yaml"):
            eid = path[len("/api/engagements/"):-len("/sigma.yaml")]
            self._serve_export(eid, "sigma.yaml")
        elif path.startswith("/api/engagements/") and path.endswith("/narrate"):
            eid = path[len("/api/engagements/"):-len("/narrate")]
            self._serve_export(eid, "narrate")
        # Phase 5: aggregation endpoints — dashboard mirror of the
        # FastAPI service so popped-out panels can fetch on the same
        # port without CORS plumbing.
        elif path == "/api/alerts/rate":
            self._serve_alert_rate(query)
        elif path == "/api/alerts/top":
            self._serve_alert_top(query)
        # HTML-fragment variants — what the alert-rate popout fetches
        # when the operator twiddles the range / mode / severity chips.
        elif path == "/api/alerts/chart.html":
            self._serve_alert_chart_fragment(query)
        elif path == "/api/alerts/top.html":
            self._serve_alert_top_fragment(query)
        elif path == "/api/activity/heatmap":
            self._serve_activity_heatmap(query)
        elif path == "/api/activity/heatmap.html":
            self._serve_activity_heatmap_fragment(query)
        elif path == "/api/activity/cell.html":
            self._serve_activity_cell_fragment(query)
        elif path == "/api/dns/stats":
            self._serve_dns_stats()
        elif path == "/api/dns/top":
            self._serve_dns_top(query)
        # HTML-fragment variants for the DNS popout filter chips.
        elif path == "/api/dns/feed.html":
            self._serve_dns_feed_fragment(query)
        elif path == "/api/dns/top.html":
            self._serve_dns_top_fragment(query)
        else:
            self.send_error(404)

    # ----- POST / DELETE — Phase 2 ack endpoints ----------------------
    # These mutate `state-docker/acks.json` via plenith.acks.AckStore.
    # The dashboard's own JS calls them; SOAR / external automation
    # uses the matching endpoints on plenith/api/server.py (same store).

    def do_POST(self):  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        # /api/engagements/batch/ack — must match BEFORE the per-id ack
        if path == "/api/engagements/batch/ack":
            return self._handle_batch_ack()
        # /mfa/decisions/<ip> — Isolate button; mirrors the FastAPI route
        # at plenith/api/server.py:490 so an Isolate from the dashboard
        # writes the same state-docker/mfa/<ip>.fail file the orchestrator
        # routing layer reads.
        if path.startswith("/mfa/decisions/"):
            ip = path[len("/mfa/decisions/"):]
            return self._handle_mfa_decision(ip)
        # /api/engagements/<id>/<verb>
        prefix = "/api/engagements/"
        if path.startswith(prefix):
            tail = path[len(prefix):]
            # Split into id + verb (handles trailing slashes defensively)
            if "/" in tail:
                eng_id, verb = tail.split("/", 1)
                # Guard: only /batch/ack is wired; anything else under
                # /batch/* would have created entries for eng_id="batch"
                # (state-corruption hazard from external automation).
                if eng_id == "batch":
                    self._send_json(
                        {"error": f"batch/{verb} not implemented"},
                        status=404,
                    )
                    return
                if verb == "ack":         return self._handle_ack(eng_id)
                if verb == "notes":       return self._handle_post_note(eng_id)
                if verb == "snapshot":    return self._handle_snapshot(eng_id)
                if verb == "kill":        return self._handle_kill(eng_id)
                if verb == "escalate":    return self._handle_escalate(eng_id)
        self.send_error(404)

    def do_DELETE(self):  # noqa: N802
        path = urlparse(self.path).path
        prefix = "/api/engagements/"
        if not path.startswith(prefix):
            self.send_error(404); return
        tail = path[len(prefix):]
        # /api/engagements/<eng_id>/ack/<action_name>
        if "/ack/" in tail:
            eng_id, action_name = tail.split("/ack/", 1)
            removed = _ack_store().unack(eng_id, action_name)
            self._send_json({"removed": removed}); return
        # /api/engagements/<eng_id>/notes/<note_id>
        if "/notes/" in tail:
            eng_id, note_id = tail.split("/notes/", 1)
            removed = _notes_store().delete(eng_id, note_id)
            self._send_json({"removed": removed}); return
        # /api/engagements/<eng_id>/kill   (cancel pending request)
        if tail.endswith("/kill"):
            eng_id = tail[:-len("/kill")]
            removed = _kill_queue().cancel(eng_id)
            self._send_json({"removed": removed}); return
        self.send_error(404)

    # ----- POST handlers (each one a thin wrapper around the store) ----

    def _handle_ack(self, eng_id: str) -> None:
        body = self._read_json_body()
        if body is None: return
        action_name = body.get("action_name")
        if not isinstance(action_name, str) or not action_name:
            self._send_json({"error": "action_name required"}, status=400); return
        entry = _ack_store().ack(
            eng_id, action_name,
            op_id=body.get("op_id") or "anonymous",
            note=body.get("note") or "",
        )
        self._send_json({"engagement_id":   eng_id,
                          "action_name":     action_name,
                          "acknowledged_at": entry["ts"],
                          "acknowledged_by": entry["op_id"]})

    def _handle_batch_ack(self) -> None:
        body = self._read_json_body()
        if body is None: return
        ids = body.get("ids")
        action_name = body.get("action_name")
        if not isinstance(ids, list) or not ids or \
                not isinstance(action_name, str) or not action_name:
            self._send_json({"error": "ids[list] + action_name[str] required"},
                            status=400); return
        result = _ack_store().batch_ack(
            ids, action_name=action_name,
            op_id=body.get("op_id") or "anonymous",
            note=body.get("note") or "",
        )
        self._send_json(result)

    def _handle_post_note(self, eng_id: str) -> None:
        body = self._read_json_body()
        if body is None: return
        note_body = (body.get("body") or "").strip()
        if not note_body:
            self._send_json({"error": "note body required"}, status=422); return
        try:
            note = _notes_store().add(
                eng_id, note_body,
                author=body.get("author") or "anonymous",
            )
        except ValueError as e:
            self._send_json({"error": str(e)}, status=422); return
        self._send_json(note)

    def _handle_snapshot(self, eng_id: str) -> None:
        body = self._read_json_body(optional=True) or {}
        try:
            result = _snap_writer().write(
                eng_id,
                op_id=body.get("op_id") or "anonymous",
                note=body.get("note") or "",
            )
        except ValueError as e:
            self._send_json({"error": str(e)}, status=422); return
        self._send_json(result)

    def _handle_mfa_decision(self, ip: str) -> None:
        """Write state-docker/mfa/<ip>.<decision> so the orchestrator
        routing layer picks it up on its next decision.  Mirrors
        plenith/api/server.py write_mfa_decision (Phase B.2 of
        UI_WIRING.md); ip is validated as a literal address first to
        block path traversal via URL-encoded slashes."""
        import ipaddress
        try:
            ipaddress.ip_address(ip)
        except (ValueError, TypeError):
            self._send_json(
                {"error": "ip path parameter must be a literal IPv4/IPv6 address"},
                status=400)
            return
        body = self._read_json_body(optional=True) or {}
        decision = body.get("decision", "fail")
        if decision not in ("pass", "fail"):
            self._send_json(
                {"error": "decision must be 'pass' or 'fail'"}, status=400)
            return
        reason = body.get("reason") or ""
        mfa_dir = _ROOT / "state-docker" / "mfa"
        try:
            mfa_dir.mkdir(parents=True, exist_ok=True)
            # Latest-wins: wipe stale decisions for this IP first.
            for stale in mfa_dir.glob(f"{ip}.*"):
                try:
                    stale.unlink()
                except OSError:
                    pass
            path = mfa_dir / f"{ip}.{decision}"
            content = (f"ip={ip}\ndecision={decision}\nts={int(time.time())}\n"
                       + (f"reason={reason}\n" if reason else ""))
            path.write_text(content, encoding="utf-8")
        except OSError as e:
            self._send_json({"error": str(e)}, status=500); return
        self._send_json({
            "ip": ip, "decision": decision, "written": True, "path": str(path),
        })

    def _handle_kill(self, eng_id: str) -> None:
        body = self._read_json_body(optional=True) or {}
        entry = _kill_queue().request_kill(
            eng_id,
            requested_by=body.get("op_id") or "anonymous",
            reason=body.get("reason") or "",
        )
        self._send_json({"engagement_id": eng_id, **entry})

    def _handle_escalate(self, eng_id: str) -> None:
        body = self._read_json_body(optional=True) or {}
        # Resolve the engagement so the connector message has real
        # source_ip / user / alert context, not just an ID.
        state = _gather()
        eng = next(
            (e for e in state["engagements"]
              if e.get("engagement_id", "").startswith(eng_id)),
            None,
        )
        if eng is None:
            self._send_json({"error": f"engagement {eng_id!r} not found"},
                            status=404); return
        # Chatops config: dashboard reads from a `dashboard.cfg.json` if
        # present, else empty (so escalate is a no-op preview).
        chatops_cfg = {}
        cfg_path = _ROOT / "state-docker" / "dashboard.cfg.json"
        if cfg_path.exists():
            try:
                chatops_cfg = json.loads(cfg_path.read_text(encoding="utf-8")
                                          ).get("chatops") or {}
            except (OSError, json.JSONDecodeError):
                pass
        result = _escalate_sync(
            eng,
            tier=body.get("tier") or "L2",
            message=body.get("message") or "",
            chatops_config=chatops_cfg,
        )
        self._send_json({"engagement_id": eng_id, **result})

    def _read_json_body(self, *, optional: bool = False):
        """Read + parse a JSON POST body.  On error, respond with 400
        and return None — the caller short-circuits.

        `optional=True` lets endpoints accept POST with no body (used by
        Snapshot / Kill / Escalate where every field has a default).
        Returns an empty dict for missing body in that mode instead of
        erroring."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            if optional:
                return {}
            self._send_json({"error": "missing body"}, status=400)
            return None
        if length > 1_000_000:
            self._send_json({"error": "oversized body"}, status=400)
            return None
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json({"error": "invalid JSON body"}, status=400)
            return None

    # ----- helpers -----------------------------------------------------

    def _send_html(self, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    # ----- Phase 5: aggregation endpoint helpers ----------------------

    @staticmethod
    def _q_float(query: dict, name: str, default=None):
        v = query.get(name, [None])[0]
        if v is None or v == "":
            return default
        try:
            return float(v)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _q_int(query: dict, name: str, default: int):
        v = query.get(name, [None])[0]
        try:
            return int(v) if v is not None else default
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _q_str(query: dict, name: str, default=None):
        v = query.get(name, [None])[0]
        return v if v else default

    def _serve_alert_rate(self, query: dict) -> None:
        from plenith.aggregations import alert_rate
        until = self._q_float(query, "until", time.time())
        since = self._q_float(query, "since", until - 21600)
        bucket = self._q_int(query, "bucket_seconds", 300)
        severity = self._q_str(query, "severity")
        compare_to = self._q_str(query, "compare_to")
        result = alert_rate(
            _ROOT / "state-docker",
            since=since, until=until,
            bucket_seconds=bucket,
            severities=[severity] if severity else None,
            compare_to=compare_to,
        )
        self._send_json(result)

    def _serve_alert_top(self, query: dict) -> None:
        from plenith.aggregations import alert_top
        until = self._q_float(query, "until", time.time())
        since = self._q_float(query, "since", until - 86400)
        limit = self._q_int(query, "limit", 10)
        self._send_json(alert_top(
            _ROOT / "state-docker",
            since=since, until=until, limit=limit,
        ))

    def _serve_alert_chart_fragment(self, query: dict) -> None:
        """HTML fragment: the chart SVG plus the four severity totals,
        emitted as a single payload so the client can do one fetch per
        control change.  Drives the /panel/alert-rate popout."""
        from plenith.aggregations import alert_rate
        until = self._q_float(query, "until", time.time())
        since = self._q_float(query, "since", until - 21600)
        bucket = self._q_int(query, "bucket_seconds", 300)
        range_label = self._q_str(query, "range") or "6h"
        mode = self._q_str(query, "mode") or "stacked"
        sev_raw = self._q_str(query, "severities") or ",".join(_ALERT_SEVERITIES)
        severities = [s for s in sev_raw.split(",")
                       if s in _ALERT_SEVERITIES] or list(_ALERT_SEVERITIES)
        result = alert_rate(
            _ROOT / "state-docker",
            since=since, until=until,
            bucket_seconds=bucket,
            severities=None,        # always fetch all; client filters via chips
            compare_to="previous",
        )
        chart = _render_alert_rate_chart_svg(
            result.get("series") or [],
            compare=result.get("compare"),
            height=240,
            severities=severities,
            mode=mode if mode in ("stacked", "line") else "stacked",
            range_label=range_label,
        )
        # Totals — recompute filtered by the active severities so the
        # number bar matches what's drawn on the chart.
        totals_all = result.get("totals") or {}
        totals = {s: int(totals_all.get(s, 0) or 0) for s in _ALERT_SEVERITIES}
        # Emit chart + totals in a single fragment.  Each .v gets a
        # data-ar-stat="<sev>" so the client knows where to read.
        stats = (
            f'<div class="chart-stats" data-ar-stats>'
            f'  <div class="chart-stat"><div class="v" '
            f'       style="color: var(--sev-critical);" data-ar-stat="critical">'
            f'{totals["critical"]}</div><div class="l">critical</div></div>'
            f'  <div class="chart-stat"><div class="v" '
            f'       style="color: var(--sev-high);" data-ar-stat="high">'
            f'{totals["high"]}</div><div class="l">high</div></div>'
            f'  <div class="chart-stat"><div class="v" '
            f'       style="color: var(--sev-medium);" data-ar-stat="medium">'
            f'{totals["medium"]}</div><div class="l">medium</div></div>'
            f'  <div class="chart-stat"><div class="v" data-ar-stat="info">'
            f'{totals["info"]}</div><div class="l">info</div></div>'
            f'</div>'
        )
        self._send_text(stats + chart, "text/html")

    def _serve_alert_top_fragment(self, query: dict) -> None:
        from plenith.aggregations import alert_top
        until = self._q_float(query, "until", time.time())
        since = self._q_float(query, "since", until - 86400)
        limit = self._q_int(query, "limit", 8)
        result = alert_top(
            _ROOT / "state-docker",
            since=since, until=until, limit=limit,
        )
        self._send_text(_render_top_alerts_list(result), "text/html")

    def _serve_dns_feed_fragment(self, query: dict) -> None:
        """HTML fragment for the DNS feed when the operator picks a
        result-type filter (all / resolved / blocked / nxdomain).
        Counts in the panel header are emitted in the same response
        so a single fetch updates both the rows AND the badge."""
        result = self._q_str(query, "result") or "all"
        if result not in ("all", "resolved", "blocked", "nxdomain"):
            result = "all"
        max_rows = self._q_int(query, "limit", 80)
        state = _gather()
        body = _render_dns_feed_html(state, max_rows=max_rows,
                                      result_filter=result)
        # Also recompute the count badge.  When filtered, the count is
        # the matching-row count; when 'all' it's the docker-log window
        # size we parse from.
        parsed = state.get("dns_parsed") or []
        if result == "all":
            n = len(parsed)
        else:
            n = sum(1 for p in parsed if p.get("result") == result)
        prefix = (
            f'<span data-dns-feed-count-fragment hidden>{n}</span>'
        )
        self._send_text(prefix + body, "text/html")

    def _serve_dns_top_fragment(self, query: dict) -> None:
        """HTML fragment: a single top-list (blocked OR nxdomain) so the
        popout's two side lists can refresh independently."""
        from plenith.aggregations import dns_top
        kind = self._q_str(query, "type") or "blocked"
        if kind not in ("blocked", "nxdomain", "resolved"):
            kind = "blocked"
        limit = self._q_int(query, "limit", 10)
        state = _gather()
        top = dns_top(state.get("dns_parsed") or [],
                       result_type=kind, limit=limit)
        self._send_text(_render_dns_top_list(top, kind=kind), "text/html")

    def _serve_activity_heatmap(self, query: dict) -> None:
        from plenith.aggregations import activity_heatmap
        until = self._q_float(query, "until", time.time())
        since = self._q_float(query, "since", until - 86400)
        host = self._q_str(query, "host")
        kind = self._q_str(query, "kind") or "all"
        self._send_json(activity_heatmap(
            _ROOT / "state-docker",
            since=since, until=until, host=host, kind=kind,
        ))

    def _serve_activity_heatmap_fragment(self, query: dict) -> None:
        """HTML fragment: summary tiles + heatmap grid.  One round-trip
        per control change on the activity popout."""
        from plenith.aggregations import activity_heatmap
        until = self._q_float(query, "until", time.time())
        since = self._q_float(query, "since", until - 86400)
        kind = self._q_str(query, "kind") or "all"
        result = activity_heatmap(
            _ROOT / "state-docker",
            since=since, until=until, kind=kind,
        )
        summary = _render_activity_summary(result)
        grid_html = _render_heatmap_grid(result.get("hosts") or {})
        # Two siblings, parsed apart on the client.
        self._send_text(summary + grid_html, "text/html")

    def _serve_activity_cell_fragment(self, query: dict) -> None:
        """Drill-in modal content for a single heatmap cell — lists the
        engagements that contributed to (host, hour) inside [since, until]."""
        from plenith.aggregations import activity_cell_engagements
        host = self._q_str(query, "host") or ""
        hour = self._q_int(query, "hour", -1)
        until = self._q_float(query, "until", time.time())
        since = self._q_float(query, "since", until - 86400)
        kind = self._q_str(query, "kind") or "all"
        if not host or hour < 0 or hour > 23:
            self._send_text(
                '<div class="dim" style="padding: 12px;">'
                'Invalid cell coordinates.</div>',
                "text/html",
            )
            return
        result = activity_cell_engagements(
            _ROOT / "state-docker",
            host=host, hour=hour,
            since=since, until=until, kind=kind,
        )
        engs = result.get("engagements") or []
        if not engs:
            body = ('<div class="dim" style="padding: 12px;">'
                    'No engagements contributed to this hour.</div>')
        else:
            rows = []
            for e in engs:
                eid = e.get("engagement_id", "")
                rows.append(
                    '<li class="activity-cell-row">'
                    f'<span class="activity-cell-eid mono">{html.escape(eid[:8])}</span>'
                    f'<span class="activity-cell-who mono">'
                    f'{html.escape(e.get("claimed_user", "?"))}'
                    f'@{html.escape(e.get("source_ip", "?"))}</span>'
                    f'<span class="activity-cell-counts mono dim2">'
                    f'{int(e.get("commands", 0))} cmd / '
                    f'{int(e.get("alerts", 0))} alert</span>'
                    '</li>'
                )
            body = '<ul class="activity-cell-list">' + "".join(rows) + '</ul>'
        self._send_text(body, "text/html")

    def _serve_dns_stats(self) -> None:
        from plenith.aggregations import dns_stats
        state = _gather()
        self._send_json(dns_stats(state.get("dns_parsed") or []))

    def _serve_dns_top(self, query: dict) -> None:
        from plenith.aggregations import dns_top
        result_type = self._q_str(query, "type") or "blocked"
        limit = self._q_int(query, "limit", 10)
        try:
            state = _gather()
            self._send_json({
                "result_type": result_type,
                "top": dns_top(state.get("dns_parsed") or [],
                                 result_type=result_type, limit=limit),
            })
        except ValueError as e:
            self._send_json({"error": str(e)}, status=400)

    def _serve_export(self, eid: str, kind: str) -> None:
        """Phase 4: serve an engagement export by kind.  Resolves the
        engagement by ID prefix, runs the appropriate audit.py helper,
        and sets the right Content-Type + Content-Disposition for a
        browser download.  Same shape as the FastAPI service so docs
        and SOAR integrations don't have to care which runtime served."""
        state = _gather()
        eng = next(
            (e for e in state["engagements"]
              if e.get("engagement_id", "").startswith(eid)),
            None,
        )
        if eng is None:
            self._send_json({"error": f"engagement {eid!r} not found"},
                            status=404); return
        audit = _load_audit()
        try:
            if kind == "audit":
                import io, contextlib
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    audit.print_detail(eng)
                self._send_text(buf.getvalue(), "text/plain")
            elif kind == "narrate":
                self._send_text(audit.build_narrative(eng), "text/plain")
            elif kind == "ioc.json":
                self._send_text(audit.export_ioc(eng), "application/json")
            elif kind == "ioc.csv":
                short = eng["engagement_id"][:8]
                self._send_text(
                    audit.export_ioc(eng, as_csv=True),
                    "text/csv",
                    filename=f"plenith-ioc-{short}.csv",
                )
            elif kind == "ioc.stix":
                from plenith.connectors.stix import bundle_from_engagements
                bundle = bundle_from_engagements([eng])
                self._send_text(json.dumps(bundle, indent=2, default=str),
                                "application/stix+json")
            elif kind == "sigma.yaml":
                short = eng["engagement_id"][:8]
                self._send_text(
                    audit.render_sigma(eng),
                    "text/yaml",
                    filename=f"plenith-sigma-{short}.yaml",
                )
            else:
                self.send_error(404)
        except Exception as e:                          # defensive
            self._send_json({"error": str(e)}, status=500)

    def _send_text(self, body: str, mime: str,
                    *, filename: Optional[str] = None) -> None:
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", f"{mime}; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        if filename:
            self.send_header(
                "Content-Disposition",
                f'attachment; filename="{filename}"',
            )
        self.end_headers()
        self.wfile.write(data)

    def _send_json(self, obj, status: int = 200) -> None:
        data = json.dumps(obj, default=str, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _stream(self, panel: str, *, selected_eid_hint: str = "") -> None:
        """SSE — push the appropriate panel HTML every <refresh> seconds.

        `panel` selects which slice of state goes out:
          (empty)              = main dashboard's #panels subtree
          engagements          = engagement list popout's body
          engagement/<id>      = engagement detail popout's body
          alert-rate           = alert-rate popout's body
          dns-feed             = DNS feed popout's body
          activity             = heatmap popout's body

        `selected_eid_hint` only applies to the main-dashboard variant
        — it pins which engagement is rendered as the selected detail
        panel.  Without it, every SSE tick that reorders engagements
        (e.g. a new session bumps mwilson above agarcia) would visibly
        flip the displayed engagement.
        """
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        # Phase 6: track which alerts this stream has already pushed so
        # we only emit `new_alerts` for events that arrived AFTER the
        # client connected.  Alerts that existed at connect-time render
        # in the initial page HTML; emitting them again as "new" would
        # spam the toast stack on every reload.
        seen_alerts: set = set()
        primed = False
        try:
            while True:
                snapshot = _gather()
                if panel == "engagements":
                    fragment = _extract_panels_body(_render_panel_engagements(snapshot))
                elif panel.startswith("engagement/"):
                    eid = panel.split("/", 1)[1]
                    fragment = _extract_panels_body(_render_panel_engagement_detail(snapshot, eid))
                elif panel == "alert-rate":
                    fragment = _extract_panels_body(_render_panel_alert_rate(snapshot))
                elif panel == "dns-feed":
                    fragment = _extract_panels_body(_render_panel_dns_feed(snapshot))
                elif panel == "activity":
                    fragment = _extract_panels_body(_render_panel_activity(snapshot))
                else:
                    fragment = _render_main_panels(
                        snapshot, selected_eid_hint=selected_eid_hint)

                # Compute current alerts + counter.  Dedup against the
                # previously-emitted set lives client-side now (see the
                # SSE handler in dashboard_scripts.py) so that a
                # reconnect-on-selection-change doesn't drop in-flight
                # alerts.  We still emit a per-tick "delta" against this
                # SSE connection's local set so first-connect doesn't
                # spam toasts for all historical alerts.
                current_alerts = _enumerate_alerts(snapshot)
                if not primed:
                    seen_alerts = {a["key"] for a in current_alerts}
                    new_alerts: list = []
                    primed = True
                else:
                    new_alerts = [a for a in current_alerts
                                   if a["key"] not in seen_alerts]
                    seen_alerts.update(a["key"] for a in new_alerts)
                critical_unacked = sum(
                    1 for a in current_alerts
                    if a["severity"] == "critical" and not a["acked"]
                )

                payload = {
                    "html":              fragment,
                    "ts":                snapshot["now"],
                    "new_alerts":        new_alerts,
                    # Send every current alert key so a reconnecting
                    # client can re-dedup without re-toasting history.
                    "all_alert_keys":    [a["key"] for a in current_alerts],
                    "critical_unacked":  critical_unacked,
                }
                line = "data: " + json.dumps(payload, default=str) + "\n\n"
                try:
                    self.wfile.write(line.encode("utf-8"))
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                    return
                time.sleep(Handler.refresh)
        except Exception:
            return


_PANELS_RE = re.compile(r'<div id="panels"[^>]*>(.*)</div>\s*<script>',
                          re.DOTALL)


def _enumerate_alerts(state: dict) -> list:
    """Flat list of every alert across every engagement, in a shape
    the SSE client can hand to the toast machinery.

    Each alert dict carries a stable `key` for dedup (engagement_id +
    action_name + ts_offset_s), the engagement's claimed_user / source_ip
    for the toast title, and an `acked` flag so the client can decide
    whether to count it against the critical-unacked badge.
    """
    out: list = []
    for eng in state.get("engagements", []) or []:
        eid = eng.get("engagement_id", "")
        for log in eng.get("logs", []) or []:
            for a in log.get("actions_taken", []) or []:
                name = a.get("action") or "?"
                key = f"{eid}|{name}|{a.get('ts_offset_s', 0)}"
                out.append({
                    "key":            key,
                    "engagement_id":  eid,
                    "engagement_short": eid[:8],
                    "claimed_user":   eng.get("claimed_user", "?"),
                    "source_ip":      eng.get("source_ip", "?"),
                    "action":         name,
                    "severity":       a.get("severity", "info"),
                    "triggered_by":   (a.get("triggered_by") or "")[:200],
                    "ts_offset_s":    a.get("ts_offset_s", 0),
                    "acked":          bool(a.get("acknowledged_at")),
                })
    return out


def _extract_panels_body(full_page_html: str) -> str:
    """For SSE pushes, return just the inner HTML of #panels."""
    m = _PANELS_RE.search(full_page_html)
    return m.group(1) if m else full_page_html


# ===========================================================================
# CLI
# ===========================================================================

def main():
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--refresh", type=int, default=3,
                   help="seconds between SSE pushes (default 3)")
    p.add_argument("--no-open", action="store_true",
                   help="don't open a browser window automatically")
    args = p.parse_args()

    Handler.refresh = args.refresh
    server = QuietThreadingHTTPServer((args.host, args.port), Handler)
    server.daemon_threads = True
    url = f"http://{args.host}:{args.port}/"
    print(f"\n  Plenith SOC dashboard listening on {url}")
    print(f"  Refresh interval: {args.refresh}s")
    if args.host not in ("127.0.0.1", "::1", "localhost"):
        print(
            f"\n  WARNING: dashboard is bound to {args.host!r} — NOT "
            f"loopback. The dashboard has no authentication and serves "
            f"attacker IoCs, command streams,\n"
            f"  and credential-search terms. Anyone who can reach this "
            f"port can read every engagement. Put it behind a reverse "
            f"proxy with auth, or revert to --host 127.0.0.1.\n",
            file=sys.stderr,
        )
    print(f"  Ctrl-C to stop.\n")
    if not args.no_open:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  shutting down dashboard")
        server.server_close()


if __name__ == "__main__":
    main()
