"""Prometheus exposition format for /metrics.

We don't pull in `prometheus_client` — the exposition format is a
trivial text protocol, and avoiding the dep keeps our footprint
small. Every counter / gauge we expose is named with the `plenith_`
prefix so Prometheus scrape configs can filter cleanly.

Reference: https://prometheus.io/docs/instrumenting/exposition_formats/
"""
from __future__ import annotations

import time
from typing import Dict, Optional


_PROC_START = time.time()


def render_metrics(snapshot: Dict[str, object]) -> str:
    """Render a snapshot dict into Prometheus text exposition format.

    Expected snapshot keys (all optional — missing → metric omitted):
        engagement_count            int
        alerts_total_by_severity    {"critical": N, ...}
        alerts_total_by_action      {action_name: N}
        counter_ai_detections       int
        counter_ai_proven_via_trap  int
        mfa_decisions               {"pass": N, "fail": N}
        api_request_count           int
        api_error_count             int
    """
    lines = []

    # Process uptime (always emitted)
    uptime = time.time() - _PROC_START
    lines.append("# HELP plenith_process_uptime_seconds Time since API start.")
    lines.append("# TYPE plenith_process_uptime_seconds gauge")
    lines.append(f"plenith_process_uptime_seconds {uptime:.3f}")

    if "engagement_count" in snapshot:
        lines.append("# HELP plenith_engagements_total Total engagements observed.")
        lines.append("# TYPE plenith_engagements_total counter")
        lines.append(f"plenith_engagements_total {snapshot['engagement_count']}")

    sev_counts = snapshot.get("alerts_total_by_severity") or {}
    if sev_counts:
        lines.append("# HELP plenith_alerts_total Alerts fired, by severity.")
        lines.append("# TYPE plenith_alerts_total counter")
        for sev, n in sev_counts.items():
            lines.append(f'plenith_alerts_total{{severity="{sev}"}} {n}')

    action_counts = snapshot.get("alerts_total_by_action") or {}
    if action_counts:
        lines.append("# HELP plenith_alerts_by_action_total Alerts fired, by action.")
        lines.append("# TYPE plenith_alerts_by_action_total counter")
        for action, n in action_counts.items():
            lines.append(f'plenith_alerts_by_action_total{{action="{action}"}} {n}')

    if "counter_ai_detections" in snapshot:
        lines.append("# HELP plenith_counter_ai_detections_total LLM-driven attackers detected.")
        lines.append("# TYPE plenith_counter_ai_detections_total counter")
        lines.append(f"plenith_counter_ai_detections_total {snapshot['counter_ai_detections']}")

    if "counter_ai_proven_via_trap" in snapshot:
        lines.append("# HELP plenith_counter_ai_proven_total Trap marker echo confirmations.")
        lines.append("# TYPE plenith_counter_ai_proven_total counter")
        lines.append(f"plenith_counter_ai_proven_total {snapshot['counter_ai_proven_via_trap']}")

    mfa = snapshot.get("mfa_decisions") or {}
    if mfa:
        lines.append("# HELP plenith_mfa_decisions_total MFA decisions written.")
        lines.append("# TYPE plenith_mfa_decisions_total counter")
        for decision, n in mfa.items():
            lines.append(f'plenith_mfa_decisions_total{{decision="{decision}"}} {n}')

    if "api_request_count" in snapshot:
        lines.append("# HELP plenith_api_requests_total Total API requests served.")
        lines.append("# TYPE plenith_api_requests_total counter")
        lines.append(f"plenith_api_requests_total {snapshot['api_request_count']}")

    if "api_error_count" in snapshot:
        lines.append("# HELP plenith_api_errors_total Total API requests that returned 4xx/5xx.")
        lines.append("# TYPE plenith_api_errors_total counter")
        lines.append(f"plenith_api_errors_total {snapshot['api_error_count']}")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Simple in-memory request counter (used by the FastAPI middleware)
# ---------------------------------------------------------------------------

class RequestCounters:
    def __init__(self):
        self.count = 0
        self.errors = 0

    def hit(self, status_code: int) -> None:
        self.count += 1
        if status_code >= 400:
            self.errors += 1

    def snapshot(self) -> Dict[str, int]:
        return {
            "api_request_count": self.count,
            "api_error_count":   self.errors,
        }
