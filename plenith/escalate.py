"""Escalate-to-L2 service — Phase 3 of docs/design/UI_WIRING.md.

Thin wrapper over the existing chatops connectors in
`plenith.connectors.chatops` (Slack / Teams / PagerDuty).  The
dashboard's "Escalate L2" button posts to the corresponding API
endpoint, which calls this service to fire whichever connectors are
configured for the deployment.

The connectors expect an `alert`-shaped dict (action, severity,
source_ip, claimed_user, engagement_id, mitre_technique, rationale).
We synthesize that shape from the engagement summary so escalations
read like real alerts in the chat channel.

If no chatops connectors are configured, escalate is still a valid
operation: it returns `connectors_fired=[]` and the dashboard can show
"no escalation channels configured — set MFA_PUSH_URL / Slack webhook
in your config to enable."

Async-only because httpx-based connectors are async.  The API endpoint
awaits the result; the dashboard's Python http.Handler uses `asyncio.run`
to bridge.
"""
from __future__ import annotations

import asyncio
from typing import Any

def build_alert_from_engagement(engagement: dict[str, Any], *,
                                  tier: str = "L2",
                                  message: str = "") -> dict[str, Any]:
    """Synthesize an alert-shaped dict from an engagement summary.

    Picks the highest-severity action across all session logs as the
    headline; falls back to a generic 'engagement_escalation' action if
    no alerts have fired yet (operator may escalate purely on counter-AI
    confidence)."""
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "info": 3}
    top_action: dict[str, Any] | None = None
    for log in engagement.get("logs", []) or []:
        for a in log.get("actions_taken", []) or []:
            if top_action is None or sev_rank.get(
                a.get("severity", "info"), 9,
            ) < sev_rank.get(top_action.get("severity", "info"), 9):
                top_action = a

    if top_action is None:
        top_action = {
            "action":   "engagement_escalation",
            "severity": "high",
            "rationale": (
                f"Operator-initiated {tier} escalation. "
                f"No automated alerts yet; manual review required."
            ),
        }

    summary = {
        "action":          top_action.get("action") or "engagement_escalation",
        "severity":        "critical" if tier == "L3" else
                            top_action.get("severity", "high"),
        "rationale":       (message + " " + (top_action.get("rationale") or "")).strip(),
        "ts_offset_s":     top_action.get("ts_offset_s", 0),
        "triggered_by":    top_action.get("triggered_by", ""),
        "mitre_technique": top_action.get("mitre_technique"),
        "mitre_tactic":    top_action.get("mitre_tactic"),
        "source_ip":       engagement.get("source_ip", "?"),
        "claimed_user":    engagement.get("claimed_user", "?"),
        "hostname":        engagement.get("_host", "?"),
        "engagement_id":   engagement.get("engagement_id", "?"),
        "_escalation_tier": tier,
    }
    return summary

async def escalate(engagement: dict[str, Any], *,
                    tier: str = "L2",
                    message: str = "",
                    chatops_config: dict[str, Any] | None = None,
                    ) -> dict[str, Any]:
    """Fire all configured chatops connectors with an alert built from
    the engagement.  Returns a result dict the API can echo back:

        {
          "tier":              "L2" | "L3",
          "connectors_fired":  ["slack", "pagerduty", ...],
          "connectors_failed": [...],   # connector raised, but emit() swallows
          "alert_preview":     {...}    # for the operator's audit trail
        }

    The connectors' `emit()` methods swallow exceptions internally
    (logging on failure) — see `plenith.connectors.chatops`.  We still
    report a `connectors_failed` list for the case where a connector
    construction itself errors.
    """
    from plenith.connectors.chatops import build_from_config

    alert = build_alert_from_engagement(engagement, tier=tier, message=message)
    connectors = build_from_config(chatops_config or {})

    fired: list[str] = []
    failed: list[dict[str, str]] = []
    for c in connectors:
        name = type(c).__name__
        try:
            await c.emit(alert)
            fired.append(name)
        except Exception as e:                          # defensive
            failed.append({"connector": name, "error": str(e)})

    return {
        "tier":              tier,
        "connectors_fired":  fired,
        "connectors_failed": failed,
        "alert_preview":     alert,
    }

def escalate_sync(engagement: dict[str, Any], *,
                   tier: str = "L2",
                   message: str = "",
                   chatops_config: dict[str, Any] | None = None,
                   ) -> dict[str, Any]:
    """Synchronous wrapper for callers that aren't in an event loop
    (the dashboard's BaseHTTPRequestHandler is synchronous)."""
    return asyncio.run(escalate(
        engagement, tier=tier, message=message,
        chatops_config=chatops_config,
    ))
