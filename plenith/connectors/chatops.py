"""ChatOps webhooks — Slack, Microsoft Teams, PagerDuty.

Each emitter renders a Plenith alert into the native payload shape
its platform expects. The reason this is its own module (vs. the
generic webhook in siem.py) is that humans WANT rich rendering — Slack
blocks, Teams adaptive cards, PagerDuty severity mapping — not a raw
JSON dump. A SOC analyst who sees `[CRIT] alert_ssh_persistence` as a
red card with an "Acknowledge" button reacts in seconds; one who sees
it as `{"action": "...", ...}` ignores it.

All three follow the same contract as `siem.py` — `.emit(alert)` and
`.flush()` — so the `FanOut` plumbing works unchanged.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict

import httpx

log = logging.getLogger("plenith.connectors.chatops")


_SEVERITY_TO_COLOR = {
    "critical": "#d63b3b",
    "high":     "#e8851e",
    "medium":   "#d8b91a",
    "info":     "#3aa6c2",
    "low":      "#7f8c8d",
}

# PagerDuty Events API v2 maps severity to one of: critical, error, warning, info
_SEVERITY_TO_PD = {
    "critical": "critical",
    "high":     "error",
    "medium":   "warning",
    "info":     "info",
    "low":      "info",
}


# ---------------------------------------------------------------------------
# Slack
# ---------------------------------------------------------------------------

@dataclass
class SlackWebhook:
    """Slack Incoming Webhook (https://api.slack.com/messaging/webhooks).

    Renders as a colored attachment with title / body / fields. The
    color bar on the left makes severity visible at a glance. Fields
    include source IP, user, engagement, and (when present) ATT&CK
    technique — exactly what an analyst needs in the first 2 seconds.
    """
    url: str
    timeout_seconds: float = 5.0
    channel: str = ""             # Optional override (Slack-app-dependent)
    username: str = "Plenith"
    icon_emoji: str = ":shield:"

    def _payload(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        sev = alert.get("severity", "info")
        color = _SEVERITY_TO_COLOR.get(sev, "#888")
        title = f"[{sev.upper()}] {alert.get('action', 'alert')}"

        # Compact field list — Slack renders 2 columns
        fields = []
        for label, key in (
            ("Source", "source_ip"),
            ("User",   "claimed_user"),
            ("Host",   "hostname"),
            ("ATT&CK", "mitre_technique"),
            ("Engagement", "engagement_id"),
        ):
            v = alert.get(key)
            if not v:
                continue
            # Engagement id is long — truncate to 8 chars
            if key == "engagement_id":
                v = str(v)[:8]
            fields.append({"title": label, "value": str(v), "short": True})

        payload: Dict[str, Any] = {
            "username": self.username,
            "icon_emoji": self.icon_emoji,
            "attachments": [{
                "color":     color,
                "title":     title,
                "text":      alert.get("rationale", ""),
                "fields":    fields,
                "footer":    "Plenith Deception Platform",
                "ts":        int(alert.get("ts_offset_s", 0) or 0),
            }],
        }
        if self.channel:
            payload["channel"] = self.channel
        return payload

    async def emit(self, alert: Dict[str, Any]) -> None:
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as c:
                r = await c.post(self.url, json=self._payload(alert))
                r.raise_for_status()
        except Exception as e:
            log.warning("Slack webhook failed: %s", e)

    async def flush(self) -> int:
        return 0


# ---------------------------------------------------------------------------
# Microsoft Teams (Incoming Webhook with MessageCard schema)
# ---------------------------------------------------------------------------

@dataclass
class TeamsWebhook:
    """Microsoft Teams Incoming Webhook.

    Uses the legacy MessageCard schema (still widely supported);
    Adaptive Cards are the newer schema but require a more complex
    `attachments[]` envelope and authenticated app. The MessageCard
    shape works against any Teams channel webhook URL.
    """
    url: str
    timeout_seconds: float = 5.0

    def _payload(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        sev = alert.get("severity", "info")
        color = _SEVERITY_TO_COLOR.get(sev, "#888").lstrip("#")
        title = f"[{sev.upper()}] {alert.get('action', 'alert')}"

        facts = []
        for label, key in (
            ("Source IP",     "source_ip"),
            ("Claimed User",  "claimed_user"),
            ("Host",          "hostname"),
            ("ATT&CK",        "mitre_technique"),
            ("Engagement",    "engagement_id"),
            ("Triggered by",  "triggered_by"),
        ):
            v = alert.get(key)
            if not v:
                continue
            if key == "engagement_id":
                v = str(v)[:8]
            facts.append({"name": label, "value": str(v)})

        return {
            "@type":      "MessageCard",
            "@context":   "https://schema.org/extensions",
            "themeColor": color,
            "summary":    title,
            "sections": [{
                "activityTitle":    title,
                "activitySubtitle": "Plenith Deception Platform",
                "text":             alert.get("rationale", ""),
                "facts":            facts,
                "markdown":         True,
            }],
        }

    async def emit(self, alert: Dict[str, Any]) -> None:
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as c:
                r = await c.post(self.url, json=self._payload(alert))
                r.raise_for_status()
        except Exception as e:
            log.warning("Teams webhook failed: %s", e)

    async def flush(self) -> int:
        return 0


# ---------------------------------------------------------------------------
# PagerDuty Events API v2
# ---------------------------------------------------------------------------

@dataclass
class PagerDutyEventsV2:
    """PagerDuty Events API v2 (https://developer.pagerduty.com/docs/events-api-v2).

    Routes to an integration key (services-level). Dedup key derived
    from engagement_id + action so the same engagement firing the same
    alert twice doesn't create a duplicate incident.
    """
    routing_key: str
    url: str = "https://events.pagerduty.com/v2/enqueue"
    timeout_seconds: float = 5.0
    minimum_severity: str = "high"   # don't page on info/medium by default
    _severity_rank = {"critical": 0, "high": 1, "medium": 2, "info": 3, "low": 4}

    def _should_page(self, alert: Dict[str, Any]) -> bool:
        a_sev = self._severity_rank.get(alert.get("severity", "info"), 99)
        thresh = self._severity_rank.get(self.minimum_severity, 1)
        return a_sev <= thresh

    def _payload(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        sev = alert.get("severity", "info")
        action = alert.get("action", "alert")
        eng = str(alert.get("engagement_id") or "")[:16]
        return {
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "dedup_key": f"plenith:{action}:{eng}" if eng else f"plenith:{action}",
            "payload": {
                "summary":   f"[{sev.upper()}] {action} — {alert.get('rationale', '')[:160]}",
                "severity":  _SEVERITY_TO_PD.get(sev, "info"),
                "source":    alert.get("hostname", "plenith"),
                "component": alert.get("source_ip", "unknown"),
                "group":     "deception-platform",
                "class":     alert.get("mitre_tactic", "deception-event"),
                "custom_details": {
                    "engagement_id":   alert.get("engagement_id"),
                    "claimed_user":    alert.get("claimed_user"),
                    "triggered_by":    alert.get("triggered_by"),
                    "mitre_technique": alert.get("mitre_technique"),
                    "mitre_tactic":    alert.get("mitre_tactic"),
                },
            },
        }

    async def emit(self, alert: Dict[str, Any]) -> None:
        if not self._should_page(alert):
            return
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as c:
                r = await c.post(self.url, json=self._payload(alert))
                r.raise_for_status()
        except Exception as e:
            log.warning("PagerDuty enqueue failed: %s", e)

    async def flush(self) -> int:
        return 0


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def build_from_config(cfg: Dict[str, Any] | None) -> list:
    """Build every ChatOps emitter named in the config. Returns a list
    (the caller composes them into a FanOut). Schema:

        chatops:
          slack:
            url:     https://hooks.slack.com/services/...
            channel: "#soc-alerts"
          teams:
            url: https://outlook.office.com/webhook/...
          pagerduty:
            routing_key:       abcd1234...
            minimum_severity:  high
    """
    if not cfg:
        return []
    block = cfg.get("chatops") if isinstance(cfg, dict) else None
    if not block:
        return []
    out = []
    if block.get("slack", {}).get("url"):
        s = block["slack"]
        out.append(SlackWebhook(
            url=s["url"], channel=s.get("channel", ""),
            username=s.get("username", "Plenith"),
            icon_emoji=s.get("icon_emoji", ":shield:"),
        ))
    if block.get("teams", {}).get("url"):
        out.append(TeamsWebhook(url=block["teams"]["url"]))
    if block.get("pagerduty", {}).get("routing_key"):
        p = block["pagerduty"]
        out.append(PagerDutyEventsV2(
            routing_key=p["routing_key"],
            minimum_severity=p.get("minimum_severity", "high"),
        ))
    return out
