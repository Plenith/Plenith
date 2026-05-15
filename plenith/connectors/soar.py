"""SOAR connectors — Cortex XSOAR + Splunk SOAR.

The SOAR (Security Orchestration, Automation and Response) layer is
where the SOC's playbooks live: "if alert X fires, do Y." Every
commercial deception platform ships with a content pack for the SOAR
the customer already uses. This module is our equivalent.

Two transports + a playbook-hint registry:

  CortexXSOAR (Palo Alto Networks)
      REST API: POST /incident
      Mapping: Plenith alert → XSOAR Incident
      Auth: API key (X-API-Key header) + X-API-Key-ID

  SplunkSOAR (formerly Phantom)
      REST API: POST /rest/container then /rest/artifact (per IoC)
      Mapping: Plenith alert → SOAR Container (case) + artifacts
      Auth: ph-auth-token header

  Playbook hints — per-action JSON snippets the SOC analyst imports
      into their SOAR. Each hint declares the trigger condition, the
      recommended sequence of actions, and references to MITRE ATT&CK
      mitigation IDs.

The connectors follow the same `emit/flush` contract as siem.py /
chatops.py — they drop into the existing `FanOut`.
"""
from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Any

import httpx
from datetime import UTC

log = logging.getLogger("plenith.connectors.soar")

# ---------------------------------------------------------------------------
# Severity mapping — each SOAR has its own scale
# ---------------------------------------------------------------------------

# XSOAR severity: 0.5=Informational, 1=Low, 2=Medium, 3=High, 4=Critical
_XSOAR_SEVERITY = {
    "critical": 4,
    "high":     3,
    "medium":   2,
    "info":     1,
    "low":      0.5,
}

# Splunk SOAR severity: low | medium | high (no critical bucket)
_SPLUNK_SOAR_SEVERITY = {
    "critical": "high",
    "high":     "high",
    "medium":   "medium",
    "info":     "low",
    "low":      "low",
}

# ---------------------------------------------------------------------------
# Cortex XSOAR
# ---------------------------------------------------------------------------

@dataclass
class CortexXSOARClient:
    """Cortex XSOAR (Palo Alto Networks) incident-create client.

    Spec: https://xsoar.pan.dev/docs/reference/api/
    Endpoint:  POST /incident
    Required:  X-API-Key + X-API-Key-ID headers
    Payload:   {
                 "name":     str,
                 "type":     str (incident type — usually a custom
                            "PlenithDeception" type),
                 "severity": float (0.5 .. 4),
                 "details":  str,
                 "labels":   [{type, value}, ...],
                 "rawJSON":  str (the full alert as JSON),
                 "occurred": ISO timestamp,
               }
    """
    base_url:        str
    api_key:         str
    api_key_id:      str
    incident_type:   str  = "PlenithDeception"
    verify_tls:      bool = True
    timeout_seconds: float = 10.0

    def _payload(self, alert: dict[str, Any]) -> dict[str, Any]:
        sev = alert.get("severity", "info")
        action = alert.get("action", "unknown")
        labels: list[dict[str, str]] = [
            {"type": "Plenith-Action",   "value": action},
            {"type": "Plenith-Severity", "value": sev},
        ]
        for key, label in (
            ("source_ip",       "Source IP"),
            ("claimed_user",    "Claimed User"),
            ("hostname",        "Decoy Host"),
            ("engagement_id",   "Engagement"),
            ("mitre_technique", "MITRE Technique"),
            ("mitre_tactic",    "MITRE Tactic"),
        ):
            v = alert.get(key)
            if v:
                labels.append({"type": label, "value": str(v)})

        from datetime import datetime, timezone
        occurred = (
            datetime.now(UTC)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )
        return {
            "name":     f"[{sev.upper()}] {action}",
            "type":     self.incident_type,
            "severity": _XSOAR_SEVERITY.get(sev, 1),
            "details":  alert.get("rationale", "") or f"Plenith alert: {action}",
            "labels":   labels,
            "rawJSON":  json.dumps(alert, default=str),
            "occurred": occurred,
        }

    async def emit(self, alert: dict[str, Any]) -> None:
        try:
            async with httpx.AsyncClient(verify=self.verify_tls,
                                          timeout=self.timeout_seconds) as c:
                r = await c.post(
                    self.base_url.rstrip("/") + "/incident",
                    headers={
                        "X-API-Key":    self.api_key,
                        "X-API-Key-ID": self.api_key_id,
                        "Accept":       "application/json",
                    },
                    json=self._payload(alert),
                )
                r.raise_for_status()
        except Exception as e:
            log.warning("Cortex XSOAR emit failed: %s", e)

    async def flush(self) -> int:
        return 0

# ---------------------------------------------------------------------------
# Splunk SOAR (Phantom)
# ---------------------------------------------------------------------------

@dataclass
class SplunkSOARClient:
    """Splunk SOAR (Phantom) container + artifact client.

    Spec: https://docs.splunk.com/Documentation/SOARonprem/current/PlatformAPI/RESTContainers
    Endpoints:
      POST /rest/container       — create the case/container
      POST /rest/artifact        — per IoC (one POST each)
    Auth:  ph-auth-token: <token>
    """
    base_url:        str
    auth_token:      str
    label:           str = "plenith_deception"
    verify_tls:      bool = True
    timeout_seconds: float = 10.0

    def _container_payload(self, alert: dict[str, Any]) -> dict[str, Any]:
        sev = alert.get("severity", "info")
        return {
            "name":        f"[{sev.upper()}] {alert.get('action', 'alert')}",
            "description": alert.get("rationale", ""),
            "severity":    _SPLUNK_SOAR_SEVERITY.get(sev, "low"),
            "status":      "new",
            "label":       self.label,
            "source_data_identifier":
                f"plenith:{alert.get('engagement_id', 'anon')}:{alert.get('action', '?')}",
            "data": {
                "engagement_id":   alert.get("engagement_id"),
                "mitre_technique": alert.get("mitre_technique"),
                "mitre_tactic":    alert.get("mitre_tactic"),
                "triggered_by":    alert.get("triggered_by"),
            },
        }

    def _artifact_payloads(self, alert: dict[str, Any]) -> list[dict[str, Any]]:
        """One artifact per IoC field present on the alert. Splunk SOAR
        CEFs are flexible — we use the well-known field names."""
        out = []
        if alert.get("source_ip"):
            out.append({
                "name":  "Source IP",
                "cef":   {"sourceAddress": alert["source_ip"]},
                "label": "src_ip",
            })
        if alert.get("claimed_user"):
            out.append({
                "name":  "Claimed User",
                "cef":   {"sourceUserName": alert["claimed_user"]},
                "label": "user",
            })
        if alert.get("triggered_by"):
            out.append({
                "name":  "Trigger Command",
                "cef":   {"requestURL": alert["triggered_by"]},
                "label": "command",
            })
        return out

    async def emit(self, alert: dict[str, Any]) -> None:
        headers = {
            "ph-auth-token": self.auth_token,
            "Content-Type":  "application/json",
            "Accept":        "application/json",
        }
        try:
            async with httpx.AsyncClient(verify=self.verify_tls,
                                          timeout=self.timeout_seconds) as c:
                # 1. Create the container
                r = await c.post(
                    self.base_url.rstrip("/") + "/rest/container",
                    headers=headers, json=self._container_payload(alert),
                )
                r.raise_for_status()
                cid = r.json().get("id")
                if not cid:
                    return
                # 2. POST one artifact per IoC field
                for art in self._artifact_payloads(alert):
                    art["container_id"] = cid
                    try:
                        ar = await c.post(
                            self.base_url.rstrip("/") + "/rest/artifact",
                            headers=headers, json=art,
                        )
                        ar.raise_for_status()
                    except Exception as e:
                        log.debug("Splunk SOAR artifact POST failed: %s", e)
        except Exception as e:
            log.warning("Splunk SOAR emit failed: %s", e)

    async def flush(self) -> int:
        return 0

# ---------------------------------------------------------------------------
# Playbook hint registry — per-action recommended response sequences
# ---------------------------------------------------------------------------
#
# Auditors and SOC managers want "given this alert, what does the
# analyst do?" written down. This is the source of truth for those
# recommended responses, exportable as JSON to import into either
# Cortex XSOAR (as a playbook YAML) or Splunk SOAR (as a playbook JSON).
# Action format follows the common SOAR primitives: enrich / contain /
# notify / hunt / lessons-learned.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PlaybookStep:
    primitive: str           # enrich | contain | notify | hunt | document
    target:    str           # what we operate on
    note:      str           # human-readable detail

@dataclass(frozen=True)
class PlaybookHint:
    action:       str        # Plenith action this matches
    name:         str        # human-readable name
    severity_threshold: str  # minimum severity that fires this playbook
    mitre_techniques: list[str]
    steps:        list[PlaybookStep]

_PLAYBOOK_REGISTRY: list[PlaybookHint] = [
    PlaybookHint(
        action="alert_credential_exfil",
        name="Credential Exfiltration Response",
        severity_threshold="high",
        mitre_techniques=["T1552.001", "T1005"],
        steps=[
            PlaybookStep("enrich",   "source_ip",
                         "Lookup IP rep (AbuseIPDB), geo, ASN, prior alerts."),
            PlaybookStep("enrich",   "claimed_user",
                         "Resolve user → AD record; confirm employment status."),
            PlaybookStep("contain",  "source_ip",
                         "Block at perimeter firewall + identity-proxy block list."),
            PlaybookStep("contain",  "credential",
                         "Force rotation of the REAL credentials that the planted "
                         "honeytoken impersonates."),
            PlaybookStep("notify",   "identity_team",
                         "Page the identity team for credential rotation tracking."),
            PlaybookStep("hunt",     "siem",
                         "Pivot: find any other sessions from this IP / user "
                         "across SIEM logs in last 30 days."),
            PlaybookStep("document", "case",
                         "Attach session-log to case; record TTPs for retro."),
        ],
    ),
    PlaybookHint(
        action="alert_ssh_persistence",
        name="SSH Persistence Containment",
        severity_threshold="critical",
        mitre_techniques=["T1098.004"],
        steps=[
            PlaybookStep("contain", "session",
                         "Immediately kill SSH session via orchestrator API."),
            PlaybookStep("contain", "key_rotation",
                         "Rotate ALL ssh authorized_keys on adjacent real hosts."),
            PlaybookStep("hunt",    "logs",
                         "Search auth.log on real prod for any sshd accepted-publickey "
                         "matching the planted key signature."),
            PlaybookStep("notify",  "incident_response",
                         "Escalate to IR tier 3 — this is a confirmed compromise attempt."),
            PlaybookStep("document", "case",
                         "Snapshot bastion-prod container state for forensics."),
        ],
    ),
    PlaybookHint(
        action="alert_reverse_shell",
        name="Reverse Shell — Active C2",
        severity_threshold="critical",
        mitre_techniques=["T1059.004", "T1095"],
        steps=[
            PlaybookStep("contain", "session",
                         "Sever SSH session immediately; do not engage further."),
            PlaybookStep("hunt",    "netflow",
                         "Capture full netflow from source IP for last 4 hours."),
            PlaybookStep("contain", "c2_destination",
                         "Block destination IP/port at perimeter."),
            PlaybookStep("notify",  "exec",
                         "Critical-severity page to CISO on-call."),
            PlaybookStep("document", "case",
                         "Preserve container snapshot, command stream, and any "
                         "memory dump for adversary tradecraft analysis."),
        ],
    ),
    PlaybookHint(
        action="alert_dns_exfil",
        name="DNS / HTTP Exfil Block",
        severity_threshold="high",
        mitre_techniques=["T1071.004", "T1048.003"],
        steps=[
            PlaybookStep("enrich",  "destination",
                         "Lookup destination domain against TI feeds (VirusTotal, "
                         "URLhaus, GreyNoise)."),
            PlaybookStep("contain", "domain",
                         "Block destination at egress DNS resolver + perimeter firewall."),
            PlaybookStep("hunt",    "siem",
                         "Pivot: search SIEM for any other hosts that resolved "
                         "this domain in last 30 days."),
            PlaybookStep("document", "ioc",
                         "Export domain as STIX 2.1 indicator; submit to org "
                         "TI sharing program."),
        ],
    ),
    PlaybookHint(
        action="alert_attacker_llm_detected",
        name="LLM-Driven Adversary Response",
        severity_threshold="high",
        mitre_techniques=["MC-AI-001"],
        steps=[
            PlaybookStep("enrich",  "session",
                         "Capture full command stream for adversary-tradecraft analysis "
                         "— LLM-driven attacks are still rare and forensically valuable."),
            PlaybookStep("contain", "trap_arm",
                         "Counter-AI trap is already armed; do NOT disrupt the "
                         "session — let the trap fire."),
            PlaybookStep("hunt",    "session",
                         "Watch for trap marker echoed back into subsequent commands "
                         "→ confirms LLM consumption of decoy outputs."),
            PlaybookStep("notify",  "research",
                         "Notify threat-research team — this is research-grade data."),
            PlaybookStep("document", "case",
                         "Tag case with `adversary-ai`; queue for quarterly TTP report."),
        ],
    ),
    PlaybookHint(
        action="alert_lateral_decoy",
        name="Lateral Movement to Decoy",
        severity_threshold="high",
        mitre_techniques=["T1021.004"],
        steps=[
            PlaybookStep("enrich",  "source_ip",
                         "Cross-reference with prior alerts on this IP."),
            PlaybookStep("contain", "lateral",
                         "Verify NO real prod host accepted lateral SSH from "
                         "this IP — the decoy network MUST stay isolated."),
            PlaybookStep("hunt",    "ssh_audit",
                         "Audit auth.log on every real prod host for any "
                         "successful login from this IP in last 30 days."),
            PlaybookStep("notify",  "soc",
                         "Standard SOC notification — analyst review."),
        ],
    ),
    PlaybookHint(
        action="alert_decoy_swallowed",
        name="Honeytoken Read — Engagement Confirmed",
        severity_threshold="medium",
        mitre_techniques=["T1083"],
        steps=[
            PlaybookStep("document", "engagement",
                         "Engagement is confirmed (attacker followed the planted trail). "
                         "Continue monitoring — do not disrupt."),
            PlaybookStep("hunt",     "ttps",
                         "Capture the trail the attacker followed for retro."),
            PlaybookStep("notify",   "threat_intel",
                         "Schedule IoC export to org TI sharing program once "
                         "engagement concludes."),
        ],
    ),
    PlaybookHint(
        action="alert_log_tampering",
        name="Log Tampering — Pre-Exfil Indicator",
        severity_threshold="high",
        mitre_techniques=["T1070.002", "T1070.003"],
        steps=[
            PlaybookStep("contain", "session",
                         "Snapshot session log + container state BEFORE further "
                         "interaction — attacker is trying to cover tracks."),
            PlaybookStep("hunt",    "concurrent",
                         "Check for concurrent sessions on real prod from same IP."),
            PlaybookStep("notify",  "incident_response",
                         "Tier 2/3 escalation — this is a late-stage compromise signal."),
        ],
    ),
]

def hints_for(action: str) -> list[PlaybookHint]:
    return [h for h in _PLAYBOOK_REGISTRY if h.action == action]

def all_hints() -> list[PlaybookHint]:
    return list(_PLAYBOOK_REGISTRY)

def export_xsoar_playbook(hint: PlaybookHint) -> dict[str, Any]:
    """Render one PlaybookHint as a Cortex XSOAR playbook descriptor.
    Auditors / analysts import this JSON into XSOAR as a starter
    playbook; they can then customize the implementation tasks.
    """
    return {
        "id":          f"plenith-{hint.action}",
        "name":        f"Plenith: {hint.name}",
        "version":     -1,
        "fromversion": "6.0.0",
        "tags":        ["plenith", "deception",
                        *(f"mitre.{t.lower()}" for t in hint.mitre_techniques)],
        "trigger": {
            "incident_type": "PlenithDeception",
            "filter": {"field": "labels.Plenith-Action",
                        "operator": "equals", "value": hint.action},
        },
        "tasks": [
            {"id": str(i + 1),
             "type": step.primitive,
             "name": f"{step.primitive}: {step.target}",
             "description": step.note}
            for i, step in enumerate(hint.steps)
        ],
    }

def export_splunk_soar_playbook(hint: PlaybookHint) -> dict[str, Any]:
    """Render one PlaybookHint as a Splunk SOAR playbook descriptor."""
    return {
        "name":          f"Plenith: {hint.name}",
        "description":   f"Auto-generated from Plenith PlaybookHint "
                          f"for action {hint.action!r}.",
        "labels":        ["plenith", "deception"],
        "tags":          [f"mitre.{t.lower()}" for t in hint.mitre_techniques],
        "trigger_label": "plenith_deception",
        "phases": [
            {"phase": step.primitive,
             "title": step.target,
             "description": step.note,
             "order": i}
            for i, step in enumerate(hint.steps)
        ],
    }

# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def build_from_config(cfg: dict[str, Any] | None) -> list:
    """Build every SOAR connector named in config. Schema:

        soar:
          xsoar:
            base_url:   https://xsoar.example.com:443
            api_key:    ...
            api_key_id: ...
            incident_type: PlenithDeception
          splunk_soar:
            base_url:   https://soar.example.com:443
            auth_token: ...
            label:      plenith_deception
    """
    if not cfg:
        return []
    block = cfg.get("soar") if isinstance(cfg, dict) else None
    if not block:
        return []
    out: list = []
    if block.get("xsoar", {}).get("base_url"):
        x = block["xsoar"]
        out.append(CortexXSOARClient(
            base_url=x["base_url"], api_key=x.get("api_key", ""),
            api_key_id=x.get("api_key_id", ""),
            incident_type=x.get("incident_type", "PlenithDeception"),
            verify_tls=bool(x.get("verify_tls", True)),
        ))
    if block.get("splunk_soar", {}).get("base_url"):
        s = block["splunk_soar"]
        out.append(SplunkSOARClient(
            base_url=s["base_url"], auth_token=s.get("auth_token", ""),
            label=s.get("label", "plenith_deception"),
            verify_tls=bool(s.get("verify_tls", True)),
        ))
    return out
