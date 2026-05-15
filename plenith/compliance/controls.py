"""Control-to-Plenith-evidence mapping table.

For every control in SOC 2 / ISO 27001 / NIS2 where Plenith can
contribute evidence, we list:
  - the control ID and framework reference
  - the human-readable control statement (paraphrased — see official
    spec for binding text)
  - the evidence type(s) the report harvester should look for
  - which Plenith subsystem produces that evidence

Auditors don't accept "we have a security platform" — they want
control-level evidence trails. This table is the schema for those trails.

References:
  SOC 2 TSC 2017      AICPA "Trust Services Criteria for Security,
                       Availability, Processing Integrity, Confidentiality,
                       and Privacy" (2017, revised 2022).
  ISO/IEC 27001:2022  Annex A — the 93 controls. Major themes:
                       Organizational (A.5), People (A.6), Physical
                       (A.7), Technological (A.8).
  NIS2 Article 21     EU Directive 2022/2555 — 10 risk-management
                       measure categories.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Evidence types — what kind of data the report harvester needs to pull
# ---------------------------------------------------------------------------

EVIDENCE_ENGAGEMENT_COUNT   = "engagement_count"
EVIDENCE_ALERTS_BY_SEVERITY = "alerts_by_severity"
EVIDENCE_ALERTS_BY_ACTION   = "alerts_by_action"
EVIDENCE_MITRE_COVERAGE     = "mitre_attck_coverage"
EVIDENCE_IOC_EXPORT_COUNT   = "ioc_exports"
EVIDENCE_ROTATION_HISTORY   = "content_rotation_epochs"
EVIDENCE_MFA_DECISIONS      = "mfa_decisions"
EVIDENCE_ISOLATION_PROBES   = "isolation_probe_history"
EVIDENCE_CONNECTORS         = "siem_connectors_configured"
EVIDENCE_POLICY_ENGINE      = "active_policy_engine"
EVIDENCE_OT_PROBES          = "ot_decoy_ioc_count"
EVIDENCE_COUNTER_AI         = "counter_ai_detections"

@dataclass(frozen=True)
class ControlMapping:
    framework:    str          # "SOC2" | "ISO27001" | "NIS2"
    control_id:   str          # e.g. "CC6.6", "A.8.16", "NIS2-21(2)(c)"
    title:        str
    statement:    str          # paraphrased control objective
    evidence:     list[str] = field(default_factory=list)
    notes:        str = ""

# ===========================================================================
# SOC 2 — Common Criteria (TSC 2017), focused on Security
# ===========================================================================

_SOC2 = [
    ControlMapping(
        "SOC2", "CC6.1", "Logical Access Controls",
        "The entity implements logical access security software, "
        "infrastructure, and architectures over protected information "
        "assets to protect them from security events.",
        [EVIDENCE_POLICY_ENGINE, EVIDENCE_MFA_DECISIONS,
         EVIDENCE_CONNECTORS],
        notes=("Plenith evidence: identity-proxy risk-scored routing "
               "with MFA step-up gate to real-prod; trained-policy or "
               "heuristic deception layer behind it."),
    ),
    ControlMapping(
        "SOC2", "CC6.6", "External Communication Restrictions",
        "The entity implements logical access security measures to "
        "protect against threats from sources outside its system boundaries.",
        [EVIDENCE_ISOLATION_PROBES, EVIDENCE_CONNECTORS],
        notes=("§4.2 isolation pillar: default-DROP egress, internal DNS "
               "resolver with no recursion, audited LLM bridge as sole "
               "egress path. 18-probe validation runs continuously."),
    ),
    ControlMapping(
        "SOC2", "CC6.7", "System Operation Monitoring",
        "The entity restricts the transmission, movement, and removal of "
        "information to authorized internal and external users and protects "
        "it during transmission, movement, or removal.",
        [EVIDENCE_ALERTS_BY_ACTION, EVIDENCE_IOC_EXPORT_COUNT],
        notes=("DNS-exfil detector + CoreDNS query log capture covert "
               "channels. STIX 2.1 export for IoC sharing."),
    ),
    ControlMapping(
        "SOC2", "CC7.1", "Detection and Monitoring",
        "To meet its objectives, the entity uses detection and monitoring "
        "procedures to identify (a) changes to configurations that result "
        "in the introduction of vulnerabilities, and (b) anomalies that "
        "may indicate malicious acts, natural disasters, and errors.",
        [EVIDENCE_ALERTS_BY_SEVERITY, EVIDENCE_MITRE_COVERAGE,
         EVIDENCE_COUNTER_AI],
        notes=("14 heuristic alerts + counter-AI detector covering 12 ATT&CK "
               "tactics. RL-trained policy as V2."),
    ),
    ControlMapping(
        "SOC2", "CC7.2", "System Monitoring",
        "The entity monitors system components and the operation of those "
        "components for anomalies that are indicative of malicious acts, "
        "natural disasters, and errors affecting the entity's ability to meet "
        "its objectives; anomalies are analyzed to determine whether they "
        "represent security events.",
        [EVIDENCE_ALERTS_BY_SEVERITY, EVIDENCE_OT_PROBES],
        notes=("All alerts emit through SIEM connectors (CEF/LEEF/syslog/HEC) "
               "with MITRE ATT&CK technique tags. OT decoys log Modbus/S7/DNP3 "
               "probes as separate IoC stream."),
    ),
    ControlMapping(
        "SOC2", "CC7.3", "Evaluation of Security Events",
        "The entity evaluates security events to determine whether they "
        "could or have resulted in a failure of the entity to meet its "
        "objectives (security incidents) and, if so, takes actions to "
        "prevent or address such failures.",
        [EVIDENCE_ALERTS_BY_SEVERITY, EVIDENCE_MITRE_COVERAGE],
        notes=("Every alert ships with severity (critical/high/medium/info), "
               "ATT&CK technique, recommended response, and an LLM-narrated "
               "incident summary on demand."),
    ),
    ControlMapping(
        "SOC2", "CC7.4", "Security Incident Response",
        "The entity responds to identified security incidents by executing "
        "a defined incident-response program to understand, contain, "
        "remediate, and communicate security incidents, as appropriate.",
        [EVIDENCE_MFA_DECISIONS, EVIDENCE_ALERTS_BY_ACTION],
        notes=("`isolate_session` heuristic response, MFA-step-up gating, "
               "ChatOps notifiers (Slack/Teams) + PagerDuty paging for "
               "critical alerts."),
    ),
    ControlMapping(
        "SOC2", "CC8.1", "Change Management",
        "The entity authorizes, designs, develops or acquires, configures, "
        "documents, tests, approves, and implements changes to "
        "infrastructure, data, software, and procedures to meet its objectives.",
        [EVIDENCE_ROTATION_HISTORY],
        notes=("Content-rotation epochs (quarterly cadence) regenerate every "
               "decoy artifact deterministically. Each epoch has a manifest "
               "with SHA-256 hashes for the auditor."),
    ),
]

# ===========================================================================
# ISO/IEC 27001:2022 — Annex A.8 (Technological controls)
# ===========================================================================

_ISO27001 = [
    ControlMapping(
        "ISO27001", "A.8.7", "Protection against malware",
        "Protection against malware shall be implemented and supported by "
        "appropriate user awareness.",
        [EVIDENCE_ALERTS_BY_ACTION, EVIDENCE_COUNTER_AI],
        notes=("Heuristic detection + counter-AI prompt-trap deception "
               "for LLM-driven attackers."),
    ),
    ControlMapping(
        "ISO27001", "A.8.8", "Management of technical vulnerabilities",
        "Information about technical vulnerabilities of information systems "
        "shall be obtained, the organization's exposure to such "
        "vulnerabilities shall be evaluated, and appropriate measures shall "
        "be taken.",
        [EVIDENCE_ISOLATION_PROBES],
        notes=("Continuous breakout-probe validation (18 probes × 3 agents, "
               "every 15 minutes by the §4.2 CronJob)."),
    ),
    ControlMapping(
        "ISO27001", "A.8.15", "Logging",
        "Logs that record activities, exceptions, faults and other relevant "
        "events shall be produced, stored, protected and analysed.",
        [EVIDENCE_ALERTS_BY_SEVERITY, EVIDENCE_CONNECTORS,
         EVIDENCE_IOC_EXPORT_COUNT],
        notes=("Every event written to the engagement JSONL log + "
               "fan-out emit to configured SIEM (Splunk HEC, Elastic, "
               "CEF/LEEF/syslog) with per-alert MITRE tags."),
    ),
    ControlMapping(
        "ISO27001", "A.8.16", "Monitoring activities",
        "Networks, systems and applications shall be monitored for anomalous "
        "behaviour and appropriate actions taken to evaluate potential "
        "information security incidents.",
        [EVIDENCE_ALERTS_BY_ACTION, EVIDENCE_MITRE_COVERAGE,
         EVIDENCE_OT_PROBES],
        notes=("Heuristic + RL policies score every command across 12 "
               "ATT&CK tactics. OT decoys cover ICS-layer monitoring "
               "(Modbus/S7/DNP3)."),
    ),
    ControlMapping(
        "ISO27001", "A.8.20", "Networks security",
        "Networks and network devices shall be secured, managed and "
        "controlled to protect information in systems and applications.",
        [EVIDENCE_ISOLATION_PROBES],
        notes=("k8s NetworkPolicy enforces §4.2 isolation: agents only "
               "egress to other agents + audited LLM bridge. CronJob runs "
               "the breakout-probe script every 15min."),
    ),
    ControlMapping(
        "ISO27001", "A.8.22", "Segregation of networks",
        "Groups of information services, users and information systems "
        "shall be segregated in the organization's networks.",
        [EVIDENCE_ISOLATION_PROBES],
        notes=("decoy_net (internal:true) is fully segregated from "
               "bridge_net; only audited services (proxy, llm-egress) "
               "are dual-homed."),
    ),
    ControlMapping(
        "ISO27001", "A.8.23", "Web filtering",
        "Access to external websites shall be managed to reduce exposure "
        "to malicious content.",
        [EVIDENCE_ISOLATION_PROBES, EVIDENCE_ALERTS_BY_ACTION],
        notes=("CoreDNS sealed against external recursion; "
               "`alert_dns_exfil` heuristic catches attempts at the "
               "shell level even when the agent isn't compromised."),
    ),
    ControlMapping(
        "ISO27001", "A.8.28", "Secure coding",
        "Secure coding principles shall be applied to software development.",
        [],
        notes=("Out-of-band: code is open-source under MIT; 412-test pytest "
               "suite enforces invariants on every PR via GitHub Actions CI."),
    ),
]

# ===========================================================================
# NIS2 — Article 21 cybersecurity risk-management measures
# ===========================================================================

_NIS2 = [
    ControlMapping(
        "NIS2", "Art21(2)(a)", "Policies on risk analysis and information security",
        "Policies on risk analysis and information system security.",
        [EVIDENCE_POLICY_ENGINE, EVIDENCE_ROTATION_HISTORY],
        notes=("RL-trained or heuristic policy + quarterly content rotation "
               "epoch with SHA-256 artifact manifest."),
    ),
    ControlMapping(
        "NIS2", "Art21(2)(b)", "Incident handling",
        "Incident handling.",
        [EVIDENCE_ALERTS_BY_SEVERITY, EVIDENCE_ALERTS_BY_ACTION,
         EVIDENCE_MFA_DECISIONS],
        notes=("Severity-tagged alerts → MFA step-up + isolate_session "
               "response + ChatOps + PagerDuty paging. Audit JSONL log "
               "preserves the full incident chain."),
    ),
    ControlMapping(
        "NIS2", "Art21(2)(c)", "Business continuity",
        "Business continuity, such as backup management and disaster "
        "recovery, and crisis management.",
        [EVIDENCE_ROTATION_HISTORY],
        notes=("Stateless agent containers; engagement state in a PVC; "
               "Helm chart documents RPO/RTO at the cluster level."),
    ),
    ControlMapping(
        "NIS2", "Art21(2)(d)", "Supply chain security",
        "Supply chain security, including security-related aspects "
        "concerning the relationships between each entity and its direct "
        "suppliers or service providers.",
        [EVIDENCE_CONNECTORS],
        notes=("All third-party connectors (Duo, Okta, Splunk, PagerDuty, "
               "Slack) abstracted behind a Protocol — provider can be "
               "swapped without orchestrator changes."),
    ),
    ControlMapping(
        "NIS2", "Art21(2)(e)", "Network and information system security",
        "Security in network and information systems acquisition, "
        "development and maintenance, including vulnerability handling "
        "and disclosure.",
        [EVIDENCE_ISOLATION_PROBES, EVIDENCE_ALERTS_BY_ACTION],
        notes=("18-probe breakout test runs on every deploy and every "
               "15 min in production. PROXY-protocol v1 forwarding so "
               "agents see real client IPs."),
    ),
    ControlMapping(
        "NIS2", "Art21(2)(f)", "Effectiveness assessment",
        "Policies and procedures to assess the effectiveness of "
        "cybersecurity risk-management measures.",
        [EVIDENCE_MITRE_COVERAGE, EVIDENCE_ENGAGEMENT_COUNT],
        notes=("ATT&CK coverage matrix exported from "
               "`tools/connectors.py coverage`; engagement-count "
               "histogram from audit tool."),
    ),
    ControlMapping(
        "NIS2", "Art21(2)(g)", "Basic cyber hygiene",
        "Basic cyber hygiene practices and cybersecurity training.",
        [],
        notes=("Out-of-band: operator runbook + dashboard."),
    ),
    ControlMapping(
        "NIS2", "Art21(2)(h)", "Cryptography and encryption",
        "Policies and procedures regarding the use of cryptography and, "
        "where appropriate, encryption.",
        [EVIDENCE_MFA_DECISIONS],
        notes=("TOTP (RFC 6238), HMAC-SHA1; SSH transport encryption; "
               "MFA decision files include integrity timestamps."),
    ),
    ControlMapping(
        "NIS2", "Art21(2)(i)", "Human resources security and access control",
        "Human resources security, access control policies and asset "
        "management.",
        [EVIDENCE_MFA_DECISIONS, EVIDENCE_POLICY_ENGINE],
        notes=("Identity-proxy risk-scored access; MFA enrollment store "
               "with per-user TOTP secrets; per-engagement state keyed "
               "by (source_ip, claimed_user)."),
    ),
    ControlMapping(
        "NIS2", "Art21(2)(j)", "Multi-factor authentication",
        "The use of multi-factor authentication or continuous "
        "authentication solutions, secured voice, video and text "
        "communications and secured emergency communication systems.",
        [EVIDENCE_MFA_DECISIONS],
        notes=("MFA step-up gateway with Duo / Okta / Twilio / push-sim "
               "providers. PROXY-v1 forwarding preserves real source IP "
               "for decision keying."),
    ),
]

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_FRAMEWORKS = {
    "soc2":      _SOC2,
    "iso27001":  _ISO27001,
    "nis2":      _NIS2,
}

def all_frameworks() -> list[str]:
    return list(_FRAMEWORKS.keys())

def controls_for(framework: str) -> list[ControlMapping]:
    return list(_FRAMEWORKS.get(framework.lower(), []))

def all_controls() -> list[ControlMapping]:
    out = []
    for fw in _FRAMEWORKS.values():
        out.extend(fw)
    return out
