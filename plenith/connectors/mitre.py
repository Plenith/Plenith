"""MITRE ATT&CK technique mapping.

Every commercial SIEM/SOAR in 2026 expects alerts to be tagged with
their ATT&CK technique ID so playbooks can match them to response
runbooks. This module owns the mapping from Plenith action names to
ATT&CK technique + tactic identifiers, plus helpers to enrich an alert
dict and to render Sigma rule `tags:` fields.

The mapping is intentionally conservative — we tag what's clearly
diagnostic, not every distant association. Multiple techniques per
action are common (e.g. credential search = T1552.001 + T1083).

Reference: MITRE ATT&CK Enterprise Matrix v14 (2026 Spring update).
Source: https://attack.mitre.org/
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass(frozen=True)
class MitreMapping:
    technique:      str            # e.g. "T1552.001"
    technique_name: str            # human-readable
    tactic:         str            # MITRE tactic label
    tactic_id:      str            # MITRE tactic ID (TA####)


# ---------------------------------------------------------------------------
# Master mapping. Keys are Plenith action names from ACTION_SPACE.
# Multiple mappings per action = the technique most-likely-diagnostic comes
# first; SIEM playbooks may match on any.
# ---------------------------------------------------------------------------

ACTION_TO_MITRE: Dict[str, List[MitreMapping]] = {
    # ---- Detection alerts ----
    "alert_credential_search": [
        MitreMapping("T1552.001", "Credentials In Files",
                     "Credential Access", "TA0006"),
        MitreMapping("T1083",     "File and Directory Discovery",
                     "Discovery",         "TA0007"),
    ],
    "alert_credential_exfil": [
        MitreMapping("T1552.001", "Credentials In Files",
                     "Credential Access", "TA0006"),
        MitreMapping("T1005",     "Data from Local System",
                     "Collection",        "TA0009"),
    ],
    "alert_honeytoken_tamper": [
        MitreMapping("T1070.004", "File Deletion",
                     "Defense Evasion",   "TA0005"),
        MitreMapping("T1565.001", "Stored Data Manipulation",
                     "Impact",            "TA0040"),
    ],
    "alert_payload_staging": [
        MitreMapping("T1074",     "Data Staged",
                     "Collection",        "TA0009"),
    ],
    "alert_decoy_swallowed": [
        # Not a standard ATT&CK technique — we report the closest
        # discovery technique the action represents (the attacker
        # discovered our planted artifact).
        MitreMapping("T1083",     "File and Directory Discovery",
                     "Discovery",         "TA0007"),
    ],
    "alert_dns_exfil": [
        MitreMapping("T1071.004", "Application Layer Protocol: DNS",
                     "Command and Control", "TA0011"),
        MitreMapping("T1048.003", "Exfiltration Over Unencrypted Protocol",
                     "Exfiltration",      "TA0010"),
    ],
    "alert_lateral_decoy": [
        MitreMapping("T1021.004", "Remote Services: SSH",
                     "Lateral Movement",  "TA0008"),
    ],
    "alert_log_tampering": [
        MitreMapping("T1070.003", "Clear Command History",
                     "Defense Evasion",   "TA0005"),
        MitreMapping("T1070.002", "Clear Linux or Mac System Logs",
                     "Defense Evasion",   "TA0005"),
    ],
    "alert_ssh_persistence": [
        MitreMapping("T1098.004", "Account Manipulation: SSH Authorized Keys",
                     "Persistence",       "TA0003"),
    ],
    "alert_reverse_shell": [
        MitreMapping("T1059.004", "Command and Scripting Interpreter: Unix Shell",
                     "Execution",         "TA0002"),
        MitreMapping("T1095",     "Non-Application Layer Protocol",
                     "Command and Control", "TA0011"),
    ],
    "alert_attacker_llm_detected": [
        # Brand-new in 2026 — no official ATT&CK technique yet for
        # "attacker is using AI". Mapping to T1496 (Resource Hijacking)
        # is a stretch but captures the "attacker tooling fingerprint"
        # spirit. Some commercial vendors mint custom tags like "T1xxx-AI";
        # we follow the same pattern with a vendor-prefixed extension.
        MitreMapping("MC-AI-001", "Adversary AI Tooling Detected",
                     "Reconnaissance",    "TA0043"),
    ],

    # ---- Response actions (these aren't "detections" but are still
    # useful to tag for SOAR playbook routing) ----
    "isolate_session": [
        MitreMapping("M1037",     "Filter Network Traffic (mitigation)",
                     "Mitigation",        "M1037"),
    ],
    "plant_sudo_vulnerability": [
        MitreMapping("M1015",     "Active Directory Configuration (mitigation)",
                     "Mitigation",        "M1015"),
    ],
    "spawn_fake_mysql": [
        MitreMapping("M1015",     "Active Directory Configuration (mitigation)",
                     "Mitigation",        "M1015"),
    ],
    "plant_aws_credentials": [
        MitreMapping("M1015",     "Active Directory Configuration (mitigation)",
                     "Mitigation",        "M1015"),
    ],
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def technique_for(action: str) -> Optional[MitreMapping]:
    """Return the PRIMARY (first) ATT&CK mapping for an action."""
    mappings = ACTION_TO_MITRE.get(action)
    return mappings[0] if mappings else None


def all_techniques_for(action: str) -> List[MitreMapping]:
    return list(ACTION_TO_MITRE.get(action, []))


def enrich(alert: dict) -> dict:
    """Add ATT&CK fields in-place to an alert dict if its `action` has
    a mapping. Adds `mitre_technique`, `mitre_technique_name`,
    `mitre_tactic`, `mitre_tactic_id` for the primary mapping plus
    `mitre_techniques` (list) for the full set.

    Returns the same dict so callers can chain."""
    action = alert.get("action")
    if not action:
        return alert
    mappings = ACTION_TO_MITRE.get(action)
    if not mappings:
        return alert
    primary = mappings[0]
    alert["mitre_technique"]      = primary.technique
    alert["mitre_technique_name"] = primary.technique_name
    alert["mitre_tactic"]         = primary.tactic
    alert["mitre_tactic_id"]      = primary.tactic_id
    if len(mappings) > 1:
        alert["mitre_techniques"] = [
            {"technique": m.technique, "name": m.technique_name,
             "tactic": m.tactic, "tactic_id": m.tactic_id}
            for m in mappings
        ]
    return alert


def sigma_tags(action: str) -> List[str]:
    """Render the `tags:` list a Sigma rule for this action should
    declare. Sigma convention is `attack.tXXXX` (lowercase, dot-separated)
    for techniques + `attack.<tactic>` for tactics."""
    out = []
    for m in all_techniques_for(action):
        # MITRE technique IDs in Sigma are normalized lowercase, with a
        # period preserved (T1552.001 → attack.t1552.001).
        out.append("attack." + m.technique.lower())
        out.append("attack." + m.tactic.lower().replace(" ", "_"))
    # De-dupe while preserving order
    seen = set()
    uniq = []
    for t in out:
        if t not in seen:
            seen.add(t)
            uniq.append(t)
    return uniq


def coverage_report() -> dict:
    """Return a structured map of every Plenith action and its
    ATT&CK coverage. Useful for the audit tool's --coverage flag."""
    out: dict = {"actions": {}, "tactics_covered": set(), "techniques_covered": set()}
    for action, mappings in ACTION_TO_MITRE.items():
        out["actions"][action] = [
            {"technique": m.technique, "name": m.technique_name,
             "tactic": m.tactic, "tactic_id": m.tactic_id}
            for m in mappings
        ]
        for m in mappings:
            out["tactics_covered"].add(m.tactic)
            out["techniques_covered"].add(m.technique)
    out["tactics_covered"] = sorted(out["tactics_covered"])
    out["techniques_covered"] = sorted(out["techniques_covered"])
    return out
