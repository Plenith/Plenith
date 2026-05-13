"""Evidence harvester — pulls real data from Plenith state for each
control-evidence type in `controls.py`.

The harvester is deliberately defensive: every state source is optional.
Missing data shows up as "no evidence collected" rather than crashing
the report. Auditors prefer "we couldn't measure it this period" over
fabricated data.
"""
from __future__ import annotations

import json
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class EvidenceReport:
    """Bundle of every evidence type for a reporting period."""
    period_start_ts: float
    period_end_ts:   float
    engagement_count: int = 0
    alerts_by_severity: Dict[str, int] = field(default_factory=dict)
    alerts_by_action:   Dict[str, int] = field(default_factory=dict)
    mitre_techniques:   List[str] = field(default_factory=list)
    mitre_tactics:      List[str] = field(default_factory=list)
    ioc_exports:        int = 0
    rotation_epochs:    List[str] = field(default_factory=list)
    mfa_decisions:      Dict[str, int] = field(default_factory=dict)
    isolation_probe_runs: int = 0
    siem_connectors:    List[str] = field(default_factory=list)
    policy_engine:      str = "unknown"
    ot_probes:          int = 0
    counter_ai_detections: int = 0
    counter_ai_proven_via_trap: int = 0


def collect(
    *,
    state_dir: Optional[Path] = None,
    logs_dir: Optional[Path] = None,
    mfa_dir: Optional[Path] = None,
    rotation_dir: Optional[Path] = None,
    config: Optional[Dict[str, Any]] = None,
    period_days: int = 90,
) -> EvidenceReport:
    """Walk every available state source and produce an `EvidenceReport`.

    Period is the trailing N days; events older than that are excluded.
    Defaults to 90 days (standard SOC 2 audit window).
    """
    now = time.time()
    rep = EvidenceReport(
        period_start_ts=now - period_days * 86400,
        period_end_ts=now,
    )

    # --- Engagement state ---
    if state_dir and state_dir.exists():
        for f in state_dir.glob("*.json"):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            last_seen = float(data.get("last_seen_at", 0))
            if last_seen < rep.period_start_ts:
                continue
            rep.engagement_count += 1
            obs = data.get("observed", {})
            if obs.get("attacker_likely_llm"):
                rep.counter_ai_detections += 1
            if obs.get("attacker_llm_proven_via_trap"):
                rep.counter_ai_proven_via_trap += 1

    # --- Logs (per-host JSONL aggregates) ---
    if logs_dir and logs_dir.exists():
        # Walk per-host subdirs
        for sub in logs_dir.iterdir():
            target = sub if sub.is_dir() else logs_dir
            for log_file in target.glob("*.json"):
                try:
                    data = json.loads(log_file.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                mtime = log_file.stat().st_mtime
                if mtime < rep.period_start_ts:
                    continue
                for a in data.get("actions_taken", []) or []:
                    sev = a.get("severity", "info")
                    act = a.get("action", "unknown")
                    rep.alerts_by_severity[sev] = rep.alerts_by_severity.get(sev, 0) + 1
                    rep.alerts_by_action[act] = rep.alerts_by_action.get(act, 0) + 1
            if not sub.is_dir():
                break   # avoid re-walking logs_dir itself

    # --- MITRE coverage from the mapping table (static, but a fact) ---
    from .. import connectors
    try:
        cov = connectors.mitre.coverage_report()
        rep.mitre_techniques = list(cov["techniques_covered"])
        rep.mitre_tactics    = list(cov["tactics_covered"])
    except Exception:
        pass

    # --- MFA decisions ---
    if mfa_dir and mfa_dir.exists():
        passes = list(mfa_dir.glob("*.pass"))
        fails  = list(mfa_dir.glob("*.fail"))
        rep.mfa_decisions = {"pass": len(passes), "fail": len(fails)}

    # --- Rotation epochs ---
    if rotation_dir and rotation_dir.exists():
        for sub in rotation_dir.iterdir():
            manifest = sub / "manifest.json"
            if manifest.exists():
                try:
                    m = json.loads(manifest.read_text(encoding="utf-8"))
                    if m.get("enabled"):
                        rep.rotation_epochs.append(
                            f"{m.get('deployment_id', '?')}/{m.get('epoch', '?')}",
                        )
                except (OSError, json.JSONDecodeError):
                    continue

    # --- Connectors configured (from config) ---
    if config:
        block = config.get("connectors") or {}
        for k in ("splunk_hec", "elastic_bulk", "syslog_udp",
                  "syslog_tcp", "webhook"):
            v = block.get(k) or {}
            if (v.get("url") or v.get("host")):
                rep.siem_connectors.append(k)
        chat = config.get("chatops") or {}
        for k in ("slack", "teams", "pagerduty"):
            v = chat.get(k) or {}
            if v.get("url") or v.get("routing_key"):
                rep.siem_connectors.append(f"chatops:{k}")
        pol = (config.get("policy") or {}).get("engine", "heuristic")
        rep.policy_engine = pol

    # --- Isolation probe history (count of completed validate.sh runs) ---
    # Best effort — we look for the JSONL log the dashboard writes.
    if logs_dir and logs_dir.exists():
        probe_log = logs_dir.parent / "isolation_probes.jsonl"
        if probe_log.exists():
            try:
                rep.isolation_probe_runs = sum(
                    1 for _ in probe_log.read_text(encoding="utf-8").splitlines()
                )
            except OSError:
                pass

    # --- OT probes (IoC JSONL count) ---
    if logs_dir and logs_dir.exists():
        ot_log = logs_dir.parent / "ot_iocs.jsonl"
        if ot_log.exists():
            try:
                rep.ot_probes = sum(
                    1 for _ in ot_log.read_text(encoding="utf-8").splitlines()
                )
            except OSError:
                pass

    return rep


def evidence_value(rep: EvidenceReport, evidence_type: str) -> Any:
    """Pull the value for one evidence type out of the bundle.
    Returns None when unknown — the report renderer treats that as
    "no evidence collected"."""
    from . import controls as ctrl_mod
    mapping = {
        ctrl_mod.EVIDENCE_ENGAGEMENT_COUNT:   rep.engagement_count,
        ctrl_mod.EVIDENCE_ALERTS_BY_SEVERITY: rep.alerts_by_severity,
        ctrl_mod.EVIDENCE_ALERTS_BY_ACTION:   rep.alerts_by_action,
        ctrl_mod.EVIDENCE_MITRE_COVERAGE:     {
            "techniques": rep.mitre_techniques,
            "tactics":    rep.mitre_tactics,
        },
        ctrl_mod.EVIDENCE_IOC_EXPORT_COUNT:   rep.ioc_exports,
        ctrl_mod.EVIDENCE_ROTATION_HISTORY:   rep.rotation_epochs,
        ctrl_mod.EVIDENCE_MFA_DECISIONS:      rep.mfa_decisions,
        ctrl_mod.EVIDENCE_ISOLATION_PROBES:   rep.isolation_probe_runs,
        ctrl_mod.EVIDENCE_CONNECTORS:         rep.siem_connectors,
        ctrl_mod.EVIDENCE_POLICY_ENGINE:      rep.policy_engine,
        ctrl_mod.EVIDENCE_OT_PROBES:          rep.ot_probes,
        ctrl_mod.EVIDENCE_COUNTER_AI:         {
            "detections":      rep.counter_ai_detections,
            "proven_via_trap": rep.counter_ai_proven_via_trap,
        },
    }
    return mapping.get(evidence_type)
