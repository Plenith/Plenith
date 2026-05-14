"""Tests for `plenith.escalate` — Phase 3 of UI_WIRING.md.

The escalate service is a thin wrapper over the existing chatops
connectors; most of its logic is in `build_alert_from_engagement` (the
shape we hand to a connector's `emit()`).  Tests focus on that shape
since the connectors themselves are tested separately under
test_chatops.
"""
from __future__ import annotations

import asyncio

from plenith.escalate import build_alert_from_engagement, escalate


def _engagement(**kwargs):
    """Build a minimal engagement dict for testing."""
    base = {
        "engagement_id":  "eng-001",
        "claimed_user":   "jdoe",
        "source_ip":      "203.0.113.7",
        "_host":          "bastion-prod",
        "logs":           [],
    }
    base.update(kwargs)
    return base


def test_build_alert_picks_highest_severity_action():
    """Across multiple log files / actions, the headline alert is the
    most severe one — so the chatops message reads 'CRIT reverse_shell'
    not 'INFO sudo_probe'."""
    eng = _engagement(logs=[
        {"actions_taken": [
            {"action": "sudo_probe",     "severity": "info"},
            {"action": "alert_rev_shell", "severity": "critical",
             "rationale": "bash -i revshell"},
            {"action": "alert_cred_exfil", "severity": "high"},
        ]},
    ])
    alert = build_alert_from_engagement(eng, tier="L2", message="ping@oncall")
    assert alert["action"] == "alert_rev_shell"
    assert alert["severity"] == "critical"
    assert "bash -i revshell" in alert["rationale"]
    assert "ping@oncall" in alert["rationale"]


def test_build_alert_uses_synthetic_action_when_no_alerts():
    """Operator escalates on counter-AI confidence alone, before any
    heuristic alert has fired.  Synthesize a sensible-looking alert."""
    eng = _engagement(logs=[])
    alert = build_alert_from_engagement(eng, tier="L2", message="suspicious")
    assert alert["action"] == "engagement_escalation"
    assert alert["severity"] in ("high", "critical")
    assert "L2" in alert["rationale"]


def test_l3_tier_bumps_severity_to_critical():
    """L3 means 'wake the on-call'.  Even a medium-severity engagement
    becomes critical-flavored when escalated to L3."""
    eng = _engagement(logs=[
        {"actions_taken": [{"action": "alert_decoy_swallow", "severity": "medium"}]},
    ])
    l2 = build_alert_from_engagement(eng, tier="L2")
    l3 = build_alert_from_engagement(eng, tier="L3")
    assert l2["severity"] == "medium"
    assert l3["severity"] == "critical"


def test_build_alert_carries_engagement_metadata():
    eng = _engagement(
        engagement_id="2b51584b-...",
        claimed_user="jdoe",
        source_ip="10.0.0.14",
    )
    alert = build_alert_from_engagement(eng, tier="L2")
    assert alert["engagement_id"] == "2b51584b-..."
    assert alert["claimed_user"]  == "jdoe"
    assert alert["source_ip"]     == "10.0.0.14"
    assert alert["hostname"]      == "bastion-prod"


def test_build_alert_carries_mitre_tags_when_present():
    eng = _engagement(logs=[
        {"actions_taken": [{
            "action": "alert_x", "severity": "high",
            "mitre_technique": "T1059.004",
            "mitre_tactic": "execution",
        }]},
    ])
    alert = build_alert_from_engagement(eng)
    assert alert["mitre_technique"] == "T1059.004"
    assert alert["mitre_tactic"]    == "execution"


def test_escalate_with_no_chatops_config_returns_empty_fired_list():
    """No connectors configured → escalate is still callable; returns
    an empty fired-list so the dashboard can show 'no escalation
    channels configured'."""
    result = asyncio.run(escalate(
        _engagement(),
        tier="L2",
        chatops_config={},
    ))
    assert result["tier"] == "L2"
    assert result["connectors_fired"] == []
    assert result["connectors_failed"] == []
    # Operator still gets a preview of what would have been sent
    assert result["alert_preview"]["engagement_id"] == "eng-001"


def test_escalate_returns_correct_tier(tmp_path):
    result_l2 = asyncio.run(escalate(_engagement(), tier="L2",
                                      chatops_config={}))
    result_l3 = asyncio.run(escalate(_engagement(), tier="L3",
                                      chatops_config={}))
    assert result_l2["tier"] == "L2"
    assert result_l3["tier"] == "L3"
