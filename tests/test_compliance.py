"""Tests for the compliance attestation reporter.

Covers:
  - Control table shape: every framework has at least N controls,
    every control has a non-empty title/statement.
  - Evidence harvester: builds an EvidenceReport from a temp dir tree
    and aggregates correctly.
  - Renderer: Markdown / HTML / JSON shape invariants.
  - CLI smoke: every framework selector + every output format.
"""
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from plenith.compliance import controls, evidence, report

_ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Control table shape
# ---------------------------------------------------------------------------

class TestControlTable:
    def test_three_frameworks(self):
        fws = controls.all_frameworks()
        assert set(fws) == {"soc2", "iso27001", "nis2"}

    def test_every_framework_has_controls(self):
        for fw in controls.all_frameworks():
            assert len(controls.controls_for(fw)) >= 5

    def test_every_control_has_required_fields(self):
        for c in controls.all_controls():
            assert c.framework
            assert c.control_id
            assert c.title
            assert c.statement
            assert isinstance(c.evidence, list)

    def test_unknown_framework_returns_empty(self):
        assert controls.controls_for("nonexistent") == []

# ---------------------------------------------------------------------------
# Evidence harvester
# ---------------------------------------------------------------------------

class TestEvidenceHarvester:
    def test_empty_dirs_yield_empty_report(self, tmp_path):
        rep = evidence.collect(
            state_dir=tmp_path / "noexist",
            logs_dir=tmp_path / "noexist",
        )
        assert rep.engagement_count == 0
        assert rep.alerts_by_severity == {}
        assert rep.policy_engine == "unknown"

    def test_aggregates_alerts_from_logs(self, tmp_path):
        # Build a synthetic logs/<host>/<file>.json tree
        host = tmp_path / "logs" / "bastion-prod"
        host.mkdir(parents=True)
        (host / "1.json").write_text(json.dumps({
            "engagement_id": "abc",
            "actions_taken": [
                {"action": "alert_credential_exfil", "severity": "high"},
                {"action": "alert_credential_search", "severity": "medium"},
                {"action": "alert_credential_exfil", "severity": "high"},
            ],
        }), encoding="utf-8")

        rep = evidence.collect(
            state_dir=tmp_path / "noexist",
            logs_dir=tmp_path / "logs",
        )
        assert rep.alerts_by_severity["high"] == 2
        assert rep.alerts_by_severity["medium"] == 1
        assert rep.alerts_by_action["alert_credential_exfil"] == 2

    def test_engagement_count_includes_period_only(self, tmp_path):
        sd = tmp_path / "state"
        sd.mkdir()
        # Two engagements: one recent, one ancient
        recent_ts = time.time()
        old_ts = time.time() - 365 * 86400
        (sd / "recent.json").write_text(json.dumps({
            "engagement_id": "recent",
            "last_seen_at":  recent_ts,
            "observed":      {},
        }), encoding="utf-8")
        (sd / "old.json").write_text(json.dumps({
            "engagement_id": "old",
            "last_seen_at":  old_ts,
            "observed":      {},
        }), encoding="utf-8")
        rep = evidence.collect(state_dir=sd, period_days=90)
        assert rep.engagement_count == 1

    def test_counter_ai_counts(self, tmp_path):
        sd = tmp_path / "state"
        sd.mkdir()
        (sd / "e.json").write_text(json.dumps({
            "engagement_id": "abc",
            "last_seen_at":  time.time(),
            "observed":      {
                "attacker_likely_llm":          True,
                "attacker_llm_proven_via_trap": True,
            },
        }), encoding="utf-8")
        rep = evidence.collect(state_dir=sd)
        assert rep.counter_ai_detections == 1
        assert rep.counter_ai_proven_via_trap == 1

    def test_mfa_decisions_aggregated(self, tmp_path):
        mfa = tmp_path / "mfa"
        mfa.mkdir()
        (mfa / "1.2.3.4.pass").write_text("", encoding="utf-8")
        (mfa / "5.6.7.8.fail").write_text("", encoding="utf-8")
        (mfa / "9.9.9.9.pass").write_text("", encoding="utf-8")
        rep = evidence.collect(mfa_dir=mfa)
        assert rep.mfa_decisions == {"pass": 2, "fail": 1}

    def test_connectors_extracted_from_config(self):
        cfg = {
            "connectors": {
                "splunk_hec":  {"url": "https://splunk.x", "token": "t"},
                "elastic_bulk": {},   # empty → skip
                "syslog_udp":  {"host": "syslog.x"},
            },
            "chatops": {
                "slack":     {"url": "https://hooks.slack.com/..."},
                "pagerduty": {"routing_key": "abcd"},
            },
            "policy":   {"engine": "trained_rl"},
        }
        rep = evidence.collect(config=cfg)
        assert "splunk_hec" in rep.siem_connectors
        assert "syslog_udp" in rep.siem_connectors
        assert "elastic_bulk" not in rep.siem_connectors
        assert "chatops:slack" in rep.siem_connectors
        assert "chatops:pagerduty" in rep.siem_connectors
        assert rep.policy_engine == "trained_rl"

    def test_evidence_value_lookup(self):
        rep = evidence.EvidenceReport(period_start_ts=0, period_end_ts=1)
        rep.engagement_count = 7
        v = evidence.evidence_value(rep, controls.EVIDENCE_ENGAGEMENT_COUNT)
        assert v == 7
        assert evidence.evidence_value(rep, "nonexistent") is None

# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------

@pytest.fixture
def realistic_evidence():
    rep = evidence.EvidenceReport(period_start_ts=time.time() - 86400,
                                   period_end_ts=time.time())
    rep.engagement_count = 8
    rep.alerts_by_severity = {"critical": 2, "high": 7, "medium": 4}
    rep.alerts_by_action   = {"alert_credential_exfil": 3,
                               "alert_dns_exfil": 2}
    rep.mitre_techniques   = ["T1552.001", "T1071.004"]
    rep.mitre_tactics      = ["Credential Access", "Command and Control"]
    rep.mfa_decisions      = {"pass": 12, "fail": 3}
    rep.rotation_epochs    = ["mc-2026/2026Q1", "mc-2026/2026Q2"]
    rep.siem_connectors    = ["splunk_hec", "syslog_udp", "chatops:slack"]
    rep.policy_engine      = "trained_rl"
    rep.counter_ai_detections = 1
    return rep

class TestMarkdownRenderer:
    def test_markdown_contains_all_frameworks(self, realistic_evidence):
        md = report.to_markdown(controls.all_controls(), realistic_evidence)
        assert "## SOC2" in md
        assert "## ISO27001" in md
        assert "## NIS2" in md

    def test_markdown_has_summary_table(self, realistic_evidence):
        md = report.to_markdown(controls.all_controls(), realistic_evidence)
        assert "Reporting period:" in md
        assert "| Framework |" in md

    def test_evidence_present_marker(self, realistic_evidence):
        md = report.to_markdown(controls.all_controls(), realistic_evidence)
        # Several controls have evidence
        assert "EVIDENCE" in md

    def test_no_evidence_marker_on_empty_report(self):
        empty = evidence.EvidenceReport(period_start_ts=0, period_end_ts=1)
        md = report.to_markdown(controls.all_controls(), empty)
        # Most controls should be flagged no-data
        assert "NO DATA" in md

class TestHTMLRenderer:
    def test_html_is_self_contained(self, realistic_evidence):
        h = report.to_html(controls.all_controls(), realistic_evidence)
        assert h.startswith("<!doctype html>")
        assert "<style>" in h
        # No external resources
        assert "src=" not in h
        assert "href=" not in h

    def test_status_classes_present(self, realistic_evidence):
        h = report.to_html(controls.all_controls(), realistic_evidence)
        assert "status-evidence-present" in h or "status-no-evidence-this-period" in h

class TestJSONRenderer:
    def test_json_parses_and_has_expected_shape(self, realistic_evidence):
        j = report.to_json(controls.all_controls(), realistic_evidence)
        parsed = json.loads(j)
        assert "title" in parsed
        assert "period" in parsed
        assert "controls" in parsed
        assert "evidence_report" in parsed
        # Every control entry has status + evidence
        for c in parsed["controls"]:
            assert c["status"] in (
                "evidence-present", "no-evidence-this-period", "out-of-band",
            )
            assert "evidence" in c

# ---------------------------------------------------------------------------
# CLI smoke
# ---------------------------------------------------------------------------

class TestComplianceCLI:
    def _run(self, *args, cwd=_ROOT):
        cmd = [sys.executable, str(_ROOT / "tools" / "compliance_report.py"), *args]
        return subprocess.run(cmd, capture_output=True, text=True, timeout=30,
                              cwd=cwd, encoding="utf-8")

    def test_default_emits_markdown(self):
        out = self._run("--quiet", "--framework", "soc2")
        assert out.returncode == 0

    def test_json_mode_writes_file(self, tmp_path):
        out_file = tmp_path / "report.json"
        out = self._run("--json", str(out_file), "--quiet")
        assert out.returncode == 0
        assert out_file.exists()
        parsed = json.loads(out_file.read_text(encoding="utf-8"))
        assert "controls" in parsed

    def test_html_mode_writes_file(self, tmp_path):
        out_file = tmp_path / "report.html"
        out = self._run("--html", str(out_file), "--quiet",
                        "--framework", "iso27001")
        assert out.returncode == 0
        assert out_file.exists()
        text = out_file.read_text(encoding="utf-8")
        assert "<html>" in text
