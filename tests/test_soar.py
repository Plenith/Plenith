"""Tests for the SOAR connector ecosystem (XSOAR + Splunk SOAR + playbook hints)."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from plenith.connectors import mitre, soar


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


# ---------------------------------------------------------------------------
# XSOAR payload shape
# ---------------------------------------------------------------------------

class TestCortexXSOARPayload:
    def test_severity_mapping_high(self, alert):
        c = soar.CortexXSOARClient(base_url="http://x", api_key="k", api_key_id="id")
        p = c._payload(alert)
        assert p["severity"] == 3   # high → 3

    def test_severity_mapping_critical(self):
        c = soar.CortexXSOARClient(base_url="http://x", api_key="k", api_key_id="id")
        p = c._payload({"action": "alert_revshell", "severity": "critical"})
        assert p["severity"] == 4

    def test_severity_mapping_info(self):
        c = soar.CortexXSOARClient(base_url="http://x", api_key="k", api_key_id="id")
        p = c._payload({"action": "x", "severity": "info"})
        assert p["severity"] == 1

    def test_incident_type_is_custom(self, alert):
        c = soar.CortexXSOARClient(base_url="http://x", api_key="k", api_key_id="id",
                                     incident_type="MyType")
        p = c._payload(alert)
        assert p["type"] == "MyType"

    def test_labels_include_mitre(self, alert):
        c = soar.CortexXSOARClient(base_url="http://x", api_key="k", api_key_id="id")
        p = c._payload(alert)
        labels = {l["type"]: l["value"] for l in p["labels"]}
        assert "PLENITH-Action".replace("-", "-") in labels or \
               "Plenith-Action" in labels
        assert any("Technique" in t for t in labels)

    def test_raw_json_preserves_alert(self, alert):
        c = soar.CortexXSOARClient(base_url="http://x", api_key="k", api_key_id="id")
        p = c._payload(alert)
        raw = json.loads(p["rawJSON"])
        assert raw["action"] == "alert_credential_exfil"


# ---------------------------------------------------------------------------
# Splunk SOAR payload shape
# ---------------------------------------------------------------------------

class TestSplunkSOARPayload:
    def test_severity_collapse_to_3_bucket(self):
        c = soar.SplunkSOARClient(base_url="http://x", auth_token="t")
        assert c._container_payload({"action": "x", "severity": "critical"})["severity"] == "high"
        assert c._container_payload({"action": "x", "severity": "info"})["severity"] == "low"

    def test_dedup_via_sdi(self, alert):
        c = soar.SplunkSOARClient(base_url="http://x", auth_token="t")
        p = c._container_payload(alert)
        # SDI must be deterministic per (engagement, action) for dedup
        assert "7b6c-abc1" in p["source_data_identifier"]
        assert "alert_credential_exfil" in p["source_data_identifier"]

    def test_artifacts_extracted_from_alert(self, alert):
        c = soar.SplunkSOARClient(base_url="http://x", auth_token="t")
        arts = c._artifact_payloads(alert)
        # Should have at least: Source IP, Claimed User, Trigger Command
        assert len(arts) >= 3
        labels = [a["label"] for a in arts]
        assert "src_ip" in labels
        assert "user"   in labels
        assert "command" in labels


# ---------------------------------------------------------------------------
# Playbook hint registry
# ---------------------------------------------------------------------------

class TestPlaybookHints:
    def test_every_critical_action_has_a_playbook(self):
        for action in ("alert_credential_exfil", "alert_ssh_persistence",
                        "alert_reverse_shell", "alert_dns_exfil",
                        "alert_attacker_llm_detected", "alert_lateral_decoy"):
            hints = soar.hints_for(action)
            assert hints, f"missing playbook for {action!r}"

    def test_playbook_steps_use_known_primitives(self):
        valid = {"enrich", "contain", "notify", "hunt", "document"}
        for hint in soar.all_hints():
            for step in hint.steps:
                assert step.primitive in valid, \
                    f"unknown primitive {step.primitive!r}"

    def test_playbook_has_mitre_links(self):
        for hint in soar.all_hints():
            # Counter-AI uses a vendor extension; others should have ATT&CK ids
            for t in hint.mitre_techniques:
                assert t.startswith("T") or t.startswith("MC-"), \
                    f"weird technique id {t!r}"

    def test_critical_actions_have_high_threshold(self):
        for action in ("alert_ssh_persistence", "alert_reverse_shell"):
            hints = soar.hints_for(action)
            for h in hints:
                assert h.severity_threshold == "critical"

    def test_xsoar_export_has_tasks(self):
        hint = soar.hints_for("alert_credential_exfil")[0]
        playbook = soar.export_xsoar_playbook(hint)
        assert playbook["id"].startswith("plenith-")
        assert playbook["tasks"]
        assert len(playbook["tasks"]) == len(hint.steps)

    def test_splunk_soar_export_has_phases(self):
        hint = soar.hints_for("alert_credential_exfil")[0]
        playbook = soar.export_splunk_soar_playbook(hint)
        assert "Plenith" in playbook["name"]
        assert playbook["phases"]
        assert len(playbook["phases"]) == len(hint.steps)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

class TestSOARFactory:
    def test_no_config_returns_empty(self):
        assert soar.build_from_config(None) == []
        assert soar.build_from_config({}) == []
        assert soar.build_from_config({"soar": {}}) == []

    def test_xsoar_only(self):
        out = soar.build_from_config({"soar": {
            "xsoar": {"base_url": "https://xsoar.x",
                       "api_key": "k", "api_key_id": "id"},
        }})
        assert len(out) == 1
        assert isinstance(out[0], soar.CortexXSOARClient)

    def test_both_configured(self):
        out = soar.build_from_config({"soar": {
            "xsoar":       {"base_url": "https://x", "api_key": "k", "api_key_id": "id"},
            "splunk_soar": {"base_url": "https://y", "auth_token": "t"},
        }})
        assert len(out) == 2


# ---------------------------------------------------------------------------
# Live POST (stub server)
# ---------------------------------------------------------------------------

class _StubSOAR(BaseHTTPRequestHandler):
    posted: list = []
    return_body_xsoar: dict = {"id": 1, "name": "stub-incident"}
    return_body_soar:  dict = {"id": 42}

    def log_message(self, *a):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8") if length else ""
        _StubSOAR.posted.append({
            "path":    self.path,
            "headers": dict(self.headers),
            "body":    body,
        })
        if "/incident" in self.path:
            payload = _StubSOAR.return_body_xsoar
        else:
            payload = _StubSOAR.return_body_soar
        data = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture
def stub_soar():
    _StubSOAR.posted = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _StubSOAR)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


class TestLiveEmit:
    @pytest.mark.asyncio
    async def test_xsoar_emit_posts_incident(self, alert, stub_soar):
        c = soar.CortexXSOARClient(base_url=stub_soar, api_key="k", api_key_id="id")
        await c.emit(alert)
        assert len(_StubSOAR.posted) == 1
        req = _StubSOAR.posted[0]
        assert req["path"] == "/incident"
        assert req["headers"]["X-API-Key"] == "k"
        # rawJSON preserved
        body = json.loads(req["body"])
        assert "rawJSON" in body

    @pytest.mark.asyncio
    async def test_splunk_soar_emit_posts_container_then_artifacts(self, alert, stub_soar):
        c = soar.SplunkSOARClient(base_url=stub_soar, auth_token="t")
        await c.emit(alert)
        # Container + at least 1 artifact
        assert len(_StubSOAR.posted) >= 2
        # First is the container
        assert _StubSOAR.posted[0]["path"].endswith("/rest/container")
        # Rest are artifacts
        for art in _StubSOAR.posted[1:]:
            assert art["path"].endswith("/rest/artifact")
