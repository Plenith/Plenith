"""Tests for the push-approval simulator.

Two layers:

  1. Unit — the in-memory state operations (create / approve / deny /
     expire) directly against the push_sim module.
  2. HTTP — spin a local ThreadingHTTPServer on an ephemeral port,
     drive the endpoints via urllib, assert responses.
"""
import json
import sys
import threading
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "linux-fork" / "mfa"))

import push_sim  # noqa: E402

# ---------------------------------------------------------------------------
# Unit
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _reset_state():
    push_sim.reset()
    yield
    push_sim.reset()

class TestPushSimUnit:
    def test_create_then_get(self):
        req = push_sim.create_push("jdoe", "10.0.0.5")
        assert req.username == "jdoe"
        assert req.ip == "10.0.0.5"
        assert req.status == "pending"
        assert len(req.token) > 8

        fetched = push_sim.get_push(req.token)
        assert fetched is not None
        assert fetched.token == req.token

    def test_approve_then_poll(self):
        req = push_sim.create_push("jdoe", "10.0.0.5")
        assert push_sim.approve(req.token) is True
        fetched = push_sim.get_push(req.token)
        assert fetched.status == "approved"

    def test_deny_then_poll(self):
        req = push_sim.create_push("jdoe", "10.0.0.5")
        assert push_sim.deny(req.token) is True
        assert push_sim.get_push(req.token).status == "denied"

    def test_approve_then_deny_rejected(self):
        """Once a request is approved, it stays approved — no flip-flop."""
        req = push_sim.create_push("jdoe", "10.0.0.5")
        push_sim.approve(req.token)
        assert push_sim.deny(req.token) is False
        assert push_sim.get_push(req.token).status == "approved"

    def test_unknown_token_yields_nothing(self):
        assert push_sim.get_push("nonexistent") is None
        assert push_sim.approve("nonexistent") is False
        assert push_sim.deny("nonexistent") is False

    def test_expiry(self):
        req = push_sim.create_push("jdoe", "10.0.0.5", ttl_seconds=0.0)
        # Already expired (ttl=0)
        time.sleep(0.05)
        # to_dict reports the computed status
        d = push_sim.get_push(req.token).to_dict()
        assert d["status"] == "expired"
        # Approve after expiry should fail
        assert push_sim.approve(req.token) is False

    def test_auto_approve_policy(self, monkeypatch):
        """Username in AUTO_APPROVE → status starts as approved."""
        monkeypatch.setattr(push_sim, "AUTO_APPROVE", {"trusted-user"})
        req = push_sim.create_push("trusted-user", "10.0.0.5")
        assert req.status == "approved"

    def test_auto_deny_policy(self, monkeypatch):
        monkeypatch.setattr(push_sim, "AUTO_DENY", {"bad-user"})
        req = push_sim.create_push("bad-user", "10.0.0.5")
        assert req.status == "denied"

    def test_list_pushes(self):
        push_sim.create_push("a", "1.1.1.1")
        push_sim.create_push("b", "2.2.2.2")
        all_ = push_sim.list_pushes()
        assert len(all_) == 2
        usernames = {p["username"] for p in all_}
        assert usernames == {"a", "b"}

# ---------------------------------------------------------------------------
# HTTP — boot a real server on an ephemeral port
# ---------------------------------------------------------------------------

class _HttpFixture:
    def __init__(self):
        from http.server import ThreadingHTTPServer
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), push_sim._Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def post(self, path: str, body: dict | None = None) -> tuple[int, dict]:
        data = json.dumps(body or {}).encode("utf-8")
        req = Request(self.url(path), data=data, method="POST",
                      headers={"Content-Type": "application/json"})
        try:
            with urlopen(req, timeout=2) as resp:
                payload = resp.read()
                return resp.status, json.loads(payload) if payload else {}
        except HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def get(self, path: str) -> tuple[int, dict]:
        try:
            with urlopen(self.url(path), timeout=2) as resp:
                payload = resp.read()
                return resp.status, json.loads(payload) if payload else {}
        except HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def shutdown(self):
        self.server.shutdown()
        self.server.server_close()

@pytest.fixture
def http_server():
    fx = _HttpFixture()
    try:
        yield fx
    finally:
        fx.shutdown()

class TestPushSimHTTP:
    def test_healthz(self, http_server):
        status, body = http_server.get("/healthz")
        assert status == 200
        assert body == {"ok": True}

    def test_create_request(self, http_server):
        status, body = http_server.post("/push/request",
                                         {"username": "jdoe", "ip": "10.0.0.5"})
        assert status == 201
        assert "token" in body
        assert body["status"] == "pending"

    def test_poll_pending(self, http_server):
        _, body = http_server.post("/push/request",
                                    {"username": "jdoe", "ip": "10.0.0.5"})
        token = body["token"]
        status, poll = http_server.get(f"/push/poll/{token}")
        assert status == 200
        assert poll["status"] == "pending"

    def test_full_approve_flow(self, http_server):
        _, body = http_server.post("/push/request",
                                    {"username": "jdoe", "ip": "10.0.0.5"})
        token = body["token"]
        status, _ = http_server.post(f"/push/approve/{token}")
        assert status == 204
        _, poll = http_server.get(f"/push/poll/{token}")
        assert poll["status"] == "approved"

    def test_full_deny_flow(self, http_server):
        _, body = http_server.post("/push/request",
                                    {"username": "jdoe", "ip": "10.0.0.5"})
        token = body["token"]
        status, _ = http_server.post(f"/push/deny/{token}")
        assert status == 204
        _, poll = http_server.get(f"/push/poll/{token}")
        assert poll["status"] == "denied"

    def test_approve_unknown_token_404(self, http_server):
        status, _ = http_server.post("/push/approve/no-such-token")
        assert status == 404

    def test_poll_unknown_token_404(self, http_server):
        status, _ = http_server.get("/push/poll/no-such-token")
        assert status == 404

    def test_list_endpoint(self, http_server):
        http_server.post("/push/request", {"username": "a", "ip": "1.1.1.1"})
        http_server.post("/push/request", {"username": "b", "ip": "2.2.2.2"})
        status, body = http_server.get("/push/list")
        assert status == 200
        assert len(body["pushes"]) == 2

    def test_bad_json(self, http_server):
        # Send malformed JSON
        data = b"not-json"
        req = Request(http_server.url("/push/request"), data=data, method="POST",
                      headers={"Content-Type": "application/json"})
        try:
            with urlopen(req, timeout=2) as resp:
                assert resp.status == 400
        except HTTPError as e:
            assert e.code == 400
