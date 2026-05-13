"""Tests for the TAXII 2.1 publisher.

Two layers:
  1. Auth-header + URL composition (offline, no HTTP)
  2. Round-trip against a stub HTTP server (real httpx, real socket)
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from plenith.connectors import stix, taxii


# ---------------------------------------------------------------------------
# Auth-header / URL composition
# ---------------------------------------------------------------------------

class TestClientWiring:
    def test_bearer_auth_header(self):
        c = taxii.TAXII21Client(base_url="https://x.example/", api_root="api2",
                                  collection_id="abc", bearer_token="TOKEN")
        h = c._auth_header()
        assert h["Authorization"] == "Bearer TOKEN"
        assert h["Accept"].startswith("application/taxii+json")

    def test_basic_auth_header(self):
        c = taxii.TAXII21Client(base_url="https://x.example/",
                                  basic_auth=("user", "pass"))
        h = c._auth_header()
        # base64("user:pass") = "dXNlcjpwYXNz"
        assert h["Authorization"] == "Basic dXNlcjpwYXNz"

    def test_no_auth_no_authorization(self):
        c = taxii.TAXII21Client(base_url="https://x.example/")
        assert "Authorization" not in c._auth_header()

    def test_urls(self):
        c = taxii.TAXII21Client(base_url="https://x.example/",
                                  api_root="services",
                                  collection_id="abc-123")
        assert c._discovery_url()    == "https://x.example/taxii2/"
        assert c._collections_url()  == "https://x.example/services/collections/"
        assert c._objects_url()      == "https://x.example/services/collections/abc-123/objects/"


# ---------------------------------------------------------------------------
# Stub TAXII server fixture
# ---------------------------------------------------------------------------

class _StubTAXII(BaseHTTPRequestHandler):
    posted: list = []
    return_code: int = 202
    return_body: dict = {"id": "envelope-1", "status": "pending"}

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/taxii2/":
            self._json(200, {"title": "stub", "default": "/api2/"})
        elif self.path == "/api2/collections/":
            self._json(200, {"collections": [
                {"id": "abc", "title": "Decoy IoCs"},
            ]})
        else:
            self.send_error(404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8") if length else ""
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            payload = None
        _StubTAXII.posted.append({
            "path":    self.path,
            "headers": dict(self.headers),
            "payload": payload,
        })
        self._json(_StubTAXII.return_code, _StubTAXII.return_body)

    def _json(self, code, body):
        data = json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/taxii+json;version=2.1")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture
def stub_taxii():
    _StubTAXII.posted = []
    _StubTAXII.return_code = 202
    _StubTAXII.return_body = {"id": "env-stub", "status": "pending"}
    server = ThreadingHTTPServer(("127.0.0.1", 0), _StubTAXII)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


# ---------------------------------------------------------------------------
# Live round-trip tests
# ---------------------------------------------------------------------------

class TestDiscovery:
    @pytest.mark.asyncio
    async def test_discover_ok(self, stub_taxii):
        c = taxii.TAXII21Client(base_url=stub_taxii, api_root="api2",
                                  collection_id="abc")
        r = await c.discover()
        assert r["status"] == taxii.TAXIIStatus.OK
        assert "server" in r

    @pytest.mark.asyncio
    async def test_list_collections(self, stub_taxii):
        c = taxii.TAXII21Client(base_url=stub_taxii, api_root="api2",
                                  collection_id="abc")
        r = await c.list_collections()
        assert r["status"] == taxii.TAXIIStatus.OK
        assert r["collections"][0]["id"] == "abc"


class TestPublish:
    @pytest.mark.asyncio
    async def test_publish_envelope_shape(self, stub_taxii):
        c = taxii.TAXII21Client(base_url=stub_taxii, api_root="api2",
                                  collection_id="abc",
                                  bearer_token="t")
        bundle = stix.bundle_from_engagements([{
            "engagement_id": "x", "source_ip": "10.0.0.1",
            "observed": {}, "actions_taken": [],
        }])
        r = await c.publish(bundle)
        assert r["status"] in (taxii.TAXIIStatus.PENDING, taxii.TAXIIStatus.OK)
        # The server saw a TAXII envelope (objects[], NOT bare bundle)
        req = _StubTAXII.posted[-1]
        assert "objects" in req["payload"]
        # Auth header propagated
        assert req["headers"]["Authorization"] == "Bearer t"

    @pytest.mark.asyncio
    async def test_publish_rejects_when_no_collection(self, stub_taxii):
        c = taxii.TAXII21Client(base_url=stub_taxii, api_root="api2",
                                  collection_id="")
        r = await c.publish({"objects": []})
        assert r["status"] == taxii.TAXIIStatus.REJECTED

    @pytest.mark.asyncio
    async def test_publish_handles_auth_failure(self, stub_taxii):
        _StubTAXII.return_code = 401
        _StubTAXII.return_body = {"error": "denied"}
        c = taxii.TAXII21Client(base_url=stub_taxii, api_root="api2",
                                  collection_id="abc")
        r = await c.publish({"objects": []})
        assert r["status"] == taxii.TAXIIStatus.AUTH_FAILED

    @pytest.mark.asyncio
    async def test_publish_handles_server_error(self, stub_taxii):
        _StubTAXII.return_code = 502
        c = taxii.TAXII21Client(base_url=stub_taxii, api_root="api2",
                                  collection_id="abc")
        r = await c.publish({"objects": []})
        assert r["status"] == taxii.TAXIIStatus.SERVER_ERROR


class TestPublishEngagements:
    @pytest.mark.asyncio
    async def test_helper_builds_and_publishes(self, stub_taxii):
        c = taxii.TAXII21Client(base_url=stub_taxii, api_root="api2",
                                  collection_id="abc")
        engagements = [
            {"engagement_id": "abc", "source_ip": "203.0.113.5",
             "observed": {"dns_exfil_commands": ["curl x.oast.live"]},
             "actions_taken": [{"action": "alert_dns_exfil"}]},
        ]
        r = await taxii.publish_engagements(c, engagements)
        assert r["status"] in (taxii.TAXIIStatus.OK, taxii.TAXIIStatus.PENDING)
        assert r["bundle_object_count"] >= 2   # identity + indicator(s)


# ---------------------------------------------------------------------------
# FanOut
# ---------------------------------------------------------------------------

class TestFanOut:
    @pytest.mark.asyncio
    async def test_publishes_to_every_server(self, stub_taxii):
        c1 = taxii.TAXII21Client(base_url=stub_taxii, api_root="api2",
                                   collection_id="abc")
        c2 = taxii.TAXII21Client(base_url=stub_taxii, api_root="api2",
                                   collection_id="abc")
        fan = taxii.TAXIIFanOut(clients=[c1, c2])
        results = await fan.publish_engagements([{
            "engagement_id": "e", "source_ip": "1.1.1.1",
            "observed": {}, "actions_taken": [],
        }])
        assert len(results) == 2
        for r in results:
            assert r["status"] in (taxii.TAXIIStatus.OK, taxii.TAXIIStatus.PENDING)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

class TestFactory:
    def test_empty_config_returns_empty(self):
        assert taxii.build_clients_from_config(None) == []
        assert taxii.build_clients_from_config({}) == []
        assert taxii.build_clients_from_config({"taxii": {}}) == []

    def test_two_servers_build_two_clients(self):
        cfg = {
            "taxii": {
                "servers": [
                    {"base_url": "https://misp.example/",
                     "api_root": "api2", "collection_id": "a",
                     "bearer_token": "t1"},
                    {"base_url": "https://taxii.fs-isac.org/",
                     "api_root": "services", "collection_id": "b",
                     "basic_auth": ["u", "p"]},
                ],
            },
        }
        clients = taxii.build_clients_from_config(cfg)
        assert len(clients) == 2
        assert clients[0].bearer_token == "t1"
        assert clients[1].basic_auth == ("u", "p")

    def test_missing_required_field_skips(self):
        cfg = {"taxii": {"servers": [
            {"api_root": "api2"},   # no base_url
        ]}}
        assert taxii.build_clients_from_config(cfg) == []
