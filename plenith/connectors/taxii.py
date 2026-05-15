"""TAXII 2.1 client — auto-publish STIX bundles into the TI ecosystem.

We already produce STIX 2.1 bundles (`plenith.connectors.stix`).
TAXII 2.1 is the standard transport: TI platforms like MISP, OpenCTI,
FreeTAXII, Anomali ThreatStream, EclecticIQ, and ISAC-operated servers
all expose TAXII-compliant collection endpoints.

This module ships a small async client + factory so a Plenith
deployment can `--publish` an engagement's IoCs into:
  - Its own org's MISP / OpenCTI for analyst review
  - A sector ISAC (FS-ISAC, H-ISAC, MS-ISAC) for community sharing
  - Anomali / EclecticIQ TI Hub for downstream enrichment

Spec: https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html

API surface this client uses:
    GET   /taxii2/                                 — Discovery
    GET   /{api_root}/collections/                 — List collections
    POST  /{api_root}/collections/{id}/objects/    — Publish bundle

Auth options:
    Basic (user / pass)
    Bearer (API token)
    Anonymous (open collections, e.g. AlienVault OTX-style)
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
from dataclasses import dataclass, field
from typing import Any
from collections.abc import Iterable

import httpx

from . import stix as stix_mod

log = logging.getLogger("plenith.connectors.taxii")

# ---------------------------------------------------------------------------
# Status enum we surface to callers
# ---------------------------------------------------------------------------

class TAXIIStatus:
    OK              = "ok"
    PENDING         = "pending"        # 202 — server accepted, processing async
    UNREACHABLE     = "unreachable"
    AUTH_FAILED     = "auth_failed"
    NOT_FOUND       = "not_found"      # collection doesn't exist
    REJECTED        = "rejected"       # 4xx that isn't 401/404
    SERVER_ERROR    = "server_error"   # 5xx

# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

@dataclass
class TAXII21Client:
    """TAXII 2.1 publisher. One client = one configured server.

    Required:
        base_url     — root of the server, e.g. https://misp.example.com
        api_root     — relative path under base, e.g. "api2"
        collection_id — UUID-ish identifier the server told you on discovery

    Auth (pick ONE):
        bearer_token — API token (most TI platforms)
        basic_auth   — (username, password) tuple
        Neither: anonymous
    """
    base_url:      str
    api_root:      str            = "api2"
    collection_id: str            = ""
    bearer_token:  str | None  = None
    basic_auth:    tuple | None = None
    verify_tls:    bool           = True
    timeout_seconds: float        = 15.0
    user_agent:    str            = "Plenith-TAXII/1.0"

    # --- HTTP plumbing -------------------------------------------------

    def _auth_header(self) -> dict[str, str]:
        h = {
            "Accept":     "application/taxii+json;version=2.1",
            "User-Agent": self.user_agent,
        }
        if self.bearer_token:
            h["Authorization"] = f"Bearer {self.bearer_token}"
        elif self.basic_auth:
            user, password = self.basic_auth
            tok = base64.b64encode(f"{user}:{password}".encode()).decode("ascii")
            h["Authorization"] = f"Basic {tok}"
        return h

    def _content_header(self) -> dict[str, str]:
        h = self._auth_header()
        h["Content-Type"] = "application/taxii+json;version=2.1"
        return h

    def _discovery_url(self) -> str:
        return self.base_url.rstrip("/") + "/taxii2/"

    def _collections_url(self) -> str:
        return f"{self.base_url.rstrip('/')}/{self.api_root}/collections/"

    def _objects_url(self) -> str:
        return (
            f"{self.base_url.rstrip('/')}/{self.api_root}"
            f"/collections/{self.collection_id}/objects/"
        )

    # --- public methods ------------------------------------------------

    async def discover(self) -> dict[str, Any]:
        """Hit `/taxii2/` to confirm we're talking to a real server."""
        try:
            async with httpx.AsyncClient(verify=self.verify_tls,
                                          timeout=self.timeout_seconds) as c:
                r = await c.get(self._discovery_url(), headers=self._auth_header())
                if r.status_code == 401:
                    return {"status": TAXIIStatus.AUTH_FAILED}
                if r.status_code >= 500:
                    return {"status": TAXIIStatus.SERVER_ERROR}
                r.raise_for_status()
                return {"status": TAXIIStatus.OK, "server": r.json()}
        except (httpx.HTTPError, OSError) as e:
            log.warning("TAXII discover failed: %s", e)
            return {"status": TAXIIStatus.UNREACHABLE, "error": str(e)}

    async def list_collections(self) -> dict[str, Any]:
        """Return the server's available collections — useful at config
        time so an operator can pick which one to push into."""
        try:
            async with httpx.AsyncClient(verify=self.verify_tls,
                                          timeout=self.timeout_seconds) as c:
                r = await c.get(self._collections_url(),
                                headers=self._auth_header())
                if r.status_code == 401:
                    return {"status": TAXIIStatus.AUTH_FAILED}
                if r.status_code == 404:
                    return {"status": TAXIIStatus.NOT_FOUND}
                if r.status_code >= 500:
                    return {"status": TAXIIStatus.SERVER_ERROR}
                r.raise_for_status()
                return {"status": TAXIIStatus.OK,
                        "collections": r.json().get("collections", [])}
        except (httpx.HTTPError, OSError) as e:
            log.warning("TAXII list_collections failed: %s", e)
            return {"status": TAXIIStatus.UNREACHABLE, "error": str(e)}

    async def publish(self, bundle: dict[str, Any]) -> dict[str, Any]:
        """POST a STIX 2.1 bundle to the configured collection.

        Returns a dict with `status` (one of TAXIIStatus.*), plus
        `status_url` (TAXII envelope-status resource) and `id` (the
        envelope id) on success — the TI platform processes async.
        """
        if not self.collection_id:
            return {"status": TAXIIStatus.REJECTED,
                    "error": "no collection_id configured"}
        # TAXII 2.1 expects an `envelope` shape, NOT a bare bundle:
        #   { "objects": [ ...stix objects... ] }
        envelope = {"objects": bundle.get("objects", [])}
        try:
            async with httpx.AsyncClient(verify=self.verify_tls,
                                          timeout=self.timeout_seconds) as c:
                r = await c.post(
                    self._objects_url(),
                    headers=self._content_header(),
                    json=envelope,
                )
                if r.status_code in (200, 201, 202):
                    body = {}
                    try:
                        body = r.json()
                    except (ValueError, json.JSONDecodeError):
                        pass
                    return {
                        "status":      TAXIIStatus.OK if r.status_code != 202 else TAXIIStatus.PENDING,
                        "http_status": r.status_code,
                        "status_url":  body.get("status"),
                        "id":          body.get("id"),
                        "objects":     len(envelope["objects"]),
                    }
                if r.status_code == 401:
                    return {"status": TAXIIStatus.AUTH_FAILED}
                if r.status_code == 404:
                    return {"status": TAXIIStatus.NOT_FOUND}
                if r.status_code >= 500:
                    return {"status": TAXIIStatus.SERVER_ERROR,
                            "http_status": r.status_code}
                return {"status": TAXIIStatus.REJECTED,
                        "http_status": r.status_code,
                        "body": r.text[:500]}
        except (httpx.HTTPError, OSError) as e:
            log.warning("TAXII publish failed: %s", e)
            return {"status": TAXIIStatus.UNREACHABLE, "error": str(e)}

# ---------------------------------------------------------------------------
# Convenience: build + publish from engagement state in one call
# ---------------------------------------------------------------------------

async def publish_engagements(
    client: TAXII21Client,
    engagements: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    """Render the engagement list as a STIX bundle and publish it.
    Returns the publish-side response augmented with the bundle size.
    """
    bundle = stix_mod.bundle_from_engagements(engagements)
    result = await client.publish(bundle)
    result["bundle_id"] = bundle.get("id")
    result["bundle_object_count"] = len(bundle.get("objects", []))
    return result

# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

@dataclass
class TAXIIServerConfig:
    """One server entry from `config.taxii.servers[]`. We support
    multiple servers per deployment (e.g. internal MISP + external ISAC)
    so a fan-out publishes to both."""
    name:          str
    base_url:      str
    api_root:      str = "api2"
    collection_id: str = ""
    bearer_token:  str | None  = None
    basic_auth:    tuple | None = None
    verify_tls:    bool           = True

def build_clients_from_config(cfg: dict[str, Any] | None) -> list[TAXII21Client]:
    """Build one TAXII21Client per configured server. Schema:

        taxii:
          servers:
            - name: corp-misp
              base_url: https://misp.example.com
              api_root: api2
              collection_id: 0123-abcd-...
              bearer_token: ...
            - name: fs-isac
              base_url: https://taxii.fs-isac.org
              api_root: services
              collection_id: 7890-...
              basic_auth: [username, password]
    """
    if not cfg:
        return []
    block = cfg.get("taxii") if isinstance(cfg, dict) else None
    if not block:
        return []
    out: list[TAXII21Client] = []
    for entry in block.get("servers") or []:
        try:
            out.append(TAXII21Client(
                base_url=entry["base_url"],
                api_root=entry.get("api_root", "api2"),
                collection_id=entry.get("collection_id", ""),
                bearer_token=entry.get("bearer_token"),
                basic_auth=tuple(entry["basic_auth"]) if entry.get("basic_auth") else None,
                verify_tls=bool(entry.get("verify_tls", True)),
            ))
        except KeyError:
            log.warning("TAXII server entry missing required field: %s", entry)
            continue
    return out

# ---------------------------------------------------------------------------
# Fan-out: publish to every configured server
# ---------------------------------------------------------------------------

@dataclass
class TAXIIFanOut:
    """Parallel fan-out to every configured TAXII server. Failures are
    per-server, not global — a flaky ISAC doesn't stop the org-internal
    MISP publish."""
    clients: list[TAXII21Client] = field(default_factory=list)

    async def publish(self, bundle: dict[str, Any]) -> list[dict[str, Any]]:
        if not self.clients:
            return []
        results = await asyncio.gather(
            *(c.publish(bundle) for c in self.clients),
            return_exceptions=True,
        )
        out = []
        for c, r in zip(self.clients, results):
            if isinstance(r, Exception):
                out.append({"server": c.base_url, "status": TAXIIStatus.UNREACHABLE,
                            "error": str(r)})
            else:
                out.append({**r, "server": c.base_url})
        return out

    async def publish_engagements(
        self, engagements: Iterable[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        bundle = stix_mod.bundle_from_engagements(engagements)
        results = await self.publish(bundle)
        for r in results:
            r["bundle_object_count"] = len(bundle.get("objects", []))
        return results
