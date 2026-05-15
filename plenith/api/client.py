"""Python SDK for the Plenith REST API.

Thin httpx wrapper. Downstream code (a SOAR custom integration pack,
an org-internal dashboard, a CI gate) imports this instead of crafting
raw HTTP calls.

Example:

    from plenith.api import PlenithClient

    async with PlenithClient("https://plenith.io/", token="...") as mc:
        engagements = await mc.list_engagements(severity="high")
        for e in engagements:
            print(e["engagement_id"], e["severity_max"])

The contract mirrors the FastAPI server's endpoints 1:1 — if the
endpoint exists at /foo, the SDK method is `client.foo(...)`.
"""
from __future__ import annotations

from typing import Any

import httpx

class PlenithClient:
    """Async client for the Plenith REST API.

    Constructor args:
      base_url        — root of the API (https://plenith.io/)
      token           — API bearer token (matches PLENITH_API_TOKENS)
      timeout_seconds — per-request timeout
      verify_tls      — pass False for dev with self-signed certs
    """

    def __init__(self, base_url: str, *,
                 token: str | None = None,
                 timeout_seconds: float = 10.0,
                 verify_tls: bool = True):
        self.base_url        = base_url.rstrip("/")
        self.token           = token
        self.timeout_seconds = timeout_seconds
        self.verify_tls      = verify_tls
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> PlenithClient:
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout_seconds,
            verify=self.verify_tls,
            headers=self._headers(),
        )
        return self

    async def __aexit__(self, *_a) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _headers(self) -> dict[str, str]:
        h = {"Accept": "application/json",
             "User-Agent": "PlenithClient/1.0"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    async def _get(self, path: str, **params) -> Any:
        # Filter out None params so they're not serialized as the string "None"
        clean = {k: v for k, v in params.items() if v is not None}
        client = self._client or httpx.AsyncClient(
            base_url=self.base_url, timeout=self.timeout_seconds,
            verify=self.verify_tls, headers=self._headers(),
        )
        try:
            r = await client.get(path, params=clean)
            r.raise_for_status()
            return r.json()
        finally:
            if self._client is None:
                await client.aclose()

    async def _post(self, path: str, json_body: dict[str, Any] | None = None) -> Any:
        client = self._client or httpx.AsyncClient(
            base_url=self.base_url, timeout=self.timeout_seconds,
            verify=self.verify_tls, headers=self._headers(),
        )
        try:
            r = await client.post(path, json=json_body or {})
            r.raise_for_status()
            return r.json()
        finally:
            if self._client is None:
                await client.aclose()

    # -- status -------------------------------------------------------

    async def health(self) -> dict[str, Any]:
        return await self._get("/health")

    async def ready(self) -> dict[str, Any]:
        return await self._get("/ready")

    async def version(self) -> dict[str, Any]:
        return await self._get("/version")

    async def metrics_text(self) -> str:
        """Return /metrics output as the raw Prometheus exposition string."""
        client = self._client or httpx.AsyncClient(
            base_url=self.base_url, timeout=self.timeout_seconds,
            verify=self.verify_tls, headers=self._headers(),
        )
        try:
            r = await client.get("/metrics")
            r.raise_for_status()
            return r.text
        finally:
            if self._client is None:
                await client.aclose()

    # -- engagements --------------------------------------------------

    async def list_engagements(
        self,
        *,
        user:         str | None = None,
        ip:           str | None = None,
        severity:     str | None = None,
        since_seconds: float | None = None,
        limit:        int = 100,
    ) -> list[dict[str, Any]]:
        body = await self._get(
            "/engagements", user=user, ip=ip, severity=severity,
            since_seconds=since_seconds, limit=limit,
        )
        return body.get("engagements", [])

    async def get_engagement(self, engagement_id: str) -> dict[str, Any]:
        return await self._get(f"/engagements/{engagement_id}")

    async def get_narrative(self, engagement_id: str) -> dict[str, Any]:
        return await self._get(f"/engagements/{engagement_id}/narrative")

    # -- alerts -------------------------------------------------------

    async def list_alerts(
        self,
        *,
        severity:      str | None = None,
        action:        str | None = None,
        engagement_id: str | None = None,
        limit:         int = 200,
    ) -> list[dict[str, Any]]:
        body = await self._get(
            "/alerts", severity=severity, action=action,
            engagement_id=engagement_id, limit=limit,
        )
        return body.get("alerts", [])

    # -- actions ------------------------------------------------------

    async def validate_isolation(self) -> dict[str, Any]:
        return await self._post("/isolation/validate")

    async def write_mfa_decision(self, ip: str, decision: str,
                                   reason: str | None = None) -> dict[str, Any]:
        if decision not in ("pass", "fail"):
            raise ValueError("decision must be 'pass' or 'fail'")
        return await self._post(f"/mfa/decisions/{ip}",
                                  {"decision": decision, "reason": reason})

    async def policy_info(self) -> dict[str, Any]:
        return await self._get("/policy")

    async def content_manifest(self) -> dict[str, Any]:
        return await self._get("/content/manifest")

    # -- schema -------------------------------------------------------

    async def openapi(self) -> dict[str, Any]:
        """Return the auto-generated OpenAPI 3 schema."""
        return await self._get("/openapi.json")
