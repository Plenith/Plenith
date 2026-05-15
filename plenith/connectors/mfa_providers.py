"""Real MFA provider clients — Duo, Okta, Authy.

The dev-fabric push-sim is fine for testing, but no SOC is going to
deploy Plenith without "we already use Duo and you must talk to it."
This module ships the SDK-shaped clients the mfa-gateway can swap in.

Every provider implements the same contract:

    async def request_push(username, ip) -> str    # token / async-call-id
    async def poll(token) -> "pending"|"approved"|"denied"|"expired"
    async def verify_totp(username, code) -> bool

The mfa-gateway uses `from_config(cfg)` to pick the right one. The
push-sim is the default provider when nothing is configured, so the dev
fabric Just Works.

PROTOCOL NOTES (production stubs — fill in real auth secrets in deploy):

Duo Auth API v2
    Base:   https://api-XXXXXXXX.duosecurity.com
    /auth/v2/auth                 — POST username, factor=push
    /auth/v2/auth_status?txid=... — GET poll
    HMAC-SHA1 signature in Authorization header (Duo's documented
    canonical request — basically the same shape as AWS Sig V2).

Okta Verify Push (via Factors API)
    Base:   https://{org}.okta.com
    /api/v1/users/{id}/factors/{factorId}/verify   — POST, returns
        a factorResult of CHALLENGE → poll the location header
    Bearer-token auth (Okta API token), or OAuth client_credentials.

Authy / Twilio Verify
    Base:   https://verify.twilio.com/v2
    /Services/{sid}/Verifications  — POST channel=push
    Basic-auth with account SID + auth token.
"""
from __future__ import annotations

import asyncio
import base64
import email.utils
import hashlib
import hmac
import logging
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

log = logging.getLogger("plenith.connectors.mfa")

# ---------------------------------------------------------------------------
# Protocol that every provider satisfies (for type checking + duck typing
# in the gateway).
# ---------------------------------------------------------------------------

class MFAProvider(Protocol):
    name: str
    async def request_push(self, username: str, ip: str) -> str | None: ...
    async def poll(self, token: str) -> str: ...
    async def verify_totp(self, username: str, code: str) -> bool: ...

# ---------------------------------------------------------------------------
# Duo Auth API v2 client
# ---------------------------------------------------------------------------

@dataclass
class DuoAuthClient:
    """Duo Auth API v2 client.

    Auth requires (host, ikey, skey) where:
      host: api-XXXXXXXX.duosecurity.com (your tenant)
      ikey: integration key
      skey: secret key for HMAC signature

    Reference: https://duo.com/docs/authapi
    """
    name: str = "duo"
    host: str = ""
    integration_key: str = ""
    secret_key: str = ""
    timeout_seconds: float = 15.0

    def _sign(self, method: str, path: str, params: dict[str, str]) -> dict[str, str]:
        """Build the canonical-request HMAC the Duo API expects."""
        date = email.utils.formatdate(usegmt=True)
        canon_params = "&".join(
            f"{k}={httpx.QueryParams({k: v})}" for k, v in sorted(params.items())
        )
        # Per Duo's spec: join lines with newline
        canonical = "\n".join([date, method.upper(), self.host.lower(), path, canon_params])
        sig = hmac.new(
            self.secret_key.encode("utf-8"),
            canonical.encode("utf-8"),
            hashlib.sha1,
        ).hexdigest()
        token = base64.b64encode(f"{self.integration_key}:{sig}".encode("ascii")).decode("ascii")
        return {"Date": date, "Authorization": f"Basic {token}"}

    async def _api_call(self, method: str, path: str,
                         params: dict[str, str]) -> dict[str, Any]:
        headers = self._sign(method, path, params)
        url = f"https://{self.host}{path}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as c:
                if method.upper() == "POST":
                    r = await c.post(url, data=params, headers=headers)
                else:
                    r = await c.get(url, params=params, headers=headers)
                r.raise_for_status()
                return r.json().get("response", {})
        except Exception as e:
            log.warning("Duo API call failed: %s %s → %s", method, path, e)
            return {}

    async def request_push(self, username: str, ip: str) -> str | None:
        result = await self._api_call("POST", "/auth/v2/auth", {
            "username": username,
            "factor":   "push",
            "ipaddr":   ip,
            "async":    "1",
            "type":     "Plenith step-up",
            "display_username": username,
        })
        return result.get("txid")

    async def poll(self, token: str) -> str:
        """Duo `auth_status` returns result in {allow, deny, waiting}.
        Map onto our 4-state contract."""
        result = await self._api_call("GET", "/auth/v2/auth_status", {"txid": token})
        r = result.get("result")
        if r == "allow":   return "approved"
        if r == "deny":    return "denied"
        if r == "waiting": return "pending"
        return "expired"

    async def verify_totp(self, username: str, code: str) -> bool:
        result = await self._api_call("POST", "/auth/v2/auth", {
            "username": username,
            "factor":   "passcode",
            "passcode": code,
        })
        return result.get("result") == "allow"

# ---------------------------------------------------------------------------
# Okta Verify Push client
# ---------------------------------------------------------------------------

@dataclass
class OktaVerifyClient:
    """Okta Factors API client.

    Spec: https://developer.okta.com/docs/reference/api/factors/

    Flow:
      1. Resolve user id by login (`GET /api/v1/users/{login}`).
      2. List user's factors, find push.
      3. POST verify → returns factorResult=CHALLENGE + poll URL.
      4. Poll until factorResult=SUCCESS / REJECTED / TIMEOUT.

    Auth: `Authorization: SSWS <token>` for API tokens.
    """
    name: str = "okta"
    org_url: str = ""          # https://example.okta.com
    api_token: str = ""
    timeout_seconds: float = 15.0
    # Per-token state: we cache (factor_id, poll_url) for an in-flight
    # push so subsequent polls don't re-resolve. Keyed by our internal token.
    _state: dict[str, dict[str, str]] = field(default_factory=dict)

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"SSWS {self.api_token}",
            "Content-Type":  "application/json",
            "Accept":        "application/json",
        }

    async def _resolve_user(self, c: httpx.AsyncClient, login: str) -> str | None:
        try:
            r = await c.get(f"{self.org_url}/api/v1/users/{login}",
                            headers=self._headers())
            r.raise_for_status()
            return r.json().get("id")
        except Exception as e:
            log.warning("Okta user resolve failed: %s", e)
            return None

    async def _find_push_factor(self, c: httpx.AsyncClient, user_id: str) -> str | None:
        try:
            r = await c.get(f"{self.org_url}/api/v1/users/{user_id}/factors",
                            headers=self._headers())
            r.raise_for_status()
            for f in r.json():
                if f.get("factorType") == "push":
                    return f.get("id")
        except Exception as e:
            log.warning("Okta factor list failed: %s", e)
        return None

    async def request_push(self, username: str, ip: str) -> str | None:
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as c:
            user_id = await self._resolve_user(c, username)
            if not user_id:
                return None
            factor_id = await self._find_push_factor(c, user_id)
            if not factor_id:
                return None
            try:
                r = await c.post(
                    f"{self.org_url}/api/v1/users/{user_id}/factors/{factor_id}/verify",
                    headers=self._headers(),
                    json={},
                )
                r.raise_for_status()
                body = r.json()
                poll_url = body.get("_links", {}).get("poll", {}).get("href")
                if not poll_url:
                    return None
                # Mint our own token to hand back to the gateway
                token = base64.urlsafe_b64encode(f"{user_id}|{factor_id}".encode()).decode("ascii").rstrip("=")
                self._state[token] = {"poll_url": poll_url}
                return token
            except Exception as e:
                log.warning("Okta push request failed: %s", e)
                return None

    async def poll(self, token: str) -> str:
        st = self._state.get(token)
        if not st:
            return "expired"
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as c:
            try:
                r = await c.get(st["poll_url"], headers=self._headers())
                r.raise_for_status()
                result = r.json().get("factorResult")
                if result == "SUCCESS":   return "approved"
                if result == "REJECTED":  return "denied"
                if result == "TIMEOUT":   return "expired"
                return "pending"
            except Exception as e:
                log.warning("Okta poll failed: %s", e)
                return "expired"

    async def verify_totp(self, username: str, code: str) -> bool:
        """TOTP via Okta — same factor-verify endpoint, factor is `token:software:totp`."""
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as c:
            user_id = await self._resolve_user(c, username)
            if not user_id:
                return False
            # Find the TOTP factor
            try:
                r = await c.get(f"{self.org_url}/api/v1/users/{user_id}/factors",
                                headers=self._headers())
                r.raise_for_status()
                factor_id = next(
                    (f["id"] for f in r.json()
                     if f.get("factorType") == "token:software:totp"),
                    None,
                )
                if not factor_id:
                    return False
                r = await c.post(
                    f"{self.org_url}/api/v1/users/{user_id}/factors/{factor_id}/verify",
                    headers=self._headers(),
                    json={"passCode": code},
                )
                return r.status_code == 200 and r.json().get("factorResult") == "SUCCESS"
            except Exception as e:
                log.warning("Okta TOTP verify failed: %s", e)
                return False

# ---------------------------------------------------------------------------
# Twilio Verify (formerly Authy) push client
# ---------------------------------------------------------------------------

@dataclass
class TwilioVerifyClient:
    """Twilio Verify Push client (the successor to Authy).
    Spec: https://www.twilio.com/docs/verify/quickstarts/push
    """
    name: str = "twilio"
    service_sid: str = ""
    account_sid: str = ""
    auth_token: str = ""
    timeout_seconds: float = 15.0

    @property
    def _auth(self) -> tuple:
        return (self.account_sid, self.auth_token)

    @property
    def _base(self) -> str:
        return "https://verify.twilio.com/v2"

    async def request_push(self, username: str, ip: str) -> str | None:
        url = f"{self._base}/Services/{self.service_sid}/Verifications"
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds, auth=self._auth) as c:
                r = await c.post(url, data={
                    "Channel":  "push",
                    "To":       username,    # entity identity in Twilio
                    "Details":  f"Plenith step-up from {ip}",
                })
                r.raise_for_status()
                return r.json().get("sid")
        except Exception as e:
            log.warning("Twilio Verify push failed: %s", e)
            return None

    async def poll(self, token: str) -> str:
        url = f"{self._base}/Services/{self.service_sid}/Verifications/{token}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds, auth=self._auth) as c:
                r = await c.get(url)
                r.raise_for_status()
                status = r.json().get("status")
                # Twilio statuses: approved, denied, pending, canceled, expired
                if status == "approved": return "approved"
                if status == "denied":   return "denied"
                if status == "pending":  return "pending"
                return "expired"
        except Exception as e:
            log.warning("Twilio Verify poll failed: %s", e)
            return "expired"

    async def verify_totp(self, username: str, code: str) -> bool:
        url = f"{self._base}/Services/{self.service_sid}/VerificationCheck"
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds, auth=self._auth) as c:
                r = await c.post(url, data={"To": username, "Code": code})
                r.raise_for_status()
                return r.json().get("status") == "approved"
        except Exception as e:
            log.warning("Twilio Verify TOTP failed: %s", e)
            return False

# ---------------------------------------------------------------------------
# Push-sim client (the dev-fabric default — wraps our local push-sim service)
# ---------------------------------------------------------------------------

@dataclass
class PushSimClient:
    """The dev-fabric push-sim. Same contract as the real providers so
    the gateway code doesn't branch on provider name."""
    name: str = "push-sim"
    base_url: str = "http://push-sim:8080"
    timeout_seconds: float = 5.0

    async def request_push(self, username: str, ip: str) -> str | None:
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as c:
                r = await c.post(f"{self.base_url}/push/request", json={
                    "username": username, "ip": ip,
                })
                r.raise_for_status()
                return r.json().get("token")
        except Exception as e:
            log.warning("push-sim request failed: %s", e)
            return None

    async def poll(self, token: str) -> str:
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as c:
                r = await c.get(f"{self.base_url}/push/poll/{token}")
                if r.status_code == 404:
                    return "expired"
                r.raise_for_status()
                return r.json().get("status", "pending")
        except Exception as e:
            log.warning("push-sim poll failed: %s", e)
            return "expired"

    async def verify_totp(self, username: str, code: str) -> bool:
        # push-sim doesn't carry TOTP; the gateway's local enrollment
        # store handles that. Return False so the gateway uses its
        # local resolve_secret path.
        return False

# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

_PROVIDERS = {
    "duo":      DuoAuthClient,
    "okta":     OktaVerifyClient,
    "twilio":   TwilioVerifyClient,
    "authy":    TwilioVerifyClient,   # alias
    "push-sim": PushSimClient,
}

def build_from_config(cfg: dict[str, Any] | None) -> MFAProvider | None:
    """Pick the configured provider. Schema:

        mfa:
          provider: duo | okta | twilio | push-sim
          duo:
            host: api-XXXXXXXX.duosecurity.com
            integration_key: ...
            secret_key:      ...
          okta:
            org_url:   https://example.okta.com
            api_token: ...
          twilio:
            service_sid: VAxxxx...
            account_sid: ACxxxx...
            auth_token:  ...
          push_sim:
            base_url: http://push-sim:8080

    Returns None when unset (gateway falls back to legacy push-sim env var).
    """
    if not cfg:
        return None
    block = cfg.get("mfa") if isinstance(cfg, dict) else None
    if not block:
        return None
    name = (block.get("provider") or "").lower()
    cls = _PROVIDERS.get(name)
    if not cls:
        return None
    init_args = block.get(name.replace("-", "_"), {})
    try:
        return cls(**init_args)
    except TypeError as e:
        log.warning("can't build MFA provider %r: %s", name, e)
        return None
