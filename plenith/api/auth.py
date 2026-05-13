"""Bearer-token auth middleware for the REST API.

Simple-but-real: a configurable set of static tokens passed as
`Authorization: Bearer <token>`. Tokens are loaded from:

  1. env var PLENITH_API_TOKENS (comma-separated)
  2. config.yaml `api.tokens[]`
  3. config.yaml `api.token_file` (one token per line)

Auth is optional — when no tokens are configured, the API runs in
"open" mode (every request allowed). This matches how `kubectl
port-forward` style dev workflows expect — don't make local testing
painful. Production deployments MUST configure tokens.

Constant-time compare via hmac so a network attacker can't time-side-
channel-distinguish "wrong token" from "no token at all".
"""
from __future__ import annotations

import hmac
import os
from pathlib import Path
from typing import Iterable, Optional, Set

from fastapi import HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer


_bearer_scheme = HTTPBearer(auto_error=False)


def _load_tokens_from_config(cfg: Optional[dict]) -> Set[str]:
    """Resolve tokens from env > config.tokens > config.token_file."""
    tokens: Set[str] = set()

    env_tokens = os.environ.get("PLENITH_API_TOKENS", "")
    for t in env_tokens.split(","):
        t = t.strip()
        if t:
            tokens.add(t)

    if cfg and isinstance(cfg, dict):
        api_cfg = cfg.get("api") or {}
        for t in api_cfg.get("tokens", []) or []:
            t = str(t).strip()
            if t:
                tokens.add(t)
        token_file = api_cfg.get("token_file")
        if token_file:
            try:
                for line in Path(token_file).read_text(encoding="utf-8").splitlines():
                    t = line.strip()
                    if t and not t.startswith("#"):
                        tokens.add(t)
            except OSError:
                pass
    return tokens


class APIAuth:
    """Bearer auth checker. Inject into FastAPI routes via Depends().

    Holds the set of valid tokens. When the set is empty, auth is
    disabled (open mode — for dev). Constant-time-compares submitted
    tokens against the valid set to avoid timing side channels.
    """

    def __init__(self, tokens: Iterable[str] = ()):
        self._tokens: Set[str] = {t for t in tokens if t}

    @classmethod
    def from_config(cls, cfg: Optional[dict] = None) -> "APIAuth":
        return cls(_load_tokens_from_config(cfg))

    @property
    def enabled(self) -> bool:
        return bool(self._tokens)

    def _verify(self, presented: str) -> bool:
        for tok in self._tokens:
            if hmac.compare_digest(tok, presented):
                return True
        return False

    def check(self, presented: str) -> Optional[str]:
        """Synchronous token verification — split out so the FastAPI
        dependency stays tiny. Returns the matched token on success,
        None when auth is disabled, raises HTTPException(401) on bad
        creds when enabled."""
        if not self.enabled:
            return None
        if not presented:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing Authorization: Bearer <token>",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not self._verify(presented):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return presented


def make_dependency(auth: APIAuth):
    """Build the FastAPI Depends() callable for an APIAuth instance.

    Critical: the inner function's only parameter MUST be declared
    `Depends(HTTPBearer(...))`. Otherwise FastAPI treats it as a body
    parameter, which hijacks POST request bodies and returns 422.
    """
    from fastapi import Depends

    async def _dep(
        creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
    ) -> Optional[str]:
        presented = creds.credentials if creds else ""
        return auth.check(presented)
    return _dep
