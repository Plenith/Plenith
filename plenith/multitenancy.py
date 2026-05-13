"""Multi-tenancy + per-tenant RBAC + per-tenant deployment_id namespacing.

Single-tenant is the v1 default (ADR 008). This module adds an
*optional* multi-tenant overlay for cluster operators who want one
Plenith install to serve multiple customer orgs (or multiple
business units of one org) without cross-tenant data leakage.

Three concepts:

  Tenant
      A logical isolation unit. Has its own:
        - deployment_id (drives content rotation — separate corp identity)
        - state directory namespace (state-docker/persistence/<tenant>/...)
        - logs namespace
        - MFA enrollment store
        - API token set
        - SIEM / SOAR connector config (each tenant ships to their own)

  Token claim
      An API token belongs to one tenant. The auth middleware injects
      `tenant_id` + `role` into the request; every read/write endpoint
      filters by tenant_id automatically.

  Role
      One of `admin`, `analyst`, `read_only`. Coarse-grained — finer
      RBAC (per-endpoint scopes) is deferred to v3.

Config schema:

    multitenancy:
      enabled: true
      tenants:
        - id: acme-corp
          deployment_id: 6f3a8c2e-...
          tokens:
            - {value: "tok-acme-admin-abc",   role: admin}
            - {value: "tok-acme-soc-def",     role: analyst}
            - {value: "tok-acme-readonly-ghi", role: read_only}
          state_subdir: acme-corp/
          connectors:
            splunk_hec: {url: https://acme.splunk.cloud/..., token: ...}
        - id: globex-inc
          ...

When `multitenancy.enabled: false` (default), the API runs in
single-tenant mode and this module is a no-op — APIAuth's existing
token check applies, every read sees everything.

Threat model: ADR 008 acknowledges per-tenant RBAC is a future feature.
This module is that future feature, behind an opt-in flag.
"""
from __future__ import annotations

import hmac
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------

ROLE_ADMIN     = "admin"
ROLE_ANALYST   = "analyst"
ROLE_READ_ONLY = "read_only"

_VALID_ROLES = {ROLE_ADMIN, ROLE_ANALYST, ROLE_READ_ONLY}

# Which endpoints each role can call. A coarse split for v2 — admin =
# everything, analyst = reads + selected actions (MFA decisions,
# isolation probes), read_only = GET only.
ROLE_PERMITS: Dict[str, Set[str]] = {
    ROLE_ADMIN:     {"read", "action", "admin"},
    ROLE_ANALYST:   {"read", "action"},
    ROLE_READ_ONLY: {"read"},
}


# ---------------------------------------------------------------------------
# Tenant + token records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TenantToken:
    """One API token belonging to one tenant with one role."""
    value: str
    tenant_id: str
    role: str


@dataclass
class Tenant:
    """A tenant's configuration: id, deployment_id (drives content
    rotation), state subdir, allowed tokens, optional per-tenant
    connector overrides."""
    id: str
    deployment_id: str = ""
    state_subdir: str = ""           # relative to global state/state-docker dirs
    tokens: List[TenantToken] = field(default_factory=list)
    connectors: Dict[str, Any] = field(default_factory=dict)
    mfa: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Registry — the authoritative tenant + token store
# ---------------------------------------------------------------------------

@dataclass
class TenantRegistry:
    """Holds every configured tenant. Constructed once at app startup
    from the parsed config.yaml. Lookup by token is constant-time."""
    tenants: Dict[str, Tenant] = field(default_factory=dict)
    _token_index: Dict[str, TenantToken] = field(default_factory=dict)
    enabled: bool = False

    @classmethod
    def from_config(cls, cfg: Optional[Dict[str, Any]]) -> "TenantRegistry":
        reg = cls()
        if not cfg:
            return reg
        block = cfg.get("multitenancy") if isinstance(cfg, dict) else None
        if not block or not block.get("enabled"):
            return reg
        reg.enabled = True
        for t in block.get("tenants") or []:
            tid = t.get("id")
            if not tid:
                continue
            tenant = Tenant(
                id=tid,
                deployment_id=t.get("deployment_id", ""),
                state_subdir=t.get("state_subdir") or f"{tid}/",
                connectors=t.get("connectors") or {},
                mfa=t.get("mfa") or {},
            )
            for tok in t.get("tokens") or []:
                value = tok.get("value")
                role  = tok.get("role", ROLE_READ_ONLY)
                if not value or role not in _VALID_ROLES:
                    continue
                token = TenantToken(value=value, tenant_id=tid, role=role)
                tenant.tokens.append(token)
                reg._token_index[value] = token
            reg.tenants[tid] = tenant
        return reg

    # --- lookups --------------------------------------------------------

    def lookup(self, presented_token: str) -> Optional[TenantToken]:
        """Constant-time token match — returns the TenantToken or None."""
        if not presented_token or not self.enabled:
            return None
        for known_token, record in self._token_index.items():
            if hmac.compare_digest(known_token, presented_token):
                return record
        return None

    def get_tenant(self, tenant_id: str) -> Optional[Tenant]:
        return self.tenants.get(tenant_id)

    def list_tenants(self) -> List[str]:
        return sorted(self.tenants.keys())

    # --- authorization checks ------------------------------------------

    @staticmethod
    def can(role: str, permit: str) -> bool:
        """`can("analyst", "action")` → True. `can("read_only", "admin")` → False."""
        if role not in _VALID_ROLES:
            return False
        return permit in ROLE_PERMITS[role]


# ---------------------------------------------------------------------------
# State-path namespacing helpers
# ---------------------------------------------------------------------------

def state_path_for(tenant: Optional[Tenant], base_path: "Path",
                    subkey: str) -> "Path":
    """Resolve a state path with optional per-tenant prefix.

    Example:
        base_path = state-docker/persistence
        tenant.state_subdir = "acme-corp/"
        subkey = "192.0.2.99__jdoe.json"
        → state-docker/persistence/acme-corp/192.0.2.99__jdoe.json
    """
    from pathlib import Path
    base = Path(base_path)
    if tenant and tenant.state_subdir:
        return base / tenant.state_subdir / subkey
    return base / subkey


def filter_engagements_by_tenant(
    engagements: List[Dict[str, Any]],
    tenant: Optional[Tenant],
) -> List[Dict[str, Any]]:
    """Filter a list of engagement dicts by tenant ownership.
    The ownership signal is which state_subdir an engagement's persisted
    file lives under — encoded in the engagement dict's optional
    `_tenant_id` field set at load time."""
    if tenant is None:
        return engagements
    return [e for e in engagements
            if e.get("_tenant_id") == tenant.id]
