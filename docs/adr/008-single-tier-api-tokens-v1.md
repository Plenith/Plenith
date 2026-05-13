# ADR 008: Single-tier API tokens for v1 (per-tenant RBAC deferred)

**Status:** Accepted
**Date:** 2026-05
**Supersedes:** none
**Superseded by:** none yet

## Context

The inbound REST API needs auth. The choices in order of complexity:

1. **No auth** — dev fabric only.
2. **Single-tier Bearer token** — one token (or a set) grants full
   access. Open or full.
3. **Per-route scoped tokens** — each token has a scope set, only
   matching routes allow.
4. **Per-tenant RBAC** — multi-tenant model with admin / SOC tier 1
   / 2 / 3 / read-only / per-tenant-prefixed-route claims.
5. **OAuth 2.0 / OIDC** — full SSO integration with the org's IdP.

## Decision

**v1 ships option 2: single-tier Bearer tokens.** Open mode (no
tokens configured) for dev, multiple-tokens-supported-simultaneously
for production rotation.

## Why deferring options 3-5 is correct for v1

1. **Default deployment is single-tenant.** One organization runs
   Plenith for its own SOC. There's no second tenant to isolate
   from. Option 2 is sufficient.
2. **OAuth/OIDC integration is per-IdP.** Each customer has their
   own Okta / AzureAD / Auth0 / Keycloak. Shipping pre-baked
   integration for any of them tightens the dep tree and provides
   value to only some customers. We document the swap-out path
   (mount your IdP's middleware in front of the FastAPI app) instead.
3. **Per-tenant RBAC is a real product direction** that should be
   designed with input from actual multi-tenant customers, not
   pre-built.

## Considered alternatives

- **Ship full RBAC in v1 anyway** — design risk; we'd guess what
  customers want.
- **Use FastAPI's OAuth2PasswordBearer** — adds JWT-handling code
  for a feature we don't need yet.
- **Mutual TLS only** — operationally heavy for the dev fabric.

## Consequences

- **`POST /mfa/decisions/{ip}` requires the same token tier as
  `GET /engagements`.** A token leak means full access. Threat model
  (`docs/THREAT_MODEL.md` Scenario 4) explicitly notes this.
- **Token rotation is supported** — set `PLENITH_API_TOKENS=old,new`
  for a transition window, then drop the old.
- **Multi-tenancy is in the backlog** (todo item 11). Will add
  per-tenant token scoping + `deployment_id` filtering on every
  endpoint when shipped.
- **A reverse proxy with finer auth** (Authelia, oauth2-proxy) can be
  bolted on in front of the FastAPI app — `Authorization: Bearer` will
  pass through.

## File pointers

- `plenith/api/auth.py` — APIAuth + make_dependency
- `docs/THREAT_MODEL.md` — Scenario 4 (token leak)
