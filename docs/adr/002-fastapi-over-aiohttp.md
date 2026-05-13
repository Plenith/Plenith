# ADR 002: FastAPI over aiohttp / Starlette for the inbound REST

**Status:** Accepted
**Date:** 2026-05

## Context

The integration story requires an inbound HTTP API: GET state, trigger
actions, query metrics. We need async (matches the orchestrator's
event loop), schema validation (Pydantic), and ideally auto-generated
OpenAPI docs.

## Decision

**FastAPI + uvicorn.**

## Considered alternatives

- **stdlib http.server** — what the dashboard + push-sim already use.
- **aiohttp.web** — lighter, async-native.
- **Starlette (FastAPI's underlying ASGI framework)** — most of FastAPI
  minus the Pydantic / dependency-injection sugar.
- **Flask + Flask-RESTX** — synchronous, blocks the event loop.

## Why FastAPI wins

1. **OpenAPI 3.1 for free.** Every endpoint signature, every Pydantic
   model becomes a schema entry. Downstream consumers run `openapi-
   generator` to make typed clients in any language. This is the
   ENTIRE point of the integration story.
2. **Pydantic validation matches the integration audience's
   expectation.** Splunk SOAR integrations, Cortex XSOAR packs, every
   modern SOC tooling vendor uses Pydantic-shaped schemas.
3. **TestClient is in-process.** We test the full app without booting
   uvicorn — `httpx.AsyncClient(transport=httpx.ASGITransport(app))`.
   Saves ~3 seconds per CI run.
4. **The dep cost is real but bounded.** FastAPI + uvicorn add about
   ~15MB of wheels + ~250 transitive packages. Acceptable for the
   API server; the agent containers don't ship FastAPI.

## Consequences

- **Larger Python footprint** for the API process. Mitigated: API runs
  as a separate deployment in Helm, not bundled into the agent image.
- **Pydantic v2 only.** Pinned `pydantic>=2.6` — v1 schemas don't work.
- **Async-only.** Every handler must be `async def`. Fine; we're an
  async stack anyway.
- **The dashboard + push-sim STILL use stdlib http.server** because
  they don't need OpenAPI and we want zero deps for those microservices.

## File pointers

- `plenith/api/` — the FastAPI app
- `plenith/api/server.py` — `build_app(cfg, ...)` factory
- `tools/api_server.py` — uvicorn CLI launcher
