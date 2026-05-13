# ADR 010: stdlib `http.server` for the dashboard + push-sim

**Status:** Accepted
**Date:** 2026-05

## Context

The SOC dashboard and push-sim both need HTTP servers. ADR 002 picked
FastAPI for the main REST API. Should we use FastAPI for these too?

## Decision

**No. The dashboard (`tools/dashboard.py`) and push-sim
(`linux-fork/mfa/push_sim.py`) use stdlib `http.server`.**

## Why

1. **Zero new deps for these services.**
   - The dashboard is a CLI operator runs on their workstation. Adding
     FastAPI + uvicorn there forces a 250-package install. Stdlib is
     already there.
   - push-sim ships as a Docker image. Its base is `ubuntu:22.04` +
     `python3` only (no pip). Adding FastAPI would force an install
     step in the Dockerfile, growing the image from ~80MB to ~120MB
     for what is fundamentally a 3-endpoint demo service.
2. **The services are tiny.**
   - Dashboard = 6 endpoints, one of which is the HTML page.
   - push-sim = 5 endpoints, all `POST` or `GET` with one path param.
   - Neither needs Pydantic validation, OpenAPI, dependency injection,
     or async-native flow.
3. **No need for OpenAPI** on these services. They aren't part of the
   integration surface — the dashboard is operator-facing UI, push-sim
   is a dev-fabric stand-in that production replaces with Duo/Okta.

## Consequences

- **Different conventions in different files.** The main API uses
  Pydantic; these microservices use raw `BaseHTTPRequestHandler`. New
  contributors should NOT copy a stdlib pattern into `plenith/api/`.
- **Manual auth.** The main API has APIAuth; the dashboard runs on
  `127.0.0.1` only and has no auth; push-sim is internal-network only.
- **No async on these services.** They block on each request. Fine for
  the dashboard (one operator at a time); push-sim uses
  `ThreadingHTTPServer` for concurrent approve/poll calls.
- **If a microservice grows past 10 endpoints, reconsider.** At that
  point the FastAPI ceremony is worth the install cost.

## File pointers

- `tools/dashboard.py` — operator dashboard
- `linux-fork/mfa/push_sim.py` — MFA push simulator
- `plenith/api/server.py` — the proper REST API (FastAPI)
