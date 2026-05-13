"""Plenith inbound REST API.

Until now Plenith was outbound-only: every connector pushes alerts
TO somewhere else (SIEM, SOAR, Slack, etc.). This package is the
inverse — a FastAPI service that lets external systems pull state OUT
of Plenith, trigger actions, and integrate via OpenAPI-driven SDK
generation.

Endpoint groups:

  /health, /ready, /version                — Liveness / readiness probes
  /metrics                                  — Prometheus exposition
  /engagements                              — Attacker session telemetry
  /engagements/{id}                         — Full engagement detail
  /engagements/{id}/narrative               — LLM-generated incident summary
  /alerts                                   — Fired alerts with filtering
  /isolation/validate                       — Trigger an isolation probe run
  /mfa/decisions/{ip}                       — Manual MFA decision injection
  /policy                                   — Currently-active policy info
  /content/manifest                         — Current rotation manifest
  /openapi.json, /docs, /redoc              — Auto-generated schema + UIs

Module layout:
    schemas.py    — Pydantic request/response models
    auth.py       — Bearer-token middleware
    metrics.py    — Prometheus exposition format
    server.py     — FastAPI app + route handlers
    client.py     — Python SDK wrapping the REST API
"""
from .client import PlenithClient  # noqa: F401
from .server import build_app          # noqa: F401

__all__ = ["PlenithClient", "build_app"]
