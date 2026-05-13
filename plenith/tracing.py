"""OpenTelemetry-compatible tracing shim — no-op when OTel isn't installed.

We don't depend on `opentelemetry` in `requirements.txt` because it
pulls in ~30 transitive packages. Operators who want distributed
tracing install it explicitly:

    pip install \\
        opentelemetry-api \\
        opentelemetry-sdk \\
        opentelemetry-exporter-otlp-proto-http \\
        opentelemetry-instrumentation-fastapi

And configure via env:

    OTEL_SERVICE_NAME=plenith
    OTEL_EXPORTER_OTLP_ENDPOINT=https://your-otel-collector:4318
    OTEL_EXPORTER_OTLP_HEADERS=authorization=Bearer ...
    OTEL_RESOURCE_ATTRIBUTES=deployment.id=...,service.version=1.0.0

When `opentelemetry` IS installed, every span emitted by the shim
becomes a real OTel span and flows to the configured collector (Jaeger,
Tempo, Datadog APM, Honeycomb, Lightstep, etc.).

Spans the orchestrator emits:
    engagement       — root span for an attacker session
        command      — child per command (verb, source, latency)
        llm_call     — child when LLM is invoked
        action       — child when a heuristic fires
    connector_emit   — sibling root per outbound SIEM/SOAR/TI emit
    api_request      — root per inbound REST call (auto if you also
                       install opentelemetry-instrumentation-fastapi)
"""
from __future__ import annotations

import contextlib
import os
from typing import Any, Dict, Optional


# ---------------------------------------------------------------------------
# OTel detection — lazy import so we don't pay any cost if not installed.
# ---------------------------------------------------------------------------

_OTEL_AVAILABLE: Optional[bool] = None
_tracer = None


def _try_init_otel():
    """First time something asks for a tracer, try to import + configure
    OTel. Subsequent calls are cheap (cached result). Returns True on
    success, False if not installed or not configured."""
    global _OTEL_AVAILABLE, _tracer
    if _OTEL_AVAILABLE is not None:
        return _OTEL_AVAILABLE
    try:
        from opentelemetry import trace  # type: ignore
    except ImportError:
        _OTEL_AVAILABLE = False
        return False

    # The OTel SDK auto-discovers config from env vars when imported.
    # We rely on that — operators just set OTEL_EXPORTER_OTLP_ENDPOINT.
    try:
        # Try to set up a sensible default provider if none is configured.
        # If the user pre-configured one (e.g. via opentelemetry-launcher),
        # `get_tracer_provider` returns that one instead.
        provider = trace.get_tracer_provider()
        _tracer = trace.get_tracer("plenith", "1.0.0")
        _OTEL_AVAILABLE = True
        return True
    except Exception:
        _OTEL_AVAILABLE = False
        return False


# ---------------------------------------------------------------------------
# Public context managers
# ---------------------------------------------------------------------------

@contextlib.contextmanager
def span(name: str, attributes: Optional[Dict[str, Any]] = None):
    """Generic span context manager. When OTel isn't installed, this
    is a no-op (just yields). When it IS installed, it produces a real
    span with the supplied attributes.

    Usage:
        with span("engagement", {"engagement.id": eid, "user": claimed}):
            ...
    """
    if not _try_init_otel() or _tracer is None:
        yield None
        return
    # Real OTel path
    from opentelemetry import trace  # type: ignore
    with _tracer.start_as_current_span(name) as sp:
        if attributes:
            for k, v in attributes.items():
                try:
                    sp.set_attribute(k, v)
                except Exception:
                    pass
        try:
            yield sp
        except Exception as e:
            try:
                sp.record_exception(e)
                sp.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
            except Exception:
                pass
            raise


@contextlib.contextmanager
def engagement_span(session):
    """Root span for an attacker session.
    Wraps the orchestrator's per-connection handling so every command,
    LLM call, and connector emit during this engagement is nested under
    one trace."""
    attrs = {
        "engagement.id":     str(getattr(session, "engagement_id", "?")),
        "session.id":        str(getattr(session, "id", "?")),
        "user.name":         str(getattr(session, "claimed_user", "?")),
        "user.source_ip":    str(getattr(session, "source_ip", "?")),
        "service.name":      "plenith",
        "service.component": "orchestrator",
    }
    persona = getattr(session, "persona", None)
    if persona is not None:
        attrs["session.persona"] = str(getattr(persona, "username", "?"))
        attrs["session.hostname"] = str(getattr(persona, "hostname", "?"))
    with span("plenith.engagement", attrs) as sp:
        yield sp


@contextlib.contextmanager
def command_span(session, cmd: str, source: str = "?"):
    """Child span for one command. `source` is the dispatch path
    (cache / vfs-read / vfs-write / ls / sim-bot / llm / etc.) so a
    trace consumer can see which path is hot."""
    cmd_short = cmd[:120]
    attrs = {
        "engagement.id":  str(getattr(session, "engagement_id", "?")),
        "command.text":   cmd_short,
        "command.source": source,
    }
    with span("plenith.command", attrs) as sp:
        yield sp


@contextlib.contextmanager
def llm_call_span(prompt_size: int, model: str = "?"):
    """Child span for one LLM call. We don't include the prompt text
    in attributes (PII risk + size) — just the size + model."""
    attrs = {
        "llm.model":         model,
        "llm.prompt_chars":  prompt_size,
    }
    with span("plenith.llm_call", attrs) as sp:
        yield sp


@contextlib.contextmanager
def action_span(action_name: str, severity: str):
    """Child span for a heuristic/policy action firing."""
    attrs = {
        "action.name":     action_name,
        "action.severity": severity,
    }
    with span("plenith.action", attrs) as sp:
        yield sp


@contextlib.contextmanager
def connector_emit_span(connector_name: str, alert_action: str,
                         severity: str = "?"):
    """Span for one outbound emit through a connector. Useful for
    catching slow SIEM endpoints (their latency suddenly going from
    ~50ms to ~5s usually means they're behind on ingest)."""
    attrs = {
        "connector.name":   connector_name,
        "alert.action":     alert_action,
        "alert.severity":   severity,
    }
    with span("plenith.connector_emit", attrs) as sp:
        yield sp


# ---------------------------------------------------------------------------
# Status / introspection
# ---------------------------------------------------------------------------

def is_enabled() -> bool:
    """True iff OTel is installed and a tracer was successfully constructed."""
    return bool(_try_init_otel())


def status_summary() -> Dict[str, Any]:
    """For /metrics or operator diagnostics — describe whether tracing
    is on and where it ships to."""
    out = {
        "enabled": is_enabled(),
        "endpoint": os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", ""),
        "service":  os.environ.get("OTEL_SERVICE_NAME", "plenith"),
    }
    return out
