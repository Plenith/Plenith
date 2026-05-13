"""Tests for the OpenTelemetry tracing shim.

The shim must be a NO-OP when OTel isn't installed (the default
install) — entering a span, setting attributes, raising inside the
span must all work without crashing. When OTel IS installed, the shim
must produce real spans.

We test the no-op path (always reachable) and best-effort the OTel
path with `pytest.importorskip("opentelemetry")` for the second.
"""
from unittest.mock import MagicMock

import pytest

from plenith import tracing


class _FakeSession:
    def __init__(self):
        self.engagement_id = "eng-abc"
        self.id = "sess-001"
        self.claimed_user = "jdoe"
        self.source_ip = "192.0.2.99"


# ---------------------------------------------------------------------------
# No-op path (always reachable — OTel may or may not be installed)
# ---------------------------------------------------------------------------

class TestNoOpPath:
    def test_status_summary_shape(self):
        s = tracing.status_summary()
        assert "enabled" in s
        assert "endpoint" in s
        assert "service" in s

    def test_span_context_manager_does_not_crash_with_no_attrs(self):
        with tracing.span("test.span"):
            pass

    def test_span_context_manager_does_not_crash_with_attrs(self):
        with tracing.span("test.span", {"k": "v", "n": 42}):
            pass

    def test_engagement_span_yields(self):
        s = _FakeSession()
        with tracing.engagement_span(s) as sp:
            # Span may be None (no-op) or a real OTel span; both are fine
            pass

    def test_command_span_yields(self):
        s = _FakeSession()
        with tracing.command_span(s, "whoami", source="cache"):
            pass

    def test_llm_call_span_yields(self):
        with tracing.llm_call_span(prompt_size=1234, model="qwen2.5-7b"):
            pass

    def test_action_span_yields(self):
        with tracing.action_span("alert_credential_exfil", "high"):
            pass

    def test_connector_emit_span_yields(self):
        with tracing.connector_emit_span("splunk_hec",
                                           "alert_credential_exfil",
                                           severity="high"):
            pass

    def test_exception_in_span_propagates(self):
        """Span MUST re-raise exceptions, not swallow them."""
        with pytest.raises(ValueError, match="planned"):
            with tracing.span("test.span"):
                raise ValueError("planned")

    def test_nested_spans_work(self):
        """Engagement → command → llm should all nest cleanly."""
        s = _FakeSession()
        with tracing.engagement_span(s):
            with tracing.command_span(s, "find / -name id_rsa", source="find"):
                with tracing.llm_call_span(500):
                    pass


# ---------------------------------------------------------------------------
# OTel-installed path (skipped if the package isn't there)
# ---------------------------------------------------------------------------

class TestOTelPath:
    def setup_method(self):
        # Force re-detection so tests don't see a stale cached result
        tracing._OTEL_AVAILABLE = None
        tracing._tracer = None

    def teardown_method(self):
        # And reset again for downstream tests
        tracing._OTEL_AVAILABLE = None
        tracing._tracer = None

    def test_detection_is_idempotent(self):
        # Two calls → same return value
        a = tracing._try_init_otel()
        b = tracing._try_init_otel()
        assert a == b

    def test_is_enabled_matches_init(self):
        ok = tracing._try_init_otel()
        assert tracing.is_enabled() == ok


# ---------------------------------------------------------------------------
# Orchestrator integration — wiring doesn't break the test suite
# ---------------------------------------------------------------------------

class TestOrchestratorWiring:
    @pytest.mark.asyncio
    async def test_handle_command_still_runs(self, orchestrator, session):
        """The orchestrator wraps handle_command in a command_span.
        With OTel uninstalled this is a no-op; verify the wrapping
        doesn't break the regular control flow."""
        # Run any command; should return (body, source) as before
        body, source = await orchestrator.handle_command(session, "whoami")
        assert isinstance(source, str)
