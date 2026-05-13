"""Tests for the SOC dashboard's SSE refactor (item 13).

We don't spin up a live HTTP server in the unit tests — that would
require Docker + state-docker/ + persona fixtures. Instead we test:

  1. `_render_main_panels(state)` accepts a state-shaped dict and emits
     well-formed HTML for the dynamic subtree only (no <style>, no
     <topbar>).
  2. `_render(state, refresh, sse=True)` produces an EventSource
     bootstrap and no meta-refresh.
  3. `_render(state, refresh, sse=False)` falls back to meta-refresh
     and emits no EventSource (legacy mode for curl tests and old
     browsers).
  4. The Handler class exposes /api/stream as a known route AND a
     `sse_enabled` toggle.

These tests intentionally don't import live Docker or the orchestrator;
they synthesize the smallest plausible state dict the renderer accepts.
"""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path


_ROOT = Path(__file__).resolve().parent.parent


def _load_dashboard():
    """Side-load tools/dashboard.py — it's not on a regular package
    path so importlib has to do it manually."""
    spec = importlib.util.spec_from_file_location(
        "dashboard", _ROOT / "tools" / "dashboard.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _synth_state(engagements=None, containers=None, dns_lines=None,
                 sev_totals=None, actions_by_eng=None):
    """Bare-minimum state dict the renderer accepts."""
    return {
        "engagements":    engagements or [],
        "actions_by_eng": actions_by_eng or {},
        "sev_totals":     sev_totals or {"critical": 0, "high": 0,
                                          "medium": 0, "info": 0},
        "containers":     containers or [],
        "dns_lines":      dns_lines or [],
        "rotation": {
            "corp_name":   "AcmeCorp",
            "corp_domain": "acme.example",
            "industry":    "Industrials",
            "subnet":      "10.42.0.0/16",
            "signature":   "abc123",
        },
        "now": "12:34:56",
    }


# ---------------------------------------------------------------------------
# _render_main_panels  — the SSE-pushed fragment
# ---------------------------------------------------------------------------

class TestRenderMainPanels:
    def test_empty_state_produces_placeholder(self):
        d = _load_dashboard()
        out = d._render_main_panels(_synth_state())
        # The placeholder copy is in there
        assert "No engagements yet" in out
        assert "Engagements (0)" in out

    def test_fragment_has_no_topbar_or_style(self):
        """The fragment must NOT include the <style> block or <topbar> —
        otherwise SSE pushes would clobber them on every tick."""
        d = _load_dashboard()
        out = d._render_main_panels(_synth_state())
        assert "<style" not in out.lower()
        assert "topbar" not in out
        assert "<!doctype" not in out.lower()

    def test_engagement_renders_with_pills(self):
        d = _load_dashboard()
        state = _synth_state(
            engagements=[{
                "engagement_id": "eng-aaaa-bbbb",
                "source_ip":     "203.0.113.7",
                "claimed_user":  "jdoe",
                "connection_count": 3,
                "dwell_seconds": 42,
                "narrative":     "Discovery → file_read",
                "_host":         "bastion-prod",
            }],
            actions_by_eng={
                "eng-aaaa-bbbb": [
                    {"action": "cred_harvest", "severity": "high"},
                    {"action": "discovery",     "severity": "medium"},
                ],
            },
            sev_totals={"critical": 0, "high": 1, "medium": 1, "info": 0},
        )
        out = d._render_main_panels(state)
        # Short engagement id is shown (first 8 chars)
        assert "eng-aaaa" in out
        # User + IP + host appear
        assert "jdoe" in out
        assert "203.0.113.7" in out
        assert "bastion-prod" in out
        # Pills for the two actions
        assert "cred_harvest" in out
        assert "discovery" in out
        # Severity colors are inlined as background:
        assert "background:#e8851e" in out   # high
        assert "background:#d8b91a" in out   # medium

    def test_container_table_renders_ok_and_bad(self):
        d = _load_dashboard()
        state = _synth_state(containers=[
            {"name": "plenith-bastion", "status": "Up 4 hours"},
            {"name": "plenith-dns",     "status": "Exited (1) 3m ago"},
        ])
        out = d._render_main_panels(state)
        assert "plenith-bastion" in out
        # The "ok" class colors live containers green
        assert 'class="ok"' in out
        # The "bad" class colors dead containers red
        assert 'class="bad"' in out

    def test_dns_exfil_lines_highlighted(self):
        d = _load_dashboard()
        state = _synth_state(dns_lines=[
            "172.30.0.5 -> q.oast.live NOERROR",
            "172.30.0.5 -> normal.acme.example NOERROR",
        ])
        out = d._render_main_panels(state)
        # The oast.live line gets the exfil class; the normal one does not
        assert 'class="exfil"' in out
        # And the benign line is rendered without that class
        assert "normal.acme.example" in out


# ---------------------------------------------------------------------------
# _render — full page assembly + SSE vs legacy mode
# ---------------------------------------------------------------------------

class TestRenderModes:
    def test_sse_mode_has_eventsource_no_meta_refresh(self):
        d = _load_dashboard()
        html = d._render(_synth_state(), refresh=3, sse=True)
        # EventSource script is present
        assert "new EventSource" in html
        assert "/api/stream" in html
        # No meta-refresh tag in SSE mode
        assert 'http-equiv="refresh"' not in html
        # The status pill says "live"
        assert "live (SSE)" in html
        # The dynamic content is wrapped in #panels
        assert 'id="panels"' in html

    def test_legacy_mode_has_meta_refresh_no_eventsource(self):
        d = _load_dashboard()
        html = d._render(_synth_state(), refresh=5, sse=False)
        # Meta-refresh present
        assert 'http-equiv="refresh"' in html
        assert 'content="5"' in html
        # No EventSource
        assert "EventSource" not in html
        # The status pill says auto-refresh
        assert "auto-refresh 5s" in html

    def test_topbar_data_appears_in_both_modes(self):
        d = _load_dashboard()
        for sse in (True, False):
            html = d._render(_synth_state(), refresh=3, sse=sse)
            assert "AcmeCorp" in html
            assert "acme.example" in html
            assert "abc123" in html       # signature
            assert "Plenith SOC" in html

    def test_render_does_not_crash_with_minimal_engagement(self):
        """Some old log files have only engagement_id + last_seen_at."""
        d = _load_dashboard()
        state = _synth_state(engagements=[{
            "engagement_id": "x",
        }])
        # Must not raise
        d._render(state, refresh=3, sse=True)


# ---------------------------------------------------------------------------
# Handler routes and toggles
# ---------------------------------------------------------------------------

class TestHandlerSurface:
    def test_handler_advertises_sse_endpoint(self):
        """The /api/stream branch must exist on do_GET. We grep the
        source rather than mounting the handler because BaseHTTPRequestHandler
        needs a real socket to instantiate."""
        d = _load_dashboard()
        src = Path(d.__file__).read_text(encoding="utf-8")
        assert "/api/stream" in src
        assert "text/event-stream" in src
        assert "data: " in src        # SSE framing
        # The class also exposes the sse_enabled toggle
        assert hasattr(d.Handler, "sse_enabled")
        assert d.Handler.sse_enabled is True

    def test_uses_threading_server(self):
        """SSE long-poll would block other endpoints on the single-
        threaded HTTPServer. main() must use ThreadingHTTPServer."""
        d = _load_dashboard()
        src = Path(d.__file__).read_text(encoding="utf-8")
        # Imported and used in main()
        assert "ThreadingHTTPServer" in src
        # Old single-threaded HTTPServer is NOT imported (the SSE refactor
        # required dropping it).
        assert not re.search(r"\bHTTPServer\b(?!.*Threading)", src
                              .replace("ThreadingHTTPServer", "_X_"))
