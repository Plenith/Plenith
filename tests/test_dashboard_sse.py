"""Tests for the SOC dashboard — v2 design (Phase 1 of UI_WIRING.md).

These don't spin up a live HTTP server — that would require Docker +
state-docker/ + persona fixtures.  Instead they test:

  1. `_render_main_panels(state)` accepts a state-shaped dict and emits
     well-formed HTML for the dynamic subtree only (no <style>, no
     topbar wrapper, no full <!doctype>).
  2. `_render(state, refresh, sse=True)` produces an EventSource
     bootstrap and no meta-refresh.
  3. `_render(state, refresh, sse=False)` falls back to meta-refresh.
  4. `_render` includes the topbar deployment data + SSE status pill.
  5. The popout render functions accept state and return full HTML.
  6. The Handler class exposes /api/stream + the /panel/<name> routes.

These tests intentionally don't import live Docker or the orchestrator.
The `_synth_state` helper builds the minimal state dict each renderer
needs, including the new KPI/dns_parsed/host_activity fields v2 added.
"""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path


_ROOT = Path(__file__).resolve().parent.parent


def _load_dashboard():
    """Side-load tools/dashboard.py — it's not on a regular package
    path so importlib has to do it manually.  Also injects tools/ onto
    sys.path so the sibling dashboard_styles/dashboard_scripts modules
    resolve."""
    import sys
    sys.path.insert(0, str(_ROOT / "tools"))
    spec = importlib.util.spec_from_file_location(
        "dashboard", _ROOT / "tools" / "dashboard.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _synth_state(engagements=None, containers=None, dns_lines=None,
                  dns_parsed=None, sev_totals=None, actions_by_eng=None,
                  kpis=None, host_activity=None, alert_rate_buckets=None):
    """Minimum state dict the v2 renderer accepts."""
    return {
        "engagements":    engagements or [],
        "actions_by_eng": actions_by_eng or {},
        "sev_totals":     sev_totals or {"critical": 0, "high": 0,
                                          "medium": 0, "info": 0},
        "containers":     containers or [],
        "dns_lines":      dns_lines or [],
        "dns_parsed":     dns_parsed or [],
        "kpis":           kpis or {
            "active": 0, "alerts_24h": 0, "alerts_24h_delta": 0,
            "llm_detected": 0, "llm_total": 0, "proof_by_trap": 0,
            "dwell_p50_s": 0, "decoys_planted": 0, "decoys_swallowed": 0,
        },
        "host_activity":      host_activity or {},
        "alert_rate_buckets": alert_rate_buckets or [],
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
# _render_main_panels — the SSE-pushed fragment
# ---------------------------------------------------------------------------

class TestRenderMainPanels:
    def test_empty_state_produces_placeholder(self):
        d = _load_dashboard()
        out = d._render_main_panels(_synth_state())
        assert "No engagements yet" in out
        # Backward-compat surface: the (0) count token is still present
        assert "Engagements (0)" in out

    def test_fragment_has_no_style_or_topbar_or_doctype(self):
        """The fragment must NOT include the <style> block, the topbar,
        or a full <!doctype> — those live in _render() and would clobber
        the page on each SSE push."""
        d = _load_dashboard()
        out = d._render_main_panels(_synth_state())
        assert "<style" not in out.lower()
        assert 'class="top"' not in out         # topbar is in _render, not panels
        assert "<!doctype" not in out.lower()

    def test_engagement_row_renders_with_pills(self):
        d = _load_dashboard()
        state = _synth_state(
            engagements=[{
                "engagement_id": "eng-aaaa-bbbb",
                "source_ip":     "203.0.113.7",
                "claimed_user":  "jdoe",
                "connection_count": 3,
                "first_seen_at": 1700000000,
                "last_seen_at":  1700000042,
                "_host":         "bastion-prod",
                "observed": {},
                "logs": [{"commands": [{"ts": 1700000010, "cmd": "uname -a"}]}],
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
        # The new pill classes (high / med)
        assert 'class="pill high"' in out
        assert 'class="pill med"' in out

    def test_dns_feed_classifies_exfil(self):
        d = _load_dashboard()
        state = _synth_state(dns_parsed=[
            {"ts": "14:28:04", "host": "x.ngrok.io",     "qtype": "A", "result": "blocked"},
            {"ts": "14:28:01", "host": "normal.acme.example", "qtype": "A", "result": "resolved"},
        ])
        out = d._render_main_panels(state)
        # Blocked rows carry the .blocked class on the result chip
        assert 'class="dns-result blocked"' in out
        # The resolved host shows up unflagged
        assert "normal.acme.example" in out

    def test_kpi_strip_renders_active_count(self):
        d = _load_dashboard()
        state = _synth_state(
            kpis={
                "active": 3, "alerts_24h": 17, "alerts_24h_delta": 12,
                "llm_detected": 2, "llm_total": 8, "proof_by_trap": 1,
                "dwell_p50_s": 270, "decoys_planted": 4, "decoys_swallowed": 2,
            },
            engagements=[{"engagement_id": "x", "first_seen_at": 0,
                           "last_seen_at": 0, "observed": {}, "logs": []}],
        )
        out = d._render_main_panels(state)
        # KPI label + value present
        assert "Active engagements" in out
        assert "Alerts (24h)" in out
        assert "Counter-AI detected" in out
        assert "Proof-by-trap" in out
        # Delta sign rendered
        assert "12%" in out


# ---------------------------------------------------------------------------
# _render — full page assembly + SSE vs legacy mode
# ---------------------------------------------------------------------------

class TestRenderModes:
    def test_sse_mode_has_eventsource_no_meta_refresh(self):
        d = _load_dashboard()
        html = d._render(_synth_state(), refresh=3, sse=True)
        assert "EventSource" in html
        assert "/api/stream" in html
        assert 'http-equiv="refresh"' not in html
        assert "live (SSE)" in html
        # Dynamic content wrapped in #panels for the SSE swap
        assert 'id="panels"' in html

    def test_legacy_mode_has_meta_refresh_no_eventsource(self):
        d = _load_dashboard()
        html = d._render(_synth_state(), refresh=5, sse=False)
        assert 'http-equiv="refresh"' in html
        assert 'content="5"' in html
        # No SSE script in legacy mode
        assert "EventSource" not in html
        assert "auto-refresh 5s" in html

    def test_topbar_data_appears_in_both_modes(self):
        d = _load_dashboard()
        for sse in (True, False):
            html = d._render(_synth_state(), refresh=3, sse=sse)
            # Deployment identity strip
            assert "AcmeCorp" in html
            assert "acme.example" in html
            assert "abc123" in html             # signature
            # Brand mark
            assert "PLENITH" in html
            # TV mode + Layout buttons (Phase 1 client-side controls)
            assert "TV mode" in html
            assert "Layout" in html

    def test_render_does_not_crash_with_minimal_engagement(self):
        """Some old log files have only engagement_id."""
        d = _load_dashboard()
        state = _synth_state(engagements=[{"engagement_id": "x"}])
        # Must not raise.  Missing first_seen_at / last_seen_at / logs
        # are tolerated by the row renderer (defaults to 0 / []).
        d._render(state, refresh=3, sse=True)


# ---------------------------------------------------------------------------
# Popout renderers
# ---------------------------------------------------------------------------

class TestPopoutRenderers:
    def test_panel_engagements_returns_full_page(self):
        d = _load_dashboard()
        out = d._render_panel_engagements(_synth_state())
        assert "<!doctype" in out.lower()
        assert "<style" in out.lower()
        assert "panels" in out
        # Back-to-dashboard link
        assert 'href="/"' in out

    def test_panel_engagement_detail_handles_missing_id(self):
        d = _load_dashboard()
        out = d._render_panel_engagement_detail(_synth_state(), "nonexistent")
        # No crash; helpful message instead
        assert "not found" in out.lower()

    def test_panel_alert_rate_renders(self):
        d = _load_dashboard()
        state = _synth_state(
            sev_totals={"critical": 2, "high": 5, "medium": 8, "info": 3},
            alert_rate_buckets=[
                {"ts": 0, "critical": 1, "high": 2, "medium": 3, "info": 1}
                for _ in range(12)
            ],
        )
        out = d._render_panel_alert_rate(state)
        assert "Alert rate" in out
        # Severity breakdown in the chart stats
        assert "critical" in out
        assert "medium" in out

    def test_panel_dns_feed_renders(self):
        d = _load_dashboard()
        state = _synth_state(dns_parsed=[
            {"ts": "00:00:00", "host": "x.ngrok.io", "qtype": "A", "result": "blocked"},
        ])
        out = d._render_panel_dns_feed(state)
        assert "x.ngrok.io" in out
        assert "DNS query feed" in out

    def test_panel_activity_renders_with_empty_grid(self):
        d = _load_dashboard()
        out = d._render_panel_activity(_synth_state())
        # Empty-state copy or panel heading present
        assert "Activity" in out


# ---------------------------------------------------------------------------
# Handler routes and toggles
# ---------------------------------------------------------------------------

class TestHandlerSurface:
    def test_handler_advertises_sse_endpoint(self):
        d = _load_dashboard()
        src = Path(d.__file__).read_text(encoding="utf-8")
        assert "/api/stream" in src
        assert "text/event-stream" in src
        assert "data: " in src
        assert hasattr(d.Handler, "sse_enabled")
        assert d.Handler.sse_enabled is True

    def test_handler_advertises_all_panel_routes(self):
        """Every pop-out icon in the prototypes must have a real route."""
        d = _load_dashboard()
        src = Path(d.__file__).read_text(encoding="utf-8")
        assert "/panel/engagements" in src
        assert "/panel/engagement/" in src
        assert "/panel/alert-rate" in src
        assert "/panel/dns-feed" in src
        assert "/panel/activity" in src

    def test_uses_threading_server(self):
        d = _load_dashboard()
        src = Path(d.__file__).read_text(encoding="utf-8")
        assert "ThreadingHTTPServer" in src
        assert not re.search(r"\bHTTPServer\b(?!.*Threading)", src
                              .replace("ThreadingHTTPServer", "_X_"))


# ---------------------------------------------------------------------------
# DNS parsing helper
# ---------------------------------------------------------------------------

class TestPhase6AlertEnumeration:
    """Phase 6: the SSE handler flattens every action_taken into a per-
    alert dict the client uses for toasts + browser notifications.
    These tests pin the shape so the client + server stay aligned."""

    def test_enumerate_alerts_flattens_across_engagements(self):
        d = _load_dashboard()
        state = {"engagements": [
            {"engagement_id": "eng-1", "claimed_user": "jdoe",
             "source_ip": "10.0.0.1",
             "logs": [{"actions_taken": [
                {"action": "alert_x", "severity": "critical",
                 "ts_offset_s": 5, "triggered_by": "rev shell"},
             ]}]},
            {"engagement_id": "eng-2", "claimed_user": "agarcia",
             "source_ip": "10.0.0.2",
             "logs": [{"actions_taken": [
                {"action": "alert_y", "severity": "high",
                 "ts_offset_s": 3, "triggered_by": "cred exfil"},
                {"action": "alert_z", "severity": "medium",
                 "ts_offset_s": 7, "triggered_by": "decoy read"},
             ]}]},
        ]}
        out = d._enumerate_alerts(state)
        assert len(out) == 3
        names = {a["action"] for a in out}
        assert names == {"alert_x", "alert_y", "alert_z"}

    def test_enumerate_alerts_key_is_stable_and_dedup_friendly(self):
        """The SSE handler uses `key` to detect re-emitted alerts.
        Same (eng, action, ts_offset_s) → same key."""
        d = _load_dashboard()
        state = {"engagements": [{
            "engagement_id": "eng-1", "claimed_user": "x", "source_ip": "y",
            "logs": [{"actions_taken": [
                {"action": "alert_x", "severity": "critical", "ts_offset_s": 5},
            ]}],
        }]}
        out1 = d._enumerate_alerts(state)
        out2 = d._enumerate_alerts(state)
        assert out1[0]["key"] == out2[0]["key"]

    def test_enumerate_alerts_marks_acked_state(self):
        d = _load_dashboard()
        state = {"engagements": [{
            "engagement_id": "eng-1", "claimed_user": "x", "source_ip": "y",
            "logs": [{"actions_taken": [
                {"action": "ack'd_alert", "severity": "critical",
                 "ts_offset_s": 1, "acknowledged_at": 1.0,
                 "acknowledged_by": "mwilson"},
                {"action": "fresh_alert", "severity": "critical",
                 "ts_offset_s": 2},
            ]}],
        }]}
        out = d._enumerate_alerts(state)
        by_name = {a["action"]: a for a in out}
        assert by_name["ack'd_alert"]["acked"] is True
        assert by_name["fresh_alert"]["acked"] is False

    def test_enumerate_alerts_truncates_long_triggered_by(self):
        """Toast layout breaks if triggered_by is multi-kilobyte (attacker
        could spam).  Helper trims to 200 chars."""
        d = _load_dashboard()
        long_cmd = "x" * 500
        state = {"engagements": [{
            "engagement_id": "eng-1", "claimed_user": "x", "source_ip": "y",
            "logs": [{"actions_taken": [
                {"action": "x", "severity": "high", "ts_offset_s": 0,
                 "triggered_by": long_cmd},
            ]}],
        }]}
        out = d._enumerate_alerts(state)
        assert len(out[0]["triggered_by"]) <= 200

    def test_enumerate_alerts_handles_missing_engagements(self):
        d = _load_dashboard()
        assert d._enumerate_alerts({}) == []
        assert d._enumerate_alerts({"engagements": []}) == []
        # Malformed engagement (no logs) still tolerated
        assert d._enumerate_alerts({"engagements": [{"engagement_id": "x"}]}) == []


class TestDnsClassification:
    def test_classify_exfil_domains_blocked(self):
        d = _load_dashboard()
        assert d._classify_dns_result("x.ngrok.io", "NOERROR") == "blocked"
        assert d._classify_dns_result("a.b.oast.live", "NOERROR") == "blocked"
        assert d._classify_dns_result("a.burpcollaborator.net", "NOERROR") == "blocked"

    def test_classify_nxdomain(self):
        d = _load_dashboard()
        assert d._classify_dns_result("admin.example.com", "NXDOMAIN") == "nxdomain"

    def test_classify_resolved_normal(self):
        d = _load_dashboard()
        assert d._classify_dns_result("api-prod-03.vertex.corp", "NOERROR") == "resolved"
