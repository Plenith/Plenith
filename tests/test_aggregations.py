"""Tests for `plenith.aggregations` — Phase 5 of UI_WIRING.md.

The aggregation module is the single source for bucketed alerts +
heatmap + DNS stats consumed by both the dashboard's inline render and
the API endpoints.  These tests pin the contract:

  - bucket boundaries computed correctly
  - severity filtering
  - compare_to="previous" produces a same-width prior-window series
  - heatmap aggregates commands + alerts together
  - DNS classification matches the exfil-domain rules used in v1.0.1

Pure functions over file inputs → tests inject synthetic state-docker
trees and validate the returned dicts directly.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from plenith.aggregations import (
    activity_heatmap,
    alert_rate,
    alert_top,
    dns_stats,
    dns_top,
    parse_dns_lines,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def state_root(tmp_path):
    """Empty state-docker layout for tests that seed their own logs."""
    root = tmp_path / "state-docker"
    (root / "logs").mkdir(parents=True)
    return root

def _seed_log(root: Path, host: str, started_at: float,
                actions=None, commands=None, eng_id="eng-001"):
    """Write one session log file with the given actions + commands."""
    host_dir = root / "logs" / host
    host_dir.mkdir(parents=True, exist_ok=True)
    log = {
        "engagement_id":  eng_id,
        "started_at":     started_at,
        "actions_taken":  actions or [],
        "commands":       commands or [],
    }
    fname = f"{int(started_at * 1000)}_log.json"
    (host_dir / fname).write_text(json.dumps(log), encoding="utf-8")

# ---------------------------------------------------------------------------
# alert_rate
# ---------------------------------------------------------------------------

class TestAlertRate:
    def test_empty_window_returns_zero_buckets(self, state_root):
        now = time.time()
        r = alert_rate(state_root, since=now - 3600, until=now,
                        bucket_seconds=600)
        assert len(r["series"]) == 6              # 1h / 10min
        assert all(b["critical"] == 0 for b in r["series"])
        assert r["totals"] == {"critical": 0, "high": 0,
                                "medium": 0, "info": 0}

    def test_alerts_land_in_correct_buckets(self, state_root):
        now = time.time()
        # Three alerts spread across a 30-minute window
        _seed_log(state_root, "bastion-prod",
                   started_at=now - 1500,
                   actions=[{"action": "alert_x", "severity": "critical",
                              "ts": now - 1500}])
        _seed_log(state_root, "bastion-prod",
                   started_at=now - 900,
                   actions=[{"action": "alert_y", "severity": "high",
                              "ts": now - 900}],
                   eng_id="eng-002")
        _seed_log(state_root, "api-prod-03",
                   started_at=now - 200,
                   actions=[{"action": "alert_z", "severity": "medium",
                              "ts": now - 200}],
                   eng_id="eng-003")

        r = alert_rate(state_root, since=now - 1800, until=now,
                        bucket_seconds=600)
        assert r["totals"]["critical"] == 1
        assert r["totals"]["high"]     == 1
        assert r["totals"]["medium"]   == 1
        # The total across all buckets equals the totals
        for sev in ("critical", "high", "medium"):
            assert sum(b[sev] for b in r["series"]) == r["totals"][sev]

    def test_severity_filter_excludes_unwanted(self, state_root):
        now = time.time()
        _seed_log(state_root, "h",
                   started_at=now - 500,
                   actions=[
                       {"action": "x", "severity": "critical", "ts": now - 500},
                       {"action": "y", "severity": "info",     "ts": now - 400},
                   ])
        r = alert_rate(state_root, since=now - 600, until=now,
                        bucket_seconds=600, severities=["critical"])
        assert r["totals"]["critical"] == 1
        # info wasn't asked for — its total stays 0 even though it
        # appeared in the log.
        assert r["totals"]["info"] == 0

    def test_compare_to_previous_returns_same_width_window(self, state_root):
        """compare_to='previous' must return a series shifted backward
        by exactly the window width."""
        now = time.time()
        # Seed an alert in the prior window so the compare series isn't
        # all zeros
        _seed_log(state_root, "h",
                   started_at=now - 7000,
                   actions=[{"action": "x", "severity": "high",
                              "ts": now - 7000}])
        r = alert_rate(state_root, since=now - 3600, until=now,
                        bucket_seconds=600,
                        compare_to="previous")
        assert r["compare"] is not None
        assert len(r["compare"]) == len(r["series"])
        # The prior-window series sees the older alert
        assert sum(b["high"] for b in r["compare"]) == 1
        # The current series doesn't
        assert sum(b["high"] for b in r["series"]) == 0

    def test_compare_to_none_means_no_overlay(self, state_root):
        now = time.time()
        r = alert_rate(state_root, since=now - 3600, until=now)
        assert r["compare"] is None

    def test_action_with_only_ts_offset_s_still_buckets(self, state_root):
        """Some older log files store `ts_offset_s` instead of `ts`.  The
        aggregator must reconstruct using `started_at + ts_offset_s`."""
        now = time.time()
        _seed_log(state_root, "h",
                   started_at=now - 300,
                   actions=[{"action": "x", "severity": "critical",
                              "ts_offset_s": 60}])
        r = alert_rate(state_root, since=now - 600, until=now,
                        bucket_seconds=300)
        assert r["totals"]["critical"] == 1

# ---------------------------------------------------------------------------
# alert_top
# ---------------------------------------------------------------------------

class TestAlertTop:
    def test_returns_most_frequent_alerts(self, state_root):
        now = time.time()
        for i in range(5):
            _seed_log(state_root, "h", started_at=now - 60 * (i + 1),
                       actions=[{"action": "alert_dns_exfil",
                                  "severity": "high",
                                  "ts": now - 60 * (i + 1)}])
        _seed_log(state_root, "h", started_at=now - 30,
                   actions=[{"action": "alert_rev_shell",
                              "severity": "critical",
                              "ts": now - 30}])
        r = alert_top(state_root, since=now - 600, until=now, limit=5)
        names = [a["name"] for a in r["alerts"]]
        # rev_shell beats dns_exfil despite lower count — critical > high
        assert names[0] == "alert_rev_shell"
        assert "alert_dns_exfil" in names
        # Counts are accurate
        dns_record = next(a for a in r["alerts"] if a["name"] == "alert_dns_exfil")
        assert dns_record["count"] == 5
        # Sparkline length matches the bucket count
        assert len(dns_record["sparkline"]) == 8

    def test_respects_limit(self, state_root):
        now = time.time()
        for i in range(15):
            _seed_log(state_root, "h", started_at=now - 60 * (i + 1),
                       actions=[{"action": f"alert_kind_{i}",
                                  "severity": "info",
                                  "ts": now - 60 * (i + 1)}])
        r = alert_top(state_root, since=now - 3600, until=now, limit=5)
        assert len(r["alerts"]) == 5

# ---------------------------------------------------------------------------
# activity_heatmap
# ---------------------------------------------------------------------------

class TestActivityHeatmap:
    def test_command_count_lands_in_correct_hour(self, state_root):
        now = time.time()
        _seed_log(state_root, "bastion-prod", started_at=now,
                   commands=[{"ts": now, "cmd": "ls"},
                             {"ts": now, "cmd": "id"}])
        r = activity_heatmap(state_root, since=now - 3600, until=now + 1)
        cur_hour = time.localtime(now).tm_hour
        assert r["hosts"]["bastion-prod"][cur_hour] == 2

    def test_host_filter(self, state_root):
        now = time.time()
        _seed_log(state_root, "a", started_at=now,
                   commands=[{"ts": now, "cmd": "x"}])
        _seed_log(state_root, "b", started_at=now,
                   commands=[{"ts": now, "cmd": "x"}])
        r = activity_heatmap(state_root, since=now - 60, until=now + 1,
                              host="a")
        assert "a" in r["hosts"]
        assert "b" not in r["hosts"]

    def test_actions_and_commands_both_count(self, state_root):
        now = time.time()
        _seed_log(state_root, "h", started_at=now,
                   actions=[{"action": "x", "severity": "high", "ts": now}],
                   commands=[{"ts": now, "cmd": "ls"}])
        r = activity_heatmap(state_root, since=now - 60, until=now + 1)
        cur_hour = time.localtime(now).tm_hour
        assert r["hosts"]["h"][cur_hour] == 2

    def test_empty_state_returns_empty_grid(self, tmp_path):
        r = activity_heatmap(tmp_path / "empty", since=0, until=time.time())
        assert r["hosts"] == {}
        assert r["peak_hour"] is None
        assert r["busiest_host"] is None

    def test_peak_hour_and_busiest_host_computed(self, state_root):
        now = time.time()
        cur_hour = time.localtime(now).tm_hour
        # Make 'busy-host' the most active
        for i in range(5):
            _seed_log(state_root, "busy-host", started_at=now - i,
                       commands=[{"ts": now - i, "cmd": "x"}],
                       eng_id=f"e{i}")
        _seed_log(state_root, "quiet-host", started_at=now,
                   commands=[{"ts": now, "cmd": "x"}])
        r = activity_heatmap(state_root, since=now - 3600, until=now + 1)
        assert r["busiest_host"] == "busy-host"
        assert r["peak_hour"] == cur_hour

# ---------------------------------------------------------------------------
# DNS classification + stats + top
# ---------------------------------------------------------------------------

class TestDNSClassification:
    def test_parse_resolves_normal_query(self):
        lines = [
            "[14:28:01] api-prod-03.vertex.corp. A NOERROR",
        ]
        parsed = parse_dns_lines(lines)
        assert len(parsed) == 1
        assert parsed[0]["host"] == "api-prod-03.vertex.corp"
        assert parsed[0]["qtype"] == "A"
        assert parsed[0]["result"] == "resolved"

    def test_classifies_known_exfil_domains_as_blocked(self):
        for token in ("oast.live", "burpcollaborator.net", "ngrok.io",
                       "dnslog.cn", "interactsh.com"):
            lines = [f"[14:00:00] sub.{token}. A NOERROR"]
            parsed = parse_dns_lines(lines)
            assert parsed and parsed[0]["result"] == "blocked", token

    def test_nxdomain_marked_as_such(self):
        lines = ["[14:00:00] admin.vertex.corp. A NXDOMAIN"]
        parsed = parse_dns_lines(lines)
        assert parsed[0]["result"] == "nxdomain"

    def test_dns_stats_counts_each_result_class(self):
        parsed = [
            {"ts": "00", "host": "a.b", "qtype": "A", "result": "resolved"},
            {"ts": "00", "host": "x.ngrok.io", "qtype": "A", "result": "blocked"},
            {"ts": "00", "host": "missing", "qtype": "A", "result": "nxdomain"},
            {"ts": "00", "host": "a.b", "qtype": "A", "result": "resolved"},
        ]
        s = dns_stats(parsed)
        assert s == {"total": 4, "resolved": 2, "blocked": 1, "nxdomain": 1}

    def test_dns_top_returns_most_frequent_blocked(self):
        parsed = [
            {"ts": "0", "host": "a.oast.live",  "qtype": "A", "result": "blocked"},
            {"ts": "0", "host": "a.oast.live",  "qtype": "A", "result": "blocked"},
            {"ts": "0", "host": "b.ngrok.io",   "qtype": "A", "result": "blocked"},
            {"ts": "0", "host": "legit.corp",   "qtype": "A", "result": "resolved"},
        ]
        top = dns_top(parsed, result_type="blocked")
        assert top[0]["host"] == "a.oast.live"
        assert top[0]["count"] == 2
        # Resolved hosts aren't in the blocked list
        assert all(t["host"] != "legit.corp" for t in top)

    def test_dns_top_rejects_unknown_result_type(self):
        with pytest.raises(ValueError):
            dns_top([], result_type="bogus")
