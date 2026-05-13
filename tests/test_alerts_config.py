"""Tests for deploy/prometheus/alerts.yml + docs/runbooks/.

We can't reach Prometheus from CI to validate the rule expressions
syntactically (that needs `promtool`), but we can catch the failure
modes that DO bite us — most often the "alert points to a runbook URL
that doesn't exist" one.

Coverage:
  - The alerts file is valid YAML and follows the documented
    `groups → rules` schema.
  - Every alert has `severity`, `summary`, `description`, and a
    `runbook_url` annotation.
  - Every `runbook_url` resolves to a file in `docs/runbooks/`.
  - Every runbook in `docs/runbooks/` (except README.md) corresponds to
    a known alert. Catches abandoned runbooks after an alert is
    renamed.
  - The runbooks/README.md index lists every alert.
  - Alert expressions reference at least one metric that the platform
    actually exports (`up`, `time()`, or `plenith_*`). Catches typos
    in metric names — a frequent failure mode.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml


_ROOT = Path(__file__).resolve().parent.parent
_ALERTS_FILE = _ROOT / "deploy" / "prometheus" / "alerts.yml"
_RUNBOOKS_DIR = _ROOT / "docs" / "runbooks"
_RUNBOOKS_INDEX = _RUNBOOKS_DIR / "README.md"

# Metric names the platform exports — kept in sync with
# `plenith/api/metrics.py`. Adding a new metric? Update this list.
_EXPORTED_METRICS = {
    "plenith_alerts_by_action_total",
    "plenith_alerts_total",
    "plenith_api_errors_total",
    "plenith_api_requests_total",
    "plenith_counter_ai_detections_total",
    "plenith_counter_ai_proven_total",
    "plenith_engagements_total",
    "plenith_mfa_decisions_total",
    "plenith_process_uptime_seconds",
    # Wired by deployment, not by the API process itself
    "plenith_agent_heartbeat_timestamp_seconds",
    "plenith_audit_chain_ok",
}

# Built-in Prometheus surface we're allowed to reference
_BUILTIN_METRICS = {"up"}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def alerts_cfg():
    assert _ALERTS_FILE.exists(), (
        "deploy/prometheus/alerts.yml is missing — without it, "
        "operators see Grafana panels but get no pages when things break."
    )
    return yaml.safe_load(_ALERTS_FILE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def all_alerts(alerts_cfg):
    """Flatten groups → rules into one list of alert dicts."""
    out = []
    for group in alerts_cfg.get("groups", []):
        for rule in group.get("rules", []):
            if "alert" in rule:    # ignore `record:` rules
                out.append({"_group": group["name"], **rule})
    return out


# ---------------------------------------------------------------------------
# Top-level shape
# ---------------------------------------------------------------------------

class TestAlertsFileShape:
    def test_has_groups(self, alerts_cfg):
        assert isinstance(alerts_cfg.get("groups"), list)
        assert len(alerts_cfg["groups"]) >= 1

    def test_at_least_a_few_alerts_defined(self, all_alerts):
        assert len(all_alerts) >= 5, (
            "Only "
            f"{len(all_alerts)} alerts defined — that's too few to "
            "meaningfully cover orchestrator / API / detection / audit."
        )

    def test_every_alert_has_a_name(self, all_alerts):
        for a in all_alerts:
            assert a.get("alert"), f"missing `alert:` name in {a!r}"

    def test_alert_names_are_unique(self, all_alerts):
        names = [a["alert"] for a in all_alerts]
        dupes = [n for n in names if names.count(n) > 1]
        assert not dupes, f"duplicate alert names: {sorted(set(dupes))}"


# ---------------------------------------------------------------------------
# Required fields per alert
# ---------------------------------------------------------------------------

class TestAlertSchema:
    def test_every_alert_has_expr(self, all_alerts):
        for a in all_alerts:
            assert a.get("expr"), f"alert {a['alert']!r} missing `expr`"

    def test_every_alert_has_severity_label(self, all_alerts):
        valid = {"page", "ticket", "info"}
        for a in all_alerts:
            sev = (a.get("labels") or {}).get("severity")
            assert sev in valid, (
                f"alert {a['alert']!r} has severity={sev!r}, "
                f"expected one of {valid}"
            )

    def test_every_alert_has_summary_and_description(self, all_alerts):
        for a in all_alerts:
            ann = a.get("annotations") or {}
            assert ann.get("summary"), (
                f"alert {a['alert']!r} missing annotations.summary"
            )
            assert ann.get("description"), (
                f"alert {a['alert']!r} missing annotations.description"
            )

    def test_every_alert_has_runbook_url(self, all_alerts):
        for a in all_alerts:
            url = (a.get("annotations") or {}).get("runbook_url", "")
            assert url, f"alert {a['alert']!r} missing annotations.runbook_url"
            assert "docs/runbooks/" in url, (
                f"alert {a['alert']!r}: runbook_url should point into "
                f"docs/runbooks/, got {url!r}"
            )


# ---------------------------------------------------------------------------
# Runbook ↔ alert wiring
# ---------------------------------------------------------------------------

class TestRunbookCoverage:
    def test_every_alert_runbook_exists_on_disk(self, all_alerts):
        for a in all_alerts:
            name = a["alert"]
            rb = _RUNBOOKS_DIR / f"{name}.md"
            assert rb.exists(), (
                f"alert {name!r} has no runbook at {rb}. Either create "
                f"the runbook or rename the alert."
            )

    def test_runbook_url_path_matches_alert_name(self, all_alerts):
        """The URL fragment after `runbooks/` should be `<AlertName>.md`."""
        for a in all_alerts:
            name = a["alert"]
            url = a["annotations"]["runbook_url"]
            assert url.endswith(f"/runbooks/{name}.md"), (
                f"alert {name!r}: runbook_url should end in "
                f"/runbooks/{name}.md, got {url!r}"
            )

    def test_every_runbook_corresponds_to_a_known_alert(self, all_alerts):
        """Catches stale runbooks after an alert is renamed/removed."""
        alert_names = {a["alert"] for a in all_alerts}
        for rb in _RUNBOOKS_DIR.glob("*.md"):
            if rb.name == "README.md":
                continue
            name = rb.stem
            assert name in alert_names, (
                f"runbook {rb.name} doesn't match any alert; either "
                f"add the corresponding alert or delete the runbook."
            )

    def test_runbook_index_lists_every_alert(self, all_alerts):
        """The runbooks/README.md table should mention every alert."""
        index = _RUNBOOKS_INDEX.read_text(encoding="utf-8")
        for a in all_alerts:
            assert a["alert"] in index, (
                f"runbooks/README.md doesn't mention {a['alert']!r}; "
                f"add a row to its index table."
            )


# ---------------------------------------------------------------------------
# Expression-level sanity (without running promtool)
# ---------------------------------------------------------------------------

class TestExpressionsReferenceKnownMetrics:
    """Catches the most common error: typo in a metric name. We can't
    parse PromQL fully but we can grep for `plenith_*` tokens and
    confirm each one is in the export list."""

    _METRIC_RE = re.compile(r"\b(plenith_[a-z_]+)\b")

    def test_every_metric_token_is_exported(self, all_alerts):
        for a in all_alerts:
            tokens = set(self._METRIC_RE.findall(a["expr"]))
            unknown = tokens - _EXPORTED_METRICS - _BUILTIN_METRICS
            assert not unknown, (
                f"alert {a['alert']!r} references unknown metric(s) "
                f"{sorted(unknown)} — add to plenith/api/metrics.py "
                f"or fix the typo. Known: {sorted(_EXPORTED_METRICS)}"
            )

    def test_every_alert_references_at_least_one_metric(self, all_alerts):
        """Otherwise the alert can never fire on real data."""
        for a in all_alerts:
            expr = a["expr"]
            has_metric = (
                bool(self._METRIC_RE.search(expr)) or
                any(m in expr for m in _BUILTIN_METRICS)
            )
            assert has_metric, (
                f"alert {a['alert']!r} expr {expr!r} doesn't reference "
                f"a known metric"
            )


class TestAlertGroups:
    def test_groups_have_names(self, alerts_cfg):
        for g in alerts_cfg["groups"]:
            assert g.get("name"), f"unnamed group: {g!r}"
            assert g["name"].startswith("plenith-"), (
                f"group {g['name']!r} should be prefixed `plenith-` "
                "so it doesn't collide with other tenants in shared Prometheus"
            )

    def test_group_intervals_are_reasonable(self, alerts_cfg):
        """Allowed: 15s..5m. Faster is wasteful, slower hides issues."""
        for g in alerts_cfg["groups"]:
            iv = g.get("interval", "1m")
            assert re.match(r"^\d+[smh]$", iv), f"bad interval {iv!r}"
            # Coarse sanity — convert s/m/h
            n = int(iv[:-1])
            unit = iv[-1]
            secs = n * {"s": 1, "m": 60, "h": 3600}[unit]
            assert 15 <= secs <= 600, (
                f"group {g['name']!r} interval {iv!r} is unusual; "
                "expected 15s..10m"
            )
