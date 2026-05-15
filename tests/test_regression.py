"""Regression tests against captured engagement fixtures.

Each fixture is a `(state/, logs/)` pair captured from a real attacker
session. We assert that the audit tool's summary line for each fixture
matches the expected narrative. Catches regressions in:
  - IoC extraction logic (C2 endpoints, exfil domains)
  - Narrative builder (severity badge, fragment ordering, count formatting)
  - Alert deduplication across multiple connection logs
  - Persona-aware diff computation
"""
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

# Load audit.py as a module so we can call its functions directly.
_ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("audit_mod", _ROOT / "tools" / "audit.py")
audit = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(audit)

_CORPUS_DIR = Path(__file__).resolve().parent / "fixtures" / "regression-corpus"
_FIXTURES = sorted(p for p in _CORPUS_DIR.iterdir() if p.is_dir())

def _load_fixture_engagements(fixture_dir):
    state_dir = fixture_dir / "state"
    logs_dir = fixture_dir / "logs"
    personas_dir = _ROOT / "personas"
    return audit.load_engagements(state_dir, logs_dir, personas_dir)

def _strip_ansi(s):
    return re.sub(r"\033\[[0-9;]*m", "", s)

@pytest.mark.parametrize("fixture_path", _FIXTURES, ids=lambda p: p.name)
class TestRegressionCorpus:
    """One parametrized test class per fixture directory under
    tests/fixtures/regression-corpus/. Each fixture must contain an
    `expected.json` describing what audit should produce."""

    def test_engagement_loads(self, fixture_path):
        eng = _load_fixture_engagements(fixture_path)
        assert len(eng) >= 1, f"no engagement loaded from {fixture_path.name}"

    def test_summary_narrative_includes_expected_fragments(self, fixture_path):
        expected_file = fixture_path / "expected.json"
        if not expected_file.exists():
            pytest.skip(f"{fixture_path.name} has no expected.json")
        expected = json.loads(expected_file.read_text(encoding="utf-8"))
        engagements = _load_fixture_engagements(fixture_path)
        # Locate the engagement by expected.engagement_id_prefix
        prefix = expected["engagement_id_prefix"]
        matches = [e for e in engagements if e["engagement_id"].startswith(prefix)]
        assert len(matches) == 1, f"expected exactly 1 match for prefix {prefix}"
        narrative = _strip_ansi(audit.build_narrative(matches[0]))

        # Every required fragment must appear
        for frag in expected.get("required_fragments", []):
            assert frag in narrative, (
                f"fixture={fixture_path.name} missing fragment {frag!r} in narrative:\n  {narrative}"
            )
        # No forbidden fragments
        for frag in expected.get("forbidden_fragments", []):
            assert frag not in narrative, (
                f"fixture={fixture_path.name} contains forbidden fragment {frag!r}"
            )

    def test_ioc_export_extracts_expected(self, fixture_path):
        expected_file = fixture_path / "expected.json"
        if not expected_file.exists():
            pytest.skip(f"{fixture_path.name} has no expected.json")
        expected = json.loads(expected_file.read_text(encoding="utf-8"))
        if "ioc_assertions" not in expected:
            pytest.skip("fixture has no ioc_assertions")
        engagements = _load_fixture_engagements(fixture_path)
        prefix = expected["engagement_id_prefix"]
        eng = next(e for e in engagements if e["engagement_id"].startswith(prefix))
        ioc = json.loads(audit.export_ioc(eng))

        for key, exp_val in expected["ioc_assertions"].items():
            actual = ioc.get(key)
            if isinstance(exp_val, list):
                if exp_val and isinstance(exp_val[0], str):
                    # Compare against a flattened set of strings — if `actual`
                    # is a list of dicts, search across their values.
                    if actual and isinstance(actual[0], dict):
                        flat = {v for d in actual for v in d.values() if isinstance(v, str)}
                    else:
                        flat = set(actual or [])
                    for item in exp_val:
                        assert item in flat, (
                            f"expected {item!r} in ioc[{key!r}], got {actual!r}"
                        )
                else:
                    # List of objects (e.g. c2_endpoints) — each expected dict
                    # must be a subset of some actual entry.
                    for exp_item in exp_val:
                        assert any(
                            all(a.get(k) == v for k, v in exp_item.items())
                            for a in actual
                        ), f"expected {exp_item} in ioc[{key!r}], got {actual}"
            else:
                assert actual == exp_val, f"ioc[{key!r}] = {actual!r}, expected {exp_val!r}"

    def test_alert_count_by_severity(self, fixture_path):
        expected_file = fixture_path / "expected.json"
        if not expected_file.exists():
            pytest.skip(f"{fixture_path.name} has no expected.json")
        expected = json.loads(expected_file.read_text(encoding="utf-8"))
        if "alert_counts" not in expected:
            pytest.skip("fixture has no alert_counts")
        engagements = _load_fixture_engagements(fixture_path)
        prefix = expected["engagement_id_prefix"]
        eng = next(e for e in engagements if e["engagement_id"].startswith(prefix))
        counts = audit.count_alerts(eng["logs"])
        for sev, expected_n in expected["alert_counts"].items():
            assert counts.get(sev, 0) == expected_n, (
                f"fixture={fixture_path.name} severity={sev}: expected {expected_n}, got {counts.get(sev, 0)}"
            )
