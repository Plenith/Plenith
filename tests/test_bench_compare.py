"""Tests for the perf-baseline comparator in tools/bench.py.

We exercise compare() against synthetic baseline + current bench
summaries — no live SSH server needed. Verifies:
  - regression detection at the configured tolerance %
  - improvement detection (no false positives)
  - missing-source-in-current is treated as a no-op (don't fail on
    workload-shape changes)
  - throughput direction (higher = better) is handled correctly
  - the shipped state/bench/baseline.json parses and the comparator
    accepts it cleanly
"""
import json
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "tools"))

import bench

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def baseline():
    return {
        "_meta": {
            "tolerances": {
                "p50_regression_pct":   25,
                "p95_regression_pct":   30,
                "p99_regression_pct":   50,
                "throughput_drop_pct":  20,
            },
        },
        "throughput_cmds_per_sec": 10.0,
        "by_source": {
            "cache":     {"p50_ms": 4.0, "p95_ms": 12.0, "p99_ms": 25.0},
            "llm":       {"p50_ms": 800.0, "p95_ms": 2000.0, "p99_ms": 3000.0},
            "vfs-read":  {"p50_ms": 8.0, "p95_ms": 22.0, "p99_ms": 40.0},
        },
    }

@pytest.fixture
def current_clean():
    """A bench result that's identical to baseline — no regression."""
    return {
        "throughput_cmds_per_sec": 10.0,
        "by_source": {
            "cache":     {"p50_ms": 4.0, "p95_ms": 12.0, "p99_ms": 25.0},
            "llm":       {"p50_ms": 800.0, "p95_ms": 2000.0, "p99_ms": 3000.0},
            "vfs-read":  {"p50_ms": 8.0, "p95_ms": 22.0, "p99_ms": 40.0},
        },
    }

# ---------------------------------------------------------------------------
# Identical → pass
# ---------------------------------------------------------------------------

class TestCleanCompare:
    def test_identical_passes(self, baseline, current_clean):
        report = bench.compare(current_clean, baseline)
        assert report["passed"] is True
        assert report["regressions"] == []

    def test_slight_noise_within_tolerance_passes(self, baseline):
        """5% latency increase should be well within tolerances."""
        current = {
            "throughput_cmds_per_sec": 9.5,
            "by_source": {
                "cache":    {"p50_ms": 4.2, "p95_ms": 12.5, "p99_ms": 26.0},
                "llm":      {"p50_ms": 840.0, "p95_ms": 2050.0, "p99_ms": 3050.0},
                "vfs-read": {"p50_ms": 8.4, "p95_ms": 22.8, "p99_ms": 41.0},
            },
        }
        report = bench.compare(current, baseline)
        assert report["passed"] is True

# ---------------------------------------------------------------------------
# Regression detection
# ---------------------------------------------------------------------------

class TestRegressionDetection:
    def test_p50_regression_caught(self, baseline):
        """cache p50 doubles → 100% delta vs 25% tolerance → fail."""
        current = {
            "throughput_cmds_per_sec": 10.0,
            "by_source": {
                "cache":     {"p50_ms": 8.0, "p95_ms": 12.0, "p99_ms": 25.0},
                "llm":       {"p50_ms": 800.0, "p95_ms": 2000.0, "p99_ms": 3000.0},
                "vfs-read":  {"p50_ms": 8.0, "p95_ms": 22.0, "p99_ms": 40.0},
            },
        }
        report = bench.compare(current, baseline)
        assert report["passed"] is False
        cache_reg = [r for r in report["regressions"]
                     if r["source"] == "cache" and r["metric"] == "p50_ms"]
        assert cache_reg, "expected cache p50 regression to be flagged"
        assert cache_reg[0]["delta_pct"] == 100.0

    def test_throughput_drop_caught(self, baseline):
        """Throughput halving → 50% drop vs 20% tolerance → fail."""
        current = {
            "throughput_cmds_per_sec": 5.0,
            "by_source": baseline["by_source"],
        }
        report = bench.compare(current, baseline)
        assert report["passed"] is False
        tp_reg = [r for r in report["regressions"]
                  if r["metric"] == "throughput_cmds_per_sec"]
        assert tp_reg
        # Throughput delta is negative (we dropped); regress_pct is the inverse
        assert tp_reg[0]["delta_pct"] == -50.0

    def test_within_tolerance_not_a_regression(self, baseline):
        """20% p50 bump on cache is JUST under the 25% tolerance → pass."""
        current = {
            "throughput_cmds_per_sec": 10.0,
            "by_source": {
                "cache":     {"p50_ms": 4.8, "p95_ms": 12.0, "p99_ms": 25.0},
                "llm":       {"p50_ms": 800.0, "p95_ms": 2000.0, "p99_ms": 3000.0},
                "vfs-read":  {"p50_ms": 8.0, "p95_ms": 22.0, "p99_ms": 40.0},
            },
        }
        report = bench.compare(current, baseline)
        assert report["passed"] is True

    def test_multiple_regressions_all_reported(self, baseline):
        """Three sources all regress → all three flagged, not just first."""
        current = {
            "throughput_cmds_per_sec": 10.0,
            "by_source": {
                "cache":     {"p50_ms": 20.0, "p95_ms": 60.0, "p99_ms": 100.0},
                "llm":       {"p50_ms": 2000.0, "p95_ms": 5000.0, "p99_ms": 8000.0},
                "vfs-read":  {"p50_ms": 40.0, "p95_ms": 100.0, "p99_ms": 200.0},
            },
        }
        report = bench.compare(current, baseline)
        assert report["passed"] is False
        sources = {r["source"] for r in report["regressions"]}
        assert {"cache", "llm", "vfs-read"}.issubset(sources)

# ---------------------------------------------------------------------------
# Improvement detection
# ---------------------------------------------------------------------------

class TestImprovementDetection:
    def test_faster_is_an_improvement(self, baseline):
        current = {
            "throughput_cmds_per_sec": 15.0,
            "by_source": {
                "cache":     {"p50_ms": 2.0, "p95_ms": 6.0, "p99_ms": 12.0},
                "llm":       {"p50_ms": 400.0, "p95_ms": 1000.0, "p99_ms": 1500.0},
                "vfs-read":  {"p50_ms": 4.0, "p95_ms": 11.0, "p99_ms": 20.0},
            },
        }
        report = bench.compare(current, baseline)
        assert report["passed"] is True
        assert report["improvements"]
        cache_imp = [i for i in report["improvements"]
                     if i["source"] == "cache"]
        assert cache_imp

# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_missing_source_in_current_skipped(self, baseline):
        """If 'vfs-read' isn't in the current run, don't fail on it."""
        current = {
            "throughput_cmds_per_sec": 10.0,
            "by_source": {
                "cache": {"p50_ms": 4.0, "p95_ms": 12.0, "p99_ms": 25.0},
            },
        }
        report = bench.compare(current, baseline)
        assert report["passed"] is True

    def test_missing_baseline_metric_skipped(self):
        """If baseline doesn't have p99_ms for some source, don't crash."""
        baseline = {
            "throughput_cmds_per_sec": 10.0,
            "by_source": {"cache": {"p50_ms": 4.0}},   # only p50
        }
        current = {
            "throughput_cmds_per_sec": 10.0,
            "by_source": {"cache": {"p50_ms": 5.0, "p95_ms": 15.0, "p99_ms": 30.0}},
        }
        report = bench.compare(current, baseline)
        # Should not raise; the missing p95/p99 in baseline = skip
        assert "passed" in report

    def test_zero_baseline_skipped(self):
        """Division-by-zero guard."""
        baseline = {
            "throughput_cmds_per_sec": 0,
            "by_source": {"cache": {"p50_ms": 0, "p95_ms": 0, "p99_ms": 0}},
        }
        current = {
            "throughput_cmds_per_sec": 10.0,
            "by_source": {"cache": {"p50_ms": 5.0, "p95_ms": 15.0, "p99_ms": 30.0}},
        }
        # Should not crash on division by zero
        report = bench.compare(current, baseline)
        assert "passed" in report

    def test_uses_baseline_meta_tolerances(self):
        """Tolerances from `_meta.tolerances` override defaults."""
        baseline = {
            "_meta": {"tolerances": {
                "p50_regression_pct":  100,  # very generous
                "p95_regression_pct":  100,
                "p99_regression_pct":  100,
                "throughput_drop_pct": 100,
            }},
            "throughput_cmds_per_sec": 10,
            "by_source": {"cache": {"p50_ms": 4.0, "p95_ms": 12.0, "p99_ms": 25.0}},
        }
        # 50% p50 regression would fail default 25% tolerance, but baseline
        # ups it to 100% so it passes
        current = {
            "throughput_cmds_per_sec": 10,
            "by_source": {"cache": {"p50_ms": 6.0, "p95_ms": 12.0, "p99_ms": 25.0}},
        }
        report = bench.compare(current, baseline)
        assert report["passed"] is True

    def test_shipped_baseline_parses(self):
        """The state/bench/baseline.json file we committed should be valid."""
        path = _ROOT / "state" / "bench" / "baseline.json"
        assert path.exists()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert "by_source" in data
        assert "_meta" in data
        # Use compare() with itself as both args — should always pass
        report = bench.compare(data, data)
        assert report["passed"] is True

# ---------------------------------------------------------------------------
# Renderer
# ---------------------------------------------------------------------------

class TestRenderComparison:
    def test_pass_message(self, baseline, current_clean):
        report = bench.compare(current_clean, baseline)
        text = bench.render_comparison(report)
        assert "PASS" in text

    def test_regression_message_lists_them(self, baseline):
        current = {
            "throughput_cmds_per_sec": 10.0,
            "by_source": {
                "cache":     {"p50_ms": 20.0, "p95_ms": 60.0, "p99_ms": 100.0},
                "llm":       baseline["by_source"]["llm"],
                "vfs-read":  baseline["by_source"]["vfs-read"],
            },
        }
        report = bench.compare(current, baseline)
        text = bench.render_comparison(report)
        assert "REGRESSION" in text
        assert "cache" in text
