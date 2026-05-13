"""Tests for the §13 operational runbook generators.

We exercise:
  - Context resolution from config (deployment_id, RTO/RPO, on-call,
    retention horizons).
  - Each runbook renders Markdown with the expected sections.
  - Templated values flow through (e.g. config-set RTO appears in DR
    runbook).
  - CLI smoke (render single + all).
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest

from plenith.compliance import runbooks


_ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Context resolution
# ---------------------------------------------------------------------------

class TestRunbookContext:
    def test_defaults(self):
        ctx = runbooks.RunbookContext()
        assert ctx.deployment_id == "unknown-deployment"
        assert ctx.rto_minutes == 60
        assert ctx.rpo_minutes == 15

    def test_build_from_empty_config(self):
        ctx = runbooks.build_context_from_config(None)
        assert ctx.deployment_id == "unknown-deployment"

    def test_build_from_real_config(self):
        cfg = {
            "content": {"deployment_id": "real-prod-id", "epoch": "2026Q3"},
            "operations": {
                "rto_minutes":  30,
                "rpo_minutes":  5,
                "backup_location": "/backups/special/",
                "max_concurrent_sessions": 100,
                "oncall": {
                    "soc_tier1": "soc1@example.test",
                    "soc_tier2": "soc2@example.test",
                    "ciso":      "ciso@example.test",
                },
                "retention": {
                    "logs_days":        180,
                    "iocs_days":        730,
                    "engagements_days": 180,
                },
            },
        }
        ctx = runbooks.build_context_from_config(cfg)
        assert ctx.deployment_id == "real-prod-id"
        assert ctx.current_epoch == "2026Q3"
        assert ctx.rto_minutes == 30
        assert ctx.rpo_minutes == 5
        assert ctx.backup_location == "/backups/special/"
        assert ctx.max_concurrent_sessions == 100
        assert ctx.soc_tier1_oncall == "soc1@example.test"
        assert ctx.ciso_oncall == "ciso@example.test"
        assert ctx.retention_iocs_days == 730

    def test_env_var_override_for_deployment_id(self, monkeypatch):
        monkeypatch.setenv("MC_DEPLOY_TEST", "env-deployment-99")
        cfg = {"content": {"env_var": "MC_DEPLOY_TEST"}}
        ctx = runbooks.build_context_from_config(cfg)
        assert ctx.deployment_id == "env-deployment-99"


# ---------------------------------------------------------------------------
# Per-runbook rendering
# ---------------------------------------------------------------------------

class TestRenderRetention:
    def test_includes_class_table(self):
        ctx = runbooks.RunbookContext()
        md = runbooks.retention_runbook(ctx)
        assert "Classification levels" in md
        assert "Decoy artifacts" in md
        assert "Engagement state" in md
        assert "Attacker IoCs" in md

    def test_retention_horizons_propagate(self):
        ctx = runbooks.RunbookContext(retention_logs_days=42,
                                       retention_iocs_days=1234)
        md = runbooks.retention_runbook(ctx)
        assert "42" in md
        assert "1234" in md


class TestRenderRACI:
    def test_includes_phase_matrix(self):
        ctx = runbooks.RunbookContext()
        md = runbooks.ir_raci_runbook(ctx)
        assert "RACI" in md
        assert "SOC Tier 1" in md
        assert "Lessons learned" in md

    def test_oncall_emails_propagate(self):
        ctx = runbooks.RunbookContext(
            soc_tier1_oncall="custom1@x", ciso_oncall="customc@x")
        md = runbooks.ir_raci_runbook(ctx)
        assert "custom1@x" in md
        assert "customc@x" in md


class TestRenderBurndown:
    def test_includes_kill_switch_section(self):
        md = runbooks.burndown_runbook(runbooks.RunbookContext())
        assert "Kill-switch" in md or "kill switch" in md.lower()
        assert "default" in md.lower()
        assert "lessons-learned" in md.lower() or "lessons learned" in md.lower()

    def test_deployment_id_appears(self):
        ctx = runbooks.RunbookContext(deployment_id="my-prod-01")
        md = runbooks.burndown_runbook(ctx)
        assert "my-prod-01" in md


class TestRenderCapacity:
    def test_includes_resource_table(self):
        md = runbooks.capacity_runbook(runbooks.RunbookContext())
        assert "Resource budget" in md
        assert "concurrent sessions" in md.lower()

    def test_max_concurrent_propagates(self):
        ctx = runbooks.RunbookContext(max_concurrent_sessions=200)
        md = runbooks.capacity_runbook(ctx)
        assert "200" in md


class TestRenderRotation:
    def test_includes_procedure_steps(self):
        md = runbooks.rotation_runbook(runbooks.RunbookContext())
        assert "Step 1" in md or "tools/rotate_content.py" in md
        assert "Rollback" in md or "rollback" in md.lower()

    def test_current_epoch_propagates(self):
        ctx = runbooks.RunbookContext(current_epoch="2026Q4")
        md = runbooks.rotation_runbook(ctx)
        assert "2026Q4" in md


class TestRenderDR:
    def test_includes_rto_rpo_targets(self):
        md = runbooks.dr_runbook(runbooks.RunbookContext())
        assert "RTO" in md
        assert "RPO" in md
        assert "Scenario A" in md
        assert "Scenario B" in md
        assert "Scenario C" in md

    def test_rto_value_propagates(self):
        ctx = runbooks.RunbookContext(rto_minutes=15, rpo_minutes=5)
        md = runbooks.dr_runbook(ctx)
        assert "15" in md
        assert "5" in md


# ---------------------------------------------------------------------------
# render_all + bundle layout
# ---------------------------------------------------------------------------

class TestRenderAll:
    def test_render_all_returns_six_runbooks(self):
        out = runbooks.render_all(runbooks.RunbookContext())
        # Six §13 sections (data retention, RACI, burndown, capacity,
        # rotation, DR)
        assert len(out) == 6
        for name, body in out.items():
            assert name.endswith(".md")
            assert body.strip().startswith("#")   # markdown title


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

class TestRunbookCLI:
    def _run(self, *args):
        return subprocess.run(
            [sys.executable, str(_ROOT / "tools" / "runbook.py"), *args],
            capture_output=True, text=True, timeout=30, encoding="utf-8",
        )

    def test_no_args_lists_runbooks(self):
        out = self._run()
        assert out.returncode == 0
        assert "retention" in out.stdout
        assert "dr" in out.stdout

    def test_single_runbook_to_stdout(self):
        out = self._run("dr")
        assert out.returncode == 0
        assert "Disaster Recovery" in out.stdout

    def test_all_to_directory(self, tmp_path):
        out = self._run("all", "--out", str(tmp_path))
        assert out.returncode == 0
        files = sorted(p.name for p in tmp_path.glob("*.md"))
        assert len(files) == 6
        # Each file is non-trivial
        for f in files:
            assert (tmp_path / f).stat().st_size > 500
