"""Tests for retention enforcement (plenith/retention.py + CLI).

Covers:
  - `RetentionPolicy.from_config` honors overrides and rejects nonsense
  - `build_plan` correctly identifies aged-out files per category and
    leaves fresh files alone
  - `apply_plan(dry_run=True)` doesn't touch disk
  - `apply_plan(dry_run=False)` deletes precisely the planned files
  - Filter predicate scopes a DSR-style purge
  - CLI exit codes: 0 clean / 1 deletion failures / 2 bad args /
    3 refused for safety
  - CLI safety interlock: --filter + --apply requires --confirm
  - Failure isolation: an undeletable file is reported, others still go
"""
from __future__ import annotations

import importlib.util
import json
import os
import time
from pathlib import Path
from unittest import mock

import pytest

from plenith.retention import (
    DEFAULT_WINDOWS,
    CategorySpec,
    RetentionPolicy,
    apply_plan,
    build_plan,
    purge,
)


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def _touch(path: Path, *, age_days: float, content: str = "{}"):
    """Create a file with mtime in the past."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    past = time.time() - (age_days * 86400.0)
    os.utime(path, (past, past))
    return path


def _make_layout(root: Path):
    """Spread a few engagement / persistence / heartbeat files across
    multiple ages."""
    layout = {
        # Engagement logs — under state-docker/logs/<host>/
        "state-docker/logs/bastion-prod/old1.json":     180,
        "state-docker/logs/bastion-prod/old2.json":     100,
        "state-docker/logs/bastion-prod/recent.json":    10,
        "state-docker/logs/db-prod/older.json":         200,
        # Persistence state — under state-docker/persistence/ (non-recursive)
        "state-docker/persistence/old.json":            300,
        "state-docker/persistence/recent.json":          30,
        # Heartbeats — own (shorter) window
        "state-docker/persistence/heartbeats/old.json":  60,
        "state-docker/persistence/heartbeats/fresh.json": 1,
        # Cache files (non-recursive)
        "caches/default_responses.yaml":                200,
        "caches/fresh.yaml":                              5,
    }
    for rel, age in layout.items():
        _touch(root / rel, age_days=age, content=json.dumps({"x": 1}))
    return layout


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

class TestPolicy:
    def test_defaults_match_data_handling_doc(self):
        p = RetentionPolicy()
        for k, v in DEFAULT_WINDOWS.items():
            assert p.days_for(k) == v

    def test_from_config_overrides(self):
        p = RetentionPolicy.from_config({
            "engagements_days": 60,
            "ioc_days":         180,
        })
        assert p.days_for("engagements") == 60
        assert p.days_for("ioc_archive") == 180
        # Untouched fields stay at default
        assert p.days_for("heartbeats") == DEFAULT_WINDOWS["heartbeats"]

    def test_from_config_accepts_short_keys(self):
        """`engagements: 30` works as well as `engagements_days: 30`."""
        p = RetentionPolicy.from_config({"engagements": 30})
        assert p.days_for("engagements") == 30

    def test_from_config_rejects_negative(self):
        with pytest.raises(ValueError, match="non-negative"):
            RetentionPolicy.from_config({"engagements_days": -5})

    def test_unknown_category_raises(self):
        p = RetentionPolicy()
        with pytest.raises(KeyError):
            p.days_for("not_a_real_category")

    def test_seconds_for(self):
        p = RetentionPolicy()
        assert p.seconds_for("engagements") == DEFAULT_WINDOWS["engagements"] * 86400


# ---------------------------------------------------------------------------
# build_plan
# ---------------------------------------------------------------------------

class TestBuildPlan:
    def test_plans_oldest_engagement_files(self, tmp_path):
        _make_layout(tmp_path)
        policy = RetentionPolicy()    # defaults: engagements=90
        plan = build_plan(root=tmp_path, policy=policy)
        eng = plan.by_category["engagements"]
        # old1.json (180d) and older.json (200d) cross 90d
        # old2.json (100d) crosses too; recent.json (10d) does not
        paths = {Path(e.path).name for e in eng.to_delete}
        assert paths == {"old1.json", "old2.json", "older.json"}
        # recent.json kept
        assert eng.kept == 1

    def test_heartbeats_have_shorter_window(self, tmp_path):
        _make_layout(tmp_path)
        policy = RetentionPolicy()    # heartbeats=7
        plan = build_plan(root=tmp_path, policy=policy)
        hb = plan.by_category["heartbeats"]
        names = {Path(e.path).name for e in hb.to_delete}
        # old.json (60d > 7d) goes; fresh.json (1d) stays
        assert names == {"old.json"}
        assert hb.kept == 1

    def test_persistence_not_recursive_into_heartbeats(self, tmp_path):
        """The persistence/ spec must NOT scoop heartbeats/, which has
        its own (shorter) policy. Otherwise we'd delete heartbeats on
        the persistence schedule."""
        _make_layout(tmp_path)
        policy = RetentionPolicy()
        plan = build_plan(root=tmp_path, policy=policy)
        persistence = plan.by_category["persistence"]
        for entry in persistence.to_delete:
            # Heartbeats live at state-docker/persistence/heartbeats/
            assert "heartbeats" not in entry.path.parts

    def test_missing_root_flagged(self, tmp_path):
        policy = RetentionPolicy()
        plan = build_plan(root=tmp_path, policy=policy)
        # Nothing exists yet → every category is missing_root and empty
        for cp in plan.by_category.values():
            assert cp.missing_root is True
            assert len(cp.to_delete) == 0

    def test_filter_predicate_narrows_scope(self, tmp_path):
        """A predicate restricts deletion to matching content."""
        _make_layout(tmp_path)
        # Rewrite one old engagement log to carry a specific source_ip
        target = tmp_path / "state-docker/logs/bastion-prod/old1.json"
        target.write_text(json.dumps({"source_ip": "203.0.113.7"}),
                          encoding="utf-8")
        past = time.time() - 180 * 86400.0
        os.utime(target, (past, past))

        def only_that_ip(path, parsed):
            return parsed.get("source_ip") == "203.0.113.7"

        policy = RetentionPolicy()
        plan = build_plan(root=tmp_path, policy=policy,
                          filter_predicate=only_that_ip)
        eng = plan.by_category["engagements"]
        paths = {Path(e.path).name for e in eng.to_delete}
        assert paths == {"old1.json"}    # only the matching file

    def test_now_override_is_respected(self, tmp_path):
        """With an explicit `now=0` (epoch 1970), no file is older than
        the window — nothing is deleted regardless of mtime."""
        _make_layout(tmp_path)
        plan = build_plan(root=tmp_path, policy=RetentionPolicy(), now=0)
        for cp in plan.by_category.values():
            assert len(cp.to_delete) == 0


# ---------------------------------------------------------------------------
# apply_plan
# ---------------------------------------------------------------------------

class TestApplyPlan:
    def test_dry_run_does_not_delete(self, tmp_path):
        _make_layout(tmp_path)
        before = set(p for p in tmp_path.rglob("*") if p.is_file())
        plan = build_plan(root=tmp_path, policy=RetentionPolicy())
        res = apply_plan(plan, dry_run=True)
        after = set(p for p in tmp_path.rglob("*") if p.is_file())
        assert before == after
        # But the result still reports what WOULD have happened
        assert res.deleted == plan.total_files

    def test_apply_actually_deletes(self, tmp_path):
        _make_layout(tmp_path)
        plan = build_plan(root=tmp_path, policy=RetentionPolicy())
        targets = [e.path for cp in plan.by_category.values()
                          for e in cp.to_delete]
        res = apply_plan(plan, dry_run=False)
        for t in targets:
            assert not t.exists(), f"{t} should have been deleted"
        assert res.deleted == len(targets)
        assert res.failed == 0

    def test_partial_failure_isolated(self, tmp_path):
        """If one delete fails, the rest still proceed."""
        _make_layout(tmp_path)
        plan = build_plan(root=tmp_path, policy=RetentionPolicy())
        # Pick the first planned file and replace it with a path that
        # fakely raises on os.remove.
        targets = [e.path for cp in plan.by_category.values()
                          for e in cp.to_delete]
        assert len(targets) >= 2

        real_remove = os.remove
        boom = targets[0]

        def fake_remove(path):
            if Path(path) == boom:
                raise PermissionError("simulated")
            real_remove(path)

        with mock.patch("plenith.retention.os.remove",
                          side_effect=fake_remove):
            res = apply_plan(plan, dry_run=False)
        assert res.failed == 1
        assert res.deleted == len(targets) - 1
        # The protected file should still be on disk
        assert boom.exists()


# ---------------------------------------------------------------------------
# purge()
# ---------------------------------------------------------------------------

class TestPurge:
    def test_returns_serializable_summary(self, tmp_path):
        _make_layout(tmp_path)
        out = purge(root=tmp_path, dry_run=True)
        # Round-trip through JSON to confirm serialization
        roundtripped = json.loads(json.dumps(out))
        assert roundtripped["plan"]["total_files"] >= 1
        assert "engagements" in roundtripped["plan"]["categories"]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _load_cli():
    spec = importlib.util.spec_from_file_location(
        "retention_purge_cli",
        Path(__file__).resolve().parent.parent / "tools" / "retention_purge.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestCLI:
    def test_dry_run_default(self, tmp_path, capsys):
        _make_layout(tmp_path)
        cli = _load_cli()
        rc = cli.main(["--root", str(tmp_path), "--json"])
        out = json.loads(capsys.readouterr().out)
        assert rc == cli.EXIT_OK
        assert out["dry_run"] is True
        # Files still exist
        assert (tmp_path / "state-docker/logs/bastion-prod/old1.json").exists()

    def test_apply_deletes(self, tmp_path, capsys):
        _make_layout(tmp_path)
        cli = _load_cli()
        rc = cli.main(["--root", str(tmp_path), "--apply", "--json"])
        out = json.loads(capsys.readouterr().out)
        assert rc == cli.EXIT_OK
        assert out["dry_run"] is False
        assert not (tmp_path / "state-docker/logs/bastion-prod/old1.json").exists()
        # Recent files still here
        assert (tmp_path / "state-docker/logs/bastion-prod/recent.json").exists()

    def test_filter_requires_confirm_when_applying(self, tmp_path, capsys):
        """Critical safety interlock: DSR purge without confirm is refused."""
        _make_layout(tmp_path)
        cli = _load_cli()
        rc = cli.main([
            "--root", str(tmp_path),
            "--apply",
            "--filter", "source_ip=203.0.113.7",
            "--json",
        ])
        out = json.loads(capsys.readouterr().out)
        assert rc == cli.EXIT_REFUSED
        assert "confirm" in out["error"]

    def test_filter_applied_with_confirm(self, tmp_path, capsys):
        _make_layout(tmp_path)
        # Stamp one engagement log with a specific source_ip
        target = tmp_path / "state-docker/logs/bastion-prod/old1.json"
        target.write_text(json.dumps({"source_ip": "203.0.113.7"}),
                          encoding="utf-8")
        past = time.time() - 180 * 86400.0
        os.utime(target, (past, past))
        # And another (matching policy age, different IP) that should NOT be hit
        other = tmp_path / "state-docker/logs/bastion-prod/old2.json"
        other.write_text(json.dumps({"source_ip": "10.0.0.1"}),
                         encoding="utf-8")
        os.utime(other, (past, past))

        cli = _load_cli()
        rc = cli.main([
            "--root", str(tmp_path),
            "--apply", "--confirm",
            "--filter", "source_ip=203.0.113.7",
            "--json",
        ])
        out = json.loads(capsys.readouterr().out)
        assert rc == cli.EXIT_OK
        assert not target.exists()
        # Other engagement with different IP NOT removed by the filter
        assert other.exists()

    def test_cli_override_days(self, tmp_path, capsys):
        _make_layout(tmp_path)
        cli = _load_cli()
        # Set engagements to 5 days — now everything > 5d ages out
        rc = cli.main([
            "--root", str(tmp_path),
            "--engagements-days", "5",
            "--json",
        ])
        out = json.loads(capsys.readouterr().out)
        assert rc == cli.EXIT_OK
        eng = out["plan"]["categories"]["engagements"]
        # All 4 engagement files are > 5d → all 4 should be planned for delete
        assert eng["delete_count"] == 4

    def test_bad_config_path_returns_2(self, tmp_path, capsys):
        """If --config points at malformed YAML, we exit with EXIT_BAD_ARGS."""
        bad = tmp_path / "bad.yaml"
        bad.write_text(":\nnot valid yaml: [\n", encoding="utf-8")
        cli = _load_cli()
        rc = cli.main([
            "--root", str(tmp_path),
            "--config", str(bad),
            "--json",
        ])
        assert rc == cli.EXIT_BAD_ARGS

    def test_human_table_output(self, tmp_path, capsys):
        _make_layout(tmp_path)
        cli = _load_cli()
        rc = cli.main(["--root", str(tmp_path)])    # no --json
        out = capsys.readouterr().out
        assert rc == cli.EXIT_OK
        assert "CATEGORY" in out
        assert "engagements" in out
        assert "DRY-RUN" in out
