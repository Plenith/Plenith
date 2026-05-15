"""Sanity tests for .github/dependabot.yml (item 15).

We can't validate against the official Dependabot schema without adding
a dep, but we CAN catch the common mistakes:

  - File not parseable as YAML (broken indentation, stray colons).
  - Wrong top-level shape (`version: 2`, `updates: [...]`).
  - An ecosystem we care about is missing (pip, github-actions, docker).
  - A directory we declared a `docker` update for doesn't exist on disk.
  - The schedule cadence isn't one of the allowed values.

If Dependabot pushes a schema change later, these tests are the canary.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

_ROOT = Path(__file__).resolve().parent.parent
_CONFIG = _ROOT / ".github" / "dependabot.yml"

@pytest.fixture(scope="module")
def cfg():
    if not _CONFIG.exists():
        pytest.fail(
            "dependabot.yml is missing — without it, security CVEs in our "
            "dependencies will not surface as PRs. Add .github/dependabot.yml."
        )
    return yaml.safe_load(_CONFIG.read_text(encoding="utf-8"))

class TestStructure:
    def test_top_level_shape(self, cfg):
        assert cfg.get("version") == 2, "Dependabot v2 schema required"
        assert isinstance(cfg.get("updates"), list)
        assert len(cfg["updates"]) >= 3   # pip + actions + at least one docker

    def test_every_entry_has_required_fields(self, cfg):
        required = {"package-ecosystem", "directory", "schedule"}
        for i, entry in enumerate(cfg["updates"]):
            missing = required - set(entry.keys())
            assert not missing, (
                f"updates[{i}] missing {missing}: {entry!r}"
            )

    def test_schedules_use_valid_cadence(self, cfg):
        # Dependabot accepts daily / weekly / monthly. We use weekly.
        for i, entry in enumerate(cfg["updates"]):
            sched = entry["schedule"]
            assert sched["interval"] in {"daily", "weekly", "monthly"}, (
                f"updates[{i}].schedule.interval invalid: {sched['interval']!r}"
            )

class TestEcosystemCoverage:
    def test_pip_present(self, cfg):
        ecosystems = {e["package-ecosystem"] for e in cfg["updates"]}
        assert "pip" in ecosystems, (
            "pip ecosystem missing — requirements.txt won't get CVE PRs"
        )

    def test_github_actions_present(self, cfg):
        ecosystems = {e["package-ecosystem"] for e in cfg["updates"]}
        assert "github-actions" in ecosystems, (
            "github-actions ecosystem missing — CI workflow actions "
            "won't get version bumps"
        )

    def test_docker_present(self, cfg):
        ecosystems = {e["package-ecosystem"] for e in cfg["updates"]}
        assert "docker" in ecosystems, (
            "docker ecosystem missing — base-image CVEs (Ubuntu, python) "
            "won't surface as PRs"
        )

class TestDirectoriesResolve:
    def test_docker_directories_exist_on_disk(self, cfg):
        """Every docker ecosystem entry must point at a directory that
        actually contains a Dockerfile — otherwise the PR will fail to
        even open and the entry is dead config."""
        for i, entry in enumerate(cfg["updates"]):
            if entry["package-ecosystem"] != "docker":
                continue
            d = entry["directory"].lstrip("/")
            target = _ROOT / d
            assert target.exists(), (
                f"updates[{i}].directory points to {target} which doesn't exist"
            )
            dockerfiles = list(target.glob("Dockerfile*"))
            assert dockerfiles, (
                f"updates[{i}].directory has no Dockerfile under {target}"
            )

    def test_pip_directory_has_requirements_file(self, cfg):
        """pip ecosystem should point at a directory that contains a
        requirements*.txt or pyproject.toml."""
        for i, entry in enumerate(cfg["updates"]):
            if entry["package-ecosystem"] != "pip":
                continue
            d = entry["directory"].lstrip("/")
            target = _ROOT / d if d else _ROOT
            has_pip_manifest = (
                bool(list(target.glob("requirements*.txt"))) or
                (target / "pyproject.toml").exists() or
                (target / "setup.py").exists()
            )
            assert has_pip_manifest, (
                f"updates[{i}] pip ecosystem points to {target} but "
                "no requirements*.txt / pyproject.toml / setup.py found"
            )

class TestGroupingAndLimits:
    def test_pull_request_limits_are_sane(self, cfg):
        """Dependabot defaults to 5; floods of PRs annoy reviewers. We
        cap at 5 for pip and lower for narrower ecosystems."""
        for entry in cfg["updates"]:
            limit = entry.get("open-pull-requests-limit", 5)
            assert 1 <= limit <= 10, (
                f"open-pull-requests-limit {limit} for "
                f"{entry['package-ecosystem']} is unreasonable"
            )

    def test_groups_block_well_formed(self, cfg):
        """If `groups` is present, each group's update-types must be
        one of minor/patch/major (Dependabot rejects unknown values)."""
        valid_types = {"minor", "patch", "major"}
        for entry in cfg["updates"]:
            for group_name, group_cfg in (entry.get("groups") or {}).items():
                ut = group_cfg.get("update-types", [])
                bad = set(ut) - valid_types
                assert not bad, (
                    f"group {group_name!r}: invalid update-types {bad}"
                )
