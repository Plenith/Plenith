"""Validate the project-scaffolding files exist and contain the
sections downstream consumers expect.

We can't unit-test "the docs are good," but we CAN catch the common
failure modes:

  - LICENSE is missing entirely (the project would legally NOT be
    open-source).
  - CONTRIBUTING.md exists but doesn't tell you how to run the test
    suite.
  - CHANGELOG.md is missing the [Unreleased] header (Keep-a-Changelog
    consumers depend on it).
  - Issue template directory has no template files (silent UI failure
    on GitHub).
  - The pre-commit config + ruff config are present and load as valid
    YAML/TOML.
  - The compliance mapping references frameworks we actually cover.
  - MISSION.md keeps the open-source-forever promise + the 30%
    children's-development pledge (the mission MUST NOT silently
    weaken via a typo or an over-eager refactor).

These tests are the canary on "did someone delete or gut a load-
bearing project file?" rather than a substantive review of content
quality.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml


_ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# File presence
# ---------------------------------------------------------------------------

REQUIRED_TOP_LEVEL_FILES = [
    "LICENSE",
    "NOTICE",
    "README.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "MISSION.md",
    "SECURITY.md",
    "TRADEMARK.md",
    "COMMERCIAL.md",
    "GOVERNANCE.md",
    "MAINTAINERS.md",
    "ROADMAP.md",
]

REQUIRED_GITHUB_FILES = [
    ".github/PULL_REQUEST_TEMPLATE.md",
    ".github/ISSUE_TEMPLATE/bug_report.md",
    ".github/ISSUE_TEMPLATE/feature_request.md",
    ".github/ISSUE_TEMPLATE/config.yml",
    ".github/workflows/ci.yml",
    ".github/workflows/release.yml",
    ".github/dependabot.yml",
]

REQUIRED_DOCS = [
    "docs/QUICKSTART.md",
    "docs/THREAT_MODEL.md",
    "docs/HARDENING.md",
    "docs/DPIA.md",
    "docs/DATA_HANDLING.md",
    "docs/COMPLIANCE_MAPPING.md",
    "docs/SECRETS.md",
    "docs/PLUGINS.md",
    "docs/VERIFY_RELEASES.md",
    "docs/PRE_LAUNCH_CHECKLIST.md",
    "docs/IMPACT/README.md",
    "docs/IMPACT/_TEMPLATE.md",
    "docs/security-pgp.txt",
    "docs/DEPLOYMENT_GUIDE.md",
    "docs/FAQ.md",
    "docs/marketing/THREADS.md",
    "docs/assets/README.md",
    "docs/RED_TEAM.md",
]


class TestRequiredFilesExist:
    @pytest.mark.parametrize("rel", REQUIRED_TOP_LEVEL_FILES)
    def test_top_level(self, rel):
        p = _ROOT / rel
        assert p.exists(), f"top-level file missing: {rel}"
        assert p.stat().st_size > 50, (
            f"{rel} exists but is suspiciously small "
            f"({p.stat().st_size} bytes)."
        )

    @pytest.mark.parametrize("rel", REQUIRED_GITHUB_FILES)
    def test_github_files(self, rel):
        p = _ROOT / rel
        assert p.exists(), f"GitHub scaffolding file missing: {rel}"

    @pytest.mark.parametrize("rel", REQUIRED_DOCS)
    def test_docs(self, rel):
        p = _ROOT / rel
        assert p.exists(), f"docs file missing: {rel}"


# ---------------------------------------------------------------------------
# LICENSE
# ---------------------------------------------------------------------------

class TestLicense:
    def test_is_apache_2(self):
        text = (_ROOT / "LICENSE").read_text(encoding="utf-8")
        assert "Apache License" in text
        assert "Version 2.0, January 2004" in text
        # Boilerplate at the bottom should name the project
        assert "Plenith" in text

    def test_notice_lists_major_deps(self):
        text = (_ROOT / "NOTICE").read_text(encoding="utf-8")
        # Spot-check the deps we declared in requirements.txt
        for dep in ("asyncssh", "httpx", "fastapi"):
            assert dep in text, f"NOTICE doesn't mention {dep}"


# ---------------------------------------------------------------------------
# MISSION.md — load-bearing promises must survive edits
# ---------------------------------------------------------------------------

class TestMissionPromises:
    def test_open_source_forever_promise(self):
        text = (_ROOT / "MISSION.md").read_text(encoding="utf-8")
        # The exact phrasing matters less than the substance — but if
        # someone deletes the section heading it's worth flagging.
        assert "Apache 2.0" in text
        assert "open source" in text.lower()
        # The "will not relicense" clause is the critical bit
        assert re.search(
            r"(not relicense|never close-source|open-source-forever)",
            text, re.IGNORECASE,
        ), "MISSION.md no longer contains the open-source-forever pledge"

    def test_children_development_commitment_intact(self):
        text = (_ROOT / "MISSION.md").read_text(encoding="utf-8")
        # The 30% floor is the headline commitment
        assert "30%" in text, (
            "MISSION.md has lost the explicit 30% pledge. "
            "Weakening this requires the procedure in MISSION.md §3 "
            "(Governance) — not a silent edit."
        )
        # The mission scope language
        assert "children" in text.lower()
        assert "development" in text.lower()

    def test_governance_amendment_procedure_present(self):
        text = (_ROOT / "MISSION.md").read_text(encoding="utf-8")
        # Procedural safeguard: weakening requires a vote
        assert re.search(r"60 days|majority vote", text, re.IGNORECASE), (
            "MISSION.md amendment procedure has been weakened or removed"
        )


# ---------------------------------------------------------------------------
# CHANGELOG
# ---------------------------------------------------------------------------

class TestChangelog:
    def test_has_unreleased_section(self):
        text = (_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        # Keep-a-Changelog consumers parse this section name
        assert "## [Unreleased]" in text, (
            "CHANGELOG.md is missing the [Unreleased] section — "
            "Keep-a-Changelog format requires it."
        )

    def test_has_v1_0_section(self):
        text = (_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        assert "## [1.0.0]" in text


# ---------------------------------------------------------------------------
# CONTRIBUTING + CODE_OF_CONDUCT
# ---------------------------------------------------------------------------

class TestContributing:
    def test_explains_test_run(self):
        text = (_ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
        # The single most-asked question — a contributor must be able to
        # find this without reading the whole file.
        assert "pytest" in text
        assert "pre-commit" in text

    def test_references_mission_and_security(self):
        text = (_ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
        assert "MISSION.md" in text
        assert "SECURITY.md" in text


class TestCodeOfConduct:
    def test_adopts_contributor_covenant(self):
        text = (_ROOT / "CODE_OF_CONDUCT.md").read_text(encoding="utf-8")
        assert "Contributor Covenant" in text
        # Specifically v2.1 — versioning matters for upstream changes
        assert "2.1" in text
        # And the URL where the canonical text lives
        assert "contributor-covenant.org" in text


# ---------------------------------------------------------------------------
# Issue / PR templates
# ---------------------------------------------------------------------------

class TestIssueTemplates:
    def test_config_disables_blank_issues(self):
        cfg = yaml.safe_load(
            (_ROOT / ".github/ISSUE_TEMPLATE/config.yml").read_text(
                encoding="utf-8"
            )
        )
        assert cfg.get("blank_issues_enabled") is False, (
            "blank-issue template is still enabled — operators bypass "
            "the templated triage flow"
        )

    def test_security_link_present(self):
        cfg = yaml.safe_load(
            (_ROOT / ".github/ISSUE_TEMPLATE/config.yml").read_text(
                encoding="utf-8"
            )
        )
        links = cfg.get("contact_links", []) or []
        urls = [link.get("url", "") for link in links]
        assert any("security" in u.lower() for u in urls), (
            "issue template config has no link to private security "
            "reporting — users WILL file CVEs as public issues."
        )

    def test_bug_report_template_has_required_sections(self):
        text = (_ROOT / ".github/ISSUE_TEMPLATE/bug_report.md").read_text(
            encoding="utf-8"
        )
        for section in ("What happened", "Reproduction", "Environment"):
            assert section in text, f"bug_report.md missing section: {section}"


class TestPRTemplate:
    def test_has_test_plan_section(self):
        text = (_ROOT / ".github/PULL_REQUEST_TEMPLATE.md").read_text(
            encoding="utf-8"
        )
        for section in ("Summary", "Test plan", "Checklist"):
            assert section in text, (
                f"PULL_REQUEST_TEMPLATE.md missing section: {section}"
            )


# ---------------------------------------------------------------------------
# Pre-commit + ruff config
# ---------------------------------------------------------------------------

class TestLintConfig:
    def test_pre_commit_config_loads(self):
        cfg = yaml.safe_load(
            (_ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
        )
        # Top-level shape
        repos = cfg.get("repos", [])
        assert isinstance(repos, list) and repos, "no repos in pre-commit config"
        # Ruff is present
        ruff_repos = [
            r for r in repos
            if "ruff" in (r.get("repo") or "").lower()
        ]
        assert ruff_repos, "pre-commit config doesn't reference ruff"

    def test_ruff_toml_loads(self):
        # Python 3.11+ ships tomllib
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib    # noqa
        with (_ROOT / "ruff.toml").open("rb") as f:
            cfg = tomllib.load(f)
        # Required keys
        assert "line-length" in cfg
        assert cfg.get("target-version", "").startswith("py3")
        assert "lint" in cfg
        # The defect-catcher families are selected
        select = cfg["lint"].get("select", [])
        assert "F" in select, "ruff config no longer enables pyflakes (F) — defects will slip"


class TestRuffPasses:
    """Belt-and-braces: actually invoke ruff and assert clean.
    Skipped if ruff isn't installed (which happens in some minimal
    environments)."""

    def test_no_lint_errors(self):
        import shutil
        import subprocess
        if shutil.which("ruff") is None:
            pytest.skip("ruff not installed in this environment")
        proc = subprocess.run(
            ["ruff", "check", "."],
            cwd=str(_ROOT),
            capture_output=True, text=True,
            encoding="utf-8", errors="replace",
        )
        assert proc.returncode == 0, (
            f"ruff check failed:\n{proc.stdout}\n{proc.stderr}"
        )


# ---------------------------------------------------------------------------
# COMPLIANCE_MAPPING.md
# ---------------------------------------------------------------------------

class TestComplianceMapping:
    def test_references_soc2_and_iso27001(self):
        text = (_ROOT / "docs/COMPLIANCE_MAPPING.md").read_text(encoding="utf-8")
        assert "SOC 2" in text
        assert "ISO" in text and "27001" in text

    def test_does_not_claim_certification(self):
        """The doc must NOT use language that implies the SOFTWARE is
        certified — that's legally / factually wrong."""
        text = (_ROOT / "docs/COMPLIANCE_MAPPING.md").read_text(encoding="utf-8")
        forbidden = [
            "Plenith is SOC 2 certified",
            "Plenith is ISO 27001 compliant",
            "ISO 27001 certified software",
        ]
        for phrase in forbidden:
            assert phrase not in text, (
                f"COMPLIANCE_MAPPING.md contains overclaim: {phrase!r}"
            )

    def test_links_to_dpia_and_data_handling(self):
        text = (_ROOT / "docs/COMPLIANCE_MAPPING.md").read_text(encoding="utf-8")
        assert "DPIA" in text or "dpia" in text
        assert "DATA_HANDLING" in text or "data_handling" in text.lower()


# ---------------------------------------------------------------------------
# ADR index is in sync with files on disk
# ---------------------------------------------------------------------------

class TestADRIndex:
    def test_every_adr_file_listed_in_index(self):
        adr_dir = _ROOT / "docs" / "adr"
        index = (adr_dir / "README.md").read_text(encoding="utf-8")
        for adr in sorted(adr_dir.glob("[0-9]*.md")):
            num = adr.stem.split("-", 1)[0]
            # The index lists the ADR by its number (e.g. "| 005 |")
            assert f"| {num} |" in index, (
                f"ADR {adr.name} is on disk but not listed in "
                f"docs/adr/README.md"
            )


# ---------------------------------------------------------------------------
# Trademark / Commercial / Governance / Roadmap — load-bearing content checks
# ---------------------------------------------------------------------------

class TestTrademark:
    def test_references_apache_license(self):
        text = (_ROOT / "TRADEMARK.md").read_text(encoding="utf-8")
        assert "Apache" in text and "LICENSE" in text, (
            "TRADEMARK.md must reference Apache 2.0 + the LICENSE file "
            "so the source-vs-brand distinction is unambiguous"
        )

    def test_fork_naming_rule_present(self):
        """Forks must be named differently — the standard pattern Linux /
        PostgreSQL / Apache use."""
        text = (_ROOT / "TRADEMARK.md").read_text(encoding="utf-8")
        # Any reasonable phrasing of the fork-rename rule
        assert re.search(
            r"(rename your fork|fork should not be called|forks must)",
            text, re.IGNORECASE,
        ), "TRADEMARK.md is missing the fork-naming convention"

    def test_references_mission(self):
        text = (_ROOT / "TRADEMARK.md").read_text(encoding="utf-8")
        assert "MISSION.md" in text, (
            "TRADEMARK.md should reference MISSION.md — the trademark "
            "exists to protect the mission's revenue path"
        )


class TestCommercial:
    def test_lists_free_and_commercial(self):
        text = (_ROOT / "COMMERCIAL.md").read_text(encoding="utf-8")
        # Both sides of the distinction must be present
        assert "free" in text.lower()
        assert "commercial" in text.lower()
        assert "Apache" in text and "LICENSE" in text

    def test_anti_lockin_commitments_present(self):
        """The 'will NOT commercialize' section is the load-bearing trust
        signal. Catches accidental removal."""
        text = (_ROOT / "COMMERCIAL.md").read_text(encoding="utf-8")
        forbidden_removals = [
            r"per-host.*licens",          # No per-host runtime licensing
            r"behind a paywall",          # Compliance / security patches behind paywall
            r"open-source-forever",       # The promise
        ]
        for pattern in forbidden_removals:
            assert re.search(pattern, text, re.IGNORECASE), (
                f"COMMERCIAL.md is missing the anti-lockin commitment "
                f"matching pattern: {pattern}"
            )


class TestGovernance:
    def test_mission_steward_role_defined(self):
        text = (_ROOT / "GOVERNANCE.md").read_text(encoding="utf-8")
        assert "Mission Steward" in text, (
            "GOVERNANCE.md must define the Mission Steward role"
        )
        # Minimum count rule
        assert re.search(r"(three|3).*Mission Steward|Mission Steward.*(three|3)",
                          text, re.IGNORECASE), (
            "GOVERNANCE.md must specify the minimum 3 Mission Steward count"
        )

    def test_succession_planning_present(self):
        text = (_ROOT / "GOVERNANCE.md").read_text(encoding="utf-8")
        assert re.search(r"succession|acquisition", text, re.IGNORECASE), (
            "GOVERNANCE.md must address what happens when leadership leaves "
            "or the project is acquired — the mission depends on durable "
            "succession"
        )


class TestRoadmap:
    def test_has_done_section(self):
        text = (_ROOT / "ROADMAP.md").read_text(encoding="utf-8")
        assert "Done" in text or "v1.0" in text or "1.0.0" in text

    def test_has_out_of_scope_section(self):
        text = (_ROOT / "ROADMAP.md").read_text(encoding="utf-8")
        assert "Out of scope" in text, (
            "ROADMAP.md should have an Out-of-scope section so operators "
            "know what NOT to wait for"
        )

    def test_does_not_commit_to_calendar_deadlines(self):
        """Roadmap is intentionally non-binding. We must NOT use language
        like 'guaranteed by' or 'release date' that promises calendar
        commitments."""
        text = (_ROOT / "ROADMAP.md").read_text(encoding="utf-8")
        forbidden = ["guaranteed by", "release date", "we promise"]
        for phrase in forbidden:
            assert phrase not in text.lower(), (
                f"ROADMAP.md uses calendar-commitment language: {phrase!r}"
            )


class TestImpactScaffold:
    def test_readme_references_mission_governance(self):
        text = (_ROOT / "docs/IMPACT/README.md").read_text(encoding="utf-8")
        assert "MISSION.md" in text or "Governance" in text
        # The April 1 cadence per MISSION.md
        assert "April" in text or "annual" in text.lower()

    def test_template_has_required_sections(self):
        """Each annual report has five mandatory sections per
        MISSION.md § Governance §1."""
        text = (_ROOT / "docs/IMPACT/_TEMPLATE.md").read_text(encoding="utf-8")
        required_sections = [
            "Financial summary",
            "Allocation detail",
            "Governance",
            "Mission compliance",
            "Independent review",
        ]
        for section in required_sections:
            assert section in text, (
                f"docs/IMPACT/_TEMPLATE.md is missing section: {section}"
            )

    def test_template_mentions_30_percent_floor(self):
        text = (_ROOT / "docs/IMPACT/_TEMPLATE.md").read_text(encoding="utf-8")
        assert "30%" in text, (
            "Impact report template must explicitly reference the 30% "
            "floor from MISSION.md — silent removal would erode the pledge"
        )


class TestSecurityPGP:
    def test_references_security_md(self):
        text = (_ROOT / "docs/security-pgp.txt").read_text(encoding="utf-8")
        assert "SECURITY.md" in text


class TestPreLaunchChecklist:
    def test_documents_eight_gates(self):
        """The 8-gate verification process from ADR-014 must be the
        backbone of the checklist."""
        text = (_ROOT / "docs/PRE_LAUNCH_CHECKLIST.md").read_text(encoding="utf-8")
        for gate in ("USPTO", "EUIPO", "WIPO", "GitHub", "PyPI"):
            assert gate in text, (
                f"PRE_LAUNCH_CHECKLIST.md is missing reference to {gate}"
            )
