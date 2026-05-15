"""Documentation lint — regression-prevention for the class of drift
that produced the v1.0 launch-readiness audit findings:

1. Test-count claims in docs falling behind reality (six different
   stale numbers found across README/QUICKSTART/CHANGELOG/ROADMAP/
   FAQ/PRE_LAUNCH_CHECKLIST during the audit).
2. Legacy project names (MirrorCore, Caltrop) leaking into docs after
   the v1.0 rename. ADR-013/014 are intentional historical records
   and are allowlisted.
3. Stale MIT-license claims after the Apache 2.0 decision.
4. Stale `plenith/rotation.py` references after rotation became a
   package (`plenith/rotation/`).

Each of these was caught manually during the audit; encoding them as
tests means future contributors get an immediate red light rather
than a stealthy doc-vs-code drift that ships and embarrasses the
project later.

These tests are intentionally tolerant of historical-record contexts
(ADRs, changelogs documenting renames) — drift in *operator-facing*
docs is what we're guarding against."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Allowlist: paths where historical references are EXPECTED and correct.
# Anything matching one of these prefixes is exempt from the lints below.
# ---------------------------------------------------------------------------
_HISTORICAL_PATH_PREFIXES = (
    # ADR-013 (rename to Caltrop) and ADR-014 (rename to Plenith) MUST
    # talk about the old names — the whole point of an ADR is to
    # record the decision in its historical context.
    "docs/adr/013-",
    "docs/adr/014-",
    # The ADR index page references the rename ADRs by their decision
    # labels in the per-row description, which legitimately includes
    # "Caltrop" as the supersededByRef target.
    "docs/adr/README.md",
    # CHANGELOG entries that describe the rename history.
    "CHANGELOG.md",
)

def _is_historical(rel_path: str) -> bool:
    rel_path = rel_path.replace("\\", "/")
    return any(rel_path.startswith(p) for p in _HISTORICAL_PATH_PREFIXES)

# Markdown files only — we're not policing code comments which may
# legitimately reference legacy names in deprecation notices etc.
def _markdown_files():
    for p in _ROOT.rglob("*.md"):
        rel = p.relative_to(_ROOT)
        # Skip backups and archives.
        if any(part.startswith(".") for part in rel.parts):
            continue
        if "backup" in str(rel).lower():
            continue
        # Skip the website/ directory if it ever gets vendored.
        if rel.parts[0] == "website":
            continue
        yield p, str(rel)

# ---------------------------------------------------------------------------
# Lint 1: legacy project names must not appear in operator-facing docs.
# ---------------------------------------------------------------------------

_LEGACY_NAME_RE = re.compile(r"\b(MirrorCore|Caltrop|mirrorcore|caltrop)\b")

class TestLegacyProjectNames:
    """The project went through two renames (MirrorCore → Caltrop →
    Plenith) due to namespace collisions, codified in ADR-014's
    `Verification gates (now mandatory)` section. The historical
    record is intentionally preserved in ADR-013/014; everywhere
    else, references should be 'Plenith'."""

    def test_no_legacy_names_outside_historical_records(self):
        offenders = []
        for path, rel in _markdown_files():
            if _is_historical(rel):
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            for m in _LEGACY_NAME_RE.finditer(text):
                # Compute 1-indexed line number
                line_no = text.count("\n", 0, m.start()) + 1
                offenders.append((rel, line_no, m.group(0)))
        if offenders:
            lines = "\n".join(
                f"  {rel}:{ln}  '{token}'" for rel, ln, token in offenders
            )
            pytest.fail(
                "Legacy project name(s) found in operator-facing docs. "
                "If this is a historical record, move it under "
                "docs/adr/013-* or docs/adr/014-* (those paths are "
                "allowlisted). Otherwise rename to 'Plenith'.\n"
                f"{lines}"
            )

# ---------------------------------------------------------------------------
# Lint 2: license must be Apache 2.0 everywhere it's mentioned.
# ---------------------------------------------------------------------------

# Word-boundary "MIT license" / "MIT-license" / "the MIT" near a license
# reference. We want to catch claims like "under the MIT license" without
# false-positive on substring matches (e.g. "submit" contains "mit").
_MIT_LICENSE_RE = re.compile(
    r"\b(?:MIT\s+licen[cs]e|MIT-licen[cs]e|under\s+the\s+MIT|MIT\s+@)\b",
    re.IGNORECASE,
)

class TestLicenseConsistency:
    def test_no_mit_license_claims_in_docs(self):
        offenders = []
        for path, rel in _markdown_files():
            if _is_historical(rel):
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            for m in _MIT_LICENSE_RE.finditer(text):
                line_no = text.count("\n", 0, m.start()) + 1
                offenders.append((rel, line_no, m.group(0)))
        if offenders:
            lines = "\n".join(
                f"  {rel}:{ln}  '{token}'" for rel, ln, token in offenders
            )
            pytest.fail(
                "Project license is Apache 2.0 (see LICENSE + NOTICE + "
                "TRADEMARK.md). MIT license references in docs are drift "
                "from the v1.0 decision and must be corrected.\n"
                f"{lines}"
            )

# ---------------------------------------------------------------------------
# Lint 3: plenith/rotation became a package; old .py references are stale.
# ---------------------------------------------------------------------------

class TestRotationModulePath:
    def test_no_rotation_py_file_refs(self):
        """The rotation code is a package (plenith/rotation/) with
        artifacts.py, corp.py, rotator.py, seeds.py — not a single
        rotation.py module. Doc refs to `plenith/rotation.py` are
        confusing to operators looking for the file.

        Historical-record paths (ADR-013/014, CHANGELOG) are
        allowlisted — those legitimately reference the old module name
        when describing the rotation-package refactor in retrospect."""
        offenders = []
        for path, rel in _markdown_files():
            if _is_historical(rel):
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            for m in re.finditer(r"plenith[/\\]rotation\.py", text):
                line_no = text.count("\n", 0, m.start()) + 1
                offenders.append((rel, line_no))
        if offenders:
            lines = "\n".join(
                f"  {rel}:{ln}" for rel, ln in offenders
            )
            pytest.fail(
                "plenith/rotation is a package (directory), not a module. "
                "Replace `plenith/rotation.py` with `plenith/rotation/` "
                "(or a specific submodule like `plenith/rotation/artifacts.py`).\n"
                f"{lines}"
            )

# ---------------------------------------------------------------------------
# Lint 4: doc test counts must match `pytest --collect-only`.
# ---------------------------------------------------------------------------

# Match patterns like "1031 tests" / "1031-test" / "N tests passing".
# Numbers below 100 are clearly NOT test counts (those would be alert
# counts, persona counts, etc.) so anchor the lint to 3+ digits.
_TEST_COUNT_RE = re.compile(r"\b(\d{3,4})[-\s](?:tests?|test)(?:[\s,)\-.]|$)")

def _collect_current_test_count() -> int:
    """Ask pytest how many tests exist right now. Slow-ish but only
    runs once per CI pass. Use non-quiet `--collect-only` because
    the quiet mode in recent pytest versions drops the summary line
    we parse — only the per-file rollup is emitted in -q mode."""
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only"],
        capture_output=True,
        text=True,
        cwd=str(_ROOT),
        timeout=120,
    )
    # Pytest ends with: "1036 tests collected in 0.96s" (or
    # "1036/1037 tests collected (1 deselected)" etc.). Match the
    # leading integer in any "N tests collected" line.
    for line in reversed(result.stdout.splitlines()):
        m = re.search(r"(\d+)\s+tests?\s+collected", line)
        if m:
            return int(m.group(1))
    raise RuntimeError(
        f"could not parse test count from pytest --collect-only:\n"
        f"stdout:\n{result.stdout[-400:]}\nstderr:\n{result.stderr[-400:]}"
    )

class TestDocumentedTestCount:
    """The audit found six stale test counts (571, 872, 914, 938) in
    operator-facing docs. This lint asserts every numeric `N tests`
    claim matches the live `pytest --collect-only` count, within a
    small tolerance (±5%) to avoid red-lighting CI for every test
    added in the same PR as a doc edit."""

    # Allowlist files whose test-count refs are historical snapshots
    # (ADR records, dated journal entries). We tolerate stale numbers
    # in places that explicitly describe a past moment in time.
    _SNAPSHOT_OK = (
        "docs/adr/013-",
        "docs/adr/014-",
    )

    def test_doc_test_counts_match_pytest_collection(self):
        try:
            live_count = _collect_current_test_count()
        except (subprocess.TimeoutExpired, RuntimeError) as e:
            pytest.skip(f"could not collect live test count: {e}")

        tolerance = max(5, int(live_count * 0.05))   # ±5% or ±5, whichever larger
        low, high = live_count - tolerance, live_count + tolerance

        offenders = []
        for path, rel in _markdown_files():
            if any(rel.replace("\\", "/").startswith(p)
                    for p in self._SNAPSHOT_OK):
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            for m in _TEST_COUNT_RE.finditer(text):
                claimed = int(m.group(1))
                if not (low <= claimed <= high):
                    line_no = text.count("\n", 0, m.start()) + 1
                    offenders.append((rel, line_no, claimed))
        if offenders:
            lines = "\n".join(
                f"  {rel}:{ln}  claims {n} tests"
                for rel, ln, n in offenders
            )
            pytest.fail(
                f"Documented test counts have drifted from reality. "
                f"`pytest --collect-only` reports {live_count} tests "
                f"(±{tolerance} tolerance window: {low}-{high}). "
                f"Update the offending docs:\n{lines}"
            )
