"""Tests for the CycloneDX 1.5 SBOM generator."""
import json
import subprocess
import sys
from pathlib import Path

import pytest


_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "tools"))

import sbom as sbom_mod  # noqa: E402


class TestRequirementsParser:
    def test_parses_pinned_version(self, tmp_path):
        f = tmp_path / "r.txt"
        f.write_text("asyncssh==2.18.0\n", encoding="utf-8")
        parsed = sbom_mod._parse_requirements(f)
        assert parsed == [("asyncssh", "==2.18.0")]

    def test_parses_range_spec(self, tmp_path):
        f = tmp_path / "r.txt"
        f.write_text("numpy>=2.0,<3.0\n", encoding="utf-8")
        parsed = sbom_mod._parse_requirements(f)
        assert parsed[0][0] == "numpy"
        assert ">=" in parsed[0][1]

    def test_parses_extras_ignored(self, tmp_path):
        f = tmp_path / "r.txt"
        f.write_text("uvicorn[standard]>=0.27,<1.0\n", encoding="utf-8")
        parsed = sbom_mod._parse_requirements(f)
        assert parsed[0][0] == "uvicorn"

    def test_skips_comments_and_blank_lines(self, tmp_path):
        f = tmp_path / "r.txt"
        f.write_text(
            "# top-level comment\n\nasyncssh==2.18.0\n# another\n",
            encoding="utf-8",
        )
        parsed = sbom_mod._parse_requirements(f)
        assert len(parsed) == 1

    def test_skips_include_directive(self, tmp_path):
        f = tmp_path / "r.txt"
        f.write_text("-r requirements.txt\npytest==8.3.3\n",
                      encoding="utf-8")
        parsed = sbom_mod._parse_requirements(f)
        assert parsed == [("pytest", "==8.3.3")]

    def test_missing_file_returns_empty(self, tmp_path):
        assert sbom_mod._parse_requirements(tmp_path / "missing.txt") == []


class TestDockerBaseImageDiscovery:
    def test_finds_from_lines(self, tmp_path):
        d = tmp_path / "agent"
        d.mkdir()
        (d / "Dockerfile").write_text(
            "FROM ubuntu:22.04\nRUN apt-get update\n", encoding="utf-8",
        )
        (tmp_path / "Dockerfile.foo").write_text(
            "FROM python:3.13-slim\n", encoding="utf-8",
        )
        seen = sbom_mod._docker_base_images(tmp_path)
        names = [n for n, _ in seen]
        assert "ubuntu" in names
        assert "python" in names

    def test_dedupes_same_base(self, tmp_path):
        (tmp_path / "A").mkdir()
        (tmp_path / "B").mkdir()
        (tmp_path / "A" / "Dockerfile").write_text("FROM ubuntu:22.04\n",
                                                     encoding="utf-8")
        (tmp_path / "B" / "Dockerfile").write_text("FROM ubuntu:22.04\n",
                                                     encoding="utf-8")
        seen = sbom_mod._docker_base_images(tmp_path)
        assert len(seen) == 1

    def test_no_dockerfiles_returns_empty(self, tmp_path):
        assert sbom_mod._docker_base_images(tmp_path) == []


class TestSBOMShape:
    def test_required_top_level_fields(self):
        s = sbom_mod.build(root=_ROOT)
        for key in ("bomFormat", "specVersion", "version",
                     "serialNumber", "metadata", "components"):
            assert key in s
        assert s["bomFormat"] == "CycloneDX"
        assert s["specVersion"] == "1.5"

    def test_serial_number_is_uuid_urn(self):
        s = sbom_mod.build(root=_ROOT)
        assert s["serialNumber"].startswith("urn:uuid:")

    def test_metadata_application_component(self):
        s = sbom_mod.build(root=_ROOT)
        app = s["metadata"]["component"]
        assert app["type"] == "application"
        assert app["name"] == "plenith"
        assert app["purl"].startswith("pkg:github/")

    def test_components_include_pinned_deps(self):
        s = sbom_mod.build(root=_ROOT)
        names = {c["name"].lower() for c in s["components"]}
        # The top requirements should be present
        assert "asyncssh" in names
        assert "httpx" in names
        assert "fastapi" in names

    def test_docker_components_present(self):
        s = sbom_mod.build(root=_ROOT)
        types = {c["type"] for c in s["components"]}
        assert "container" in types  # at least one Dockerfile FROM emitted

    def test_validate_passes_on_built_sbom(self):
        s = sbom_mod.build(root=_ROOT)
        errors = sbom_mod.validate(s)
        assert errors == []

    def test_validate_fails_on_broken_sbom(self):
        bad = {"bomFormat": "wrong"}
        errors = sbom_mod.validate(bad)
        assert errors

    def test_include_dev_adds_test_deps(self):
        prod = sbom_mod.build(root=_ROOT, include_dev=False)
        dev  = sbom_mod.build(root=_ROOT, include_dev=True)
        # Dev SBOM should have AT LEAST as many components as prod
        assert len(dev["components"]) > len(prod["components"])
        # pytest should appear only in the dev SBOM
        names_dev = {c["name"].lower() for c in dev["components"]}
        assert "pytest" in names_dev


class TestSBOMCLI:
    def _run(self, *args, cwd=None):
        # NOTE: subprocess thread-decode can choke on partial UTF-8 in
        # stderr when ANSI color escapes are present on Windows; fall
        # back to "replace" errors so the test reads stderr correctly.
        return subprocess.run(
            [sys.executable, str(_ROOT / "tools" / "sbom.py"), *args],
            capture_output=True, text=True, timeout=30, cwd=cwd,
            encoding="utf-8", errors="replace",
        )

    def test_stdout_is_valid_json(self):
        r = self._run()
        assert r.returncode == 0
        parsed = json.loads(r.stdout)
        assert parsed["bomFormat"] == "CycloneDX"

    def test_out_writes_file(self, tmp_path):
        outfile = tmp_path / "sbom.json"
        r = self._run("--out", str(outfile))
        assert r.returncode == 0
        body = outfile.read_text(encoding="utf-8")
        parsed = json.loads(body)
        assert parsed["specVersion"] == "1.5"

    def test_validate_flag(self, tmp_path):
        # Write to a real file (NUL / /dev/null cause subprocess decoding
        # issues across OSes — easier to use a tmp_path)
        outfile = tmp_path / "validated.json"
        r = self._run("--validate", "--out", str(outfile))
        assert r.returncode == 0
        assert "valid CycloneDX" in r.stderr or "valid CycloneDX" in r.stdout
        # The validated SBOM should be parseable
        assert json.loads(outfile.read_text(encoding="utf-8"))["bomFormat"] == "CycloneDX"
