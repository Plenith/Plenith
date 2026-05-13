"""Tests for the content-rotation system.

Asserts the three invariants that matter for §8 fingerprint-resistance:

  1. Determinism — same (deployment_id, epoch) always produces the
     same bytes for every artifact and the same corp identity.
  2. Sensitivity — flipping deployment_id OR epoch produces a different
     corp + different artifacts (no axis is silently ignored).
  3. End-to-end — wiring through Orchestrator + Session + responses.py
     emits rotated content into the VFS when enabled, and the static
     defaults when disabled (backward-compat).
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from plenith.orchestrator import Orchestrator
from plenith.responses import execute as execute_response
from plenith.rotation import (
    ContentRotator,
    CorpIdentity,
    DeploymentSeed,
    RotatedArtifacts,
)
from plenith.rotation.seeds import iter_purposes
from plenith.session import Session


_ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# DeploymentSeed
# ---------------------------------------------------------------------------

class TestDeploymentSeed:
    def test_same_inputs_same_seed(self):
        a = DeploymentSeed(deployment_id="install-A", epoch="2026Q2")
        b = DeploymentSeed(deployment_id="install-A", epoch="2026Q2")
        assert a.for_purpose("sudoers_compat") == b.for_purpose("sudoers_compat")
        assert a.signature() == b.signature()

    def test_different_deployment_id_different_seed(self):
        a = DeploymentSeed(deployment_id="install-A", epoch="2026Q2")
        b = DeploymentSeed(deployment_id="install-B", epoch="2026Q2")
        assert a.for_purpose("sudoers_compat") != b.for_purpose("sudoers_compat")
        assert a.signature() != b.signature()

    def test_different_epoch_different_seed(self):
        a = DeploymentSeed(deployment_id="install-A", epoch="2026Q2")
        b = DeploymentSeed(deployment_id="install-A", epoch="2026Q3")
        assert a.for_purpose("sudoers_compat") != b.for_purpose("sudoers_compat")
        assert a.signature() != b.signature()

    def test_different_purposes_different_streams(self):
        a = DeploymentSeed(deployment_id="install-A", epoch="2026Q2")
        # Two different purposes from the same seed must produce different
        # RNG streams — otherwise rotating sudoers would correlate with
        # rotating mysql credentials.
        purposes = list(iter_purposes())
        seeds = {p: a.for_purpose(p) for p in purposes}
        assert len(set(seeds.values())) == len(purposes), (
            "purpose-to-seed mapping must be injective"
        )

    def test_signature_is_short_hex(self):
        a = DeploymentSeed(deployment_id="install-A", epoch="2026Q2")
        sig = a.signature()
        assert len(sig) == 12
        int(sig, 16)  # must parse as hex


# ---------------------------------------------------------------------------
# CorpIdentity
# ---------------------------------------------------------------------------

class TestCorpIdentity:
    def test_deterministic_from_seed(self):
        seed = DeploymentSeed(deployment_id="X", epoch="e1")
        c1 = CorpIdentity.from_seed(seed)
        c2 = CorpIdentity.from_seed(seed)
        assert c1 == c2

    def test_different_seeds_diverge(self):
        c1 = CorpIdentity.from_seed(DeploymentSeed("X", "e1"))
        c2 = CorpIdentity.from_seed(DeploymentSeed("Y", "e1"))
        # At least one of these fields must differ — usually all do
        assert (c1.corp_name, c1.corp_domain, c1.prod_subnet) != \
               (c2.corp_name, c2.corp_domain, c2.prod_subnet)

    def test_decoy_hosts_count(self):
        c = CorpIdentity.from_seed(DeploymentSeed("X", "e1"))
        assert len(c.decoy_hosts) == 3

    def test_prod_subnet_is_rfc1918(self):
        c = CorpIdentity.from_seed(DeploymentSeed("X", "e1"))
        assert c.prod_subnet.startswith("10.")
        assert c.prod_subnet.endswith("/16")

    def test_prod_ip_stable_per_index(self):
        c = CorpIdentity.from_seed(DeploymentSeed("X", "e1"))
        a, b = c.prod_ip(0), c.prod_ip(1)
        assert a != b
        assert c.prod_ip(0) == a  # idempotent

    def test_ssh_fingerprint_is_43_chars(self):
        c = CorpIdentity.from_seed(DeploymentSeed("X", "e1"))
        assert len(c.ssh_host_fingerprint) == 43
        assert len(c.auth_log_fingerprint) == 43


# ---------------------------------------------------------------------------
# RotatedArtifacts
# ---------------------------------------------------------------------------

class TestRotatedArtifacts:
    def test_all_fields_populated(self):
        seed = DeploymentSeed("X", "e1")
        corp = CorpIdentity.from_seed(seed)
        a = RotatedArtifacts.generate(seed, corp)
        assert a.sudoers_compat
        assert a.mysql_my_cnf
        assert a.ssh_banner
        assert a.motd
        assert a.ssh_config
        assert a.bash_history_pool_extras
        # No template placeholders should leak into output
        for body in (a.sudoers_compat, a.mysql_my_cnf, a.ssh_banner,
                     a.motd, a.ssh_config):
            assert "{" not in body or "{{" in body, (
                f"unrendered placeholder in artifact:\n{body!r}"
            )

    def test_sudoers_references_no_legacy_2026_03_14(self):
        """The pre-rotation static body had a hardcoded 'Generated 2026-03-14'
        date — a perfect fingerprint. Rotation must avoid it for any
        non-default seed."""
        seed = DeploymentSeed("install-X", "epoch-Y")
        corp = CorpIdentity.from_seed(seed)
        body = RotatedArtifacts.generate(seed, corp).sudoers_compat
        # The literal pre-rotation marker MUST NOT appear (or only by
        # astronomical accident — we accept that risk since 1 date out
        # of ~150 possible dates is ~0.7%; bump to a less coincidental
        # seed if it ever fails flakily).
        if "Generated 2026-03-14" in body:
            pytest.fail(
                "rotation reproduced the pre-rotation hardcoded date — "
                "tighten the _stable_date jitter or use a different seed."
            )

    def test_mysql_password_rotates(self):
        a = RotatedArtifacts.generate(DeploymentSeed("X1", "e"), CorpIdentity.from_seed(DeploymentSeed("X1", "e")))
        b = RotatedArtifacts.generate(DeploymentSeed("X2", "e"), CorpIdentity.from_seed(DeploymentSeed("X2", "e")))
        # The pre-rotation static password MUST NOT appear in either
        assert "M3taD4ta!2026" not in a.mysql_my_cnf
        assert "M3taD4ta!2026" not in b.mysql_my_cnf
        # And the two deployments' passwords must differ
        assert a.mysql_my_cnf != b.mysql_my_cnf


# ---------------------------------------------------------------------------
# ContentRotator
# ---------------------------------------------------------------------------

class TestContentRotator:
    def test_disabled_factory(self):
        r = ContentRotator.disabled()
        assert not r.is_enabled
        assert r.signature() == "disabled"
        assert r.build_manifest() == {"enabled": False}

    def test_from_config_disabled_when_no_deployment_id(self):
        assert not ContentRotator.from_config(None).is_enabled
        assert not ContentRotator.from_config({}).is_enabled
        assert not ContentRotator.from_config({"content": {}}).is_enabled
        assert not ContentRotator.from_config({"content": {"deployment_id": ""}}).is_enabled

    def test_from_config_enabled_with_deployment_id(self):
        r = ContentRotator.from_config({
            "content": {"deployment_id": "install-A", "epoch": "2026Q2"},
        })
        assert r.is_enabled
        assert r.seed.deployment_id == "install-A"
        assert r.seed.epoch == "2026Q2"
        assert r.corp is not None

    def test_from_config_env_var_fallback(self, monkeypatch):
        monkeypatch.setenv("PLENITH_TEST_DEPLOY", "from-env-123")
        r = ContentRotator.from_config({
            "content": {"env_var": "PLENITH_TEST_DEPLOY", "epoch": "e1"},
        })
        assert r.is_enabled
        assert r.seed.deployment_id == "from-env-123"

    def test_manifest_hashes_change_on_epoch_bump(self):
        a = ContentRotator.from_seed(DeploymentSeed("install-A", "2026Q2"))
        b = ContentRotator.from_seed(DeploymentSeed("install-A", "2026Q3"))
        m_a = a.build_manifest()["artifact_hashes"]
        m_b = b.build_manifest()["artifact_hashes"]
        # Every artifact must have a different hash across epochs
        for k in m_a:
            assert m_a[k] != m_b[k], (
                f"artifact {k!r} did NOT rotate across epochs (hash unchanged)"
            )

    def test_write_artifact_bundle(self, tmp_path):
        r = ContentRotator.from_seed(DeploymentSeed("X", "e1"))
        paths = r.write_artifact_bundle(tmp_path)
        # Expected files
        for f in ("sudoers_compat.txt", "mysql_my.cnf", "ssh_banner.txt",
                  "motd.txt", "ssh_config", "bash_history_extras.txt",
                  "corp_identity.json", "manifest.json"):
            assert (tmp_path / f).exists(), f"missing {f} from bundle"
        # Manifest is valid JSON
        m = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
        assert m["enabled"] is True
        assert m["deployment_id"] == "X"


# ---------------------------------------------------------------------------
# Runtime wiring: responses.py reads session.rotator when present.
# ---------------------------------------------------------------------------

class TestRotationRuntimeWiring:
    def _make_session(self, persona_jdoe, sim_bot, rotator):
        return Session(
            "jdoe", "127.0.0.1", persona_jdoe, sim_bot=sim_bot, rotator=rotator,
        )

    def test_plant_sudo_uses_rotated_body(self, persona_jdoe, sim_bot):
        rotator = ContentRotator.from_seed(DeploymentSeed("install-A", "e1"))
        session = self._make_session(persona_jdoe, sim_bot, rotator)
        execute_response({"action": "plant_sudo_vulnerability"}, session)
        body = session.vfs.read("/etc/sudoers.d/zzz_compat", cwd=None, home=None)
        # Static-default marker must not appear
        assert "Generated 2026-03-14" not in body
        # Rotated body must reference the corp (verified by checking the
        # rotated artifact equals what session.rotator was carrying)
        assert body == rotator.artifacts.sudoers_compat

    def test_plant_sudo_falls_back_when_disabled(self, persona_jdoe, sim_bot):
        session = self._make_session(persona_jdoe, sim_bot, rotator=None)
        execute_response({"action": "plant_sudo_vulnerability"}, session)
        body = session.vfs.read("/etc/sudoers.d/zzz_compat", cwd=None, home=None)
        # Static default still works
        assert "Generated 2026-03-14" in body

    def test_spawn_fake_mysql_uses_rotated_body(self, persona_jdoe, sim_bot):
        rotator = ContentRotator.from_seed(DeploymentSeed("install-B", "e1"))
        session = self._make_session(persona_jdoe, sim_bot, rotator)
        execute_response({"action": "spawn_fake_mysql"}, session)
        body = session.vfs.read("/etc/mysql/my.cnf", cwd=None, home=None)
        assert "M3taD4ta!2026" not in body
        assert body == rotator.artifacts.mysql_my_cnf

    def test_orchestrator_propagates_rotator_to_session_attr(self, fake_llm, cache, sim_bot):
        rotator = ContentRotator.from_seed(DeploymentSeed("install-C", "e2"))
        orch = Orchestrator(fake_llm, cache, sim_bot=sim_bot, rotator=rotator)
        assert orch.rotator is rotator
        # The orchestrator doesn't construct Session itself — ssh_server does.
        # We assert the plumbing by checking that getattr is reachable.
        assert getattr(orch, "rotator").is_enabled


# ---------------------------------------------------------------------------
# CLI smoke test
# ---------------------------------------------------------------------------

class TestRotateCLI:
    def test_show_mode(self, tmp_path):
        out = subprocess.run(
            [sys.executable, str(_ROOT / "tools" / "rotate_content.py"),
             "--deployment-id", "cli-test-A", "--epoch", "e1"],
            capture_output=True, text=True, timeout=20,
        )
        assert out.returncode == 0, out.stderr
        assert "deployment: cli-test-A" in out.stdout
        assert "Artifact hashes" in out.stdout

    def test_out_mode_materializes_bundle(self, tmp_path):
        out_dir = tmp_path / "bundle"
        out = subprocess.run(
            [sys.executable, str(_ROOT / "tools" / "rotate_content.py"),
             "--deployment-id", "cli-test-B", "--epoch", "e1",
             "--out", str(out_dir)],
            capture_output=True, text=True, timeout=20,
        )
        assert out.returncode == 0, out.stderr
        assert (out_dir / "manifest.json").exists()
        assert (out_dir / "sudoers_compat.txt").exists()

    def test_diff_detects_epoch_rotation(self, tmp_path):
        """Two epochs must diff — that's the whole point of rotating."""
        e1_dir = tmp_path / "e1"
        e2_dir = tmp_path / "e2"
        # Generate epoch 1
        subprocess.run(
            [sys.executable, str(_ROOT / "tools" / "rotate_content.py"),
             "--deployment-id", "cli-test-C", "--epoch", "2026Q2",
             "--out", str(e1_dir)],
            capture_output=True, text=True, timeout=20, check=True,
        )
        # Generate epoch 2, diff against epoch 1
        diff_out = subprocess.run(
            [sys.executable, str(_ROOT / "tools" / "rotate_content.py"),
             "--deployment-id", "cli-test-C", "--epoch", "2026Q3",
             "--out", str(e2_dir),
             "--diff", str(e1_dir)],
            capture_output=True, text=True, timeout=20,
        )
        # exit 1 means "differences found" — the rotation worked
        assert diff_out.returncode == 1, (
            f"epoch bump should have produced diffs.\n"
            f"stdout={diff_out.stdout}\nstderr={diff_out.stderr}"
        )
        assert "changed" in diff_out.stdout
