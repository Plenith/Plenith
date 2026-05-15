"""ContentRotator — the runtime handle the orchestrator uses.

Single object that bundles a `DeploymentSeed`, a `CorpIdentity` derived
from it, and lazy-cached `RotatedArtifacts`. The orchestrator + response
executors look this up once and consult it whenever they would
otherwise emit a static decoy body.

Construction:
    rotator = ContentRotator.from_config(cfg)        # config-driven
    rotator = ContentRotator.disabled()              # fallback for tests

Backward-compat: when `config.content.deployment_id` is unset, callers
fall back to the existing static defaults in `responses.py` /
`synthetic.py`. Nothing breaks; rotation is purely additive.
"""
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from collections.abc import Iterable

from .artifacts import RotatedArtifacts
from .corp import CorpIdentity
from .seeds import DeploymentSeed, iter_purposes

@dataclass
class ContentRotator:
    """Orchestrator-facing rotation handle. `is_enabled` short-circuits
    every accessor to None when no deployment_id is configured."""
    seed: DeploymentSeed | None = None
    corp: CorpIdentity | None = None
    artifacts: RotatedArtifacts | None = None

    # --- factories ------------------------------------------------------

    @classmethod
    def disabled(cls) -> "ContentRotator":
        return cls()

    @classmethod
    def from_seed(cls, seed: DeploymentSeed) -> "ContentRotator":
        corp = CorpIdentity.from_seed(seed)
        artifacts = RotatedArtifacts.generate(seed, corp)
        return cls(seed=seed, corp=corp, artifacts=artifacts)

    @classmethod
    def from_config(cls, cfg: dict[str, Any] | None) -> "ContentRotator":
        """Build from the `content` block of config.yaml.

        Recognized keys:
            content.deployment_id: str — non-empty to enable rotation
            content.epoch:         str — defaults to "default"
            content.env_var:       str — read deployment_id from this env
                                         var if `deployment_id` is missing

        Returns `disabled()` if rotation is not configured.
        """
        if not cfg:
            return cls.disabled()
        content = cfg.get("content") if isinstance(cfg, dict) else None
        if not content:
            return cls.disabled()

        deployment_id = content.get("deployment_id")
        if not deployment_id and content.get("env_var"):
            deployment_id = os.environ.get(content["env_var"])
        if not deployment_id:
            return cls.disabled()

        epoch = str(content.get("epoch", "default"))
        seed = DeploymentSeed(deployment_id=str(deployment_id), epoch=epoch)
        return cls.from_seed(seed)

    # --- queries --------------------------------------------------------

    @property
    def is_enabled(self) -> bool:
        return self.seed is not None

    def signature(self) -> str:
        return self.seed.signature() if self.seed else "disabled"

    # --- manifest -------------------------------------------------------

    def build_manifest(self) -> dict[str, Any]:
        """A reproducible JSON-able description of what this rotator
        emits. Useful for the `rotate_content.py` CLI to print a hash
        diff before/after an epoch bump, so ops can confirm content
        actually changed."""
        if not self.is_enabled:
            return {"enabled": False}

        # Lazy import to avoid pulling synthetic.py into the rotation
        # package's import-time graph.
        bodies: dict[str, str] = {
            "sudoers_compat":  self.artifacts.sudoers_compat,
            "mysql_my_cnf":    self.artifacts.mysql_my_cnf,
            "ssh_banner":      self.artifacts.ssh_banner,
            "motd":            self.artifacts.motd,
            "ssh_config":      self.artifacts.ssh_config,
            "bash_history_extras": "\n".join(self.artifacts.bash_history_pool_extras),
        }
        hashes = {
            name: hashlib.sha256(body.encode("utf-8")).hexdigest()[:16]
            for name, body in bodies.items()
        }
        return {
            "enabled": True,
            "deployment_id": self.seed.deployment_id,
            "epoch": self.seed.epoch,
            "signature": self.signature(),
            "corp": self.corp.to_dict(),
            "artifact_hashes": hashes,
            "artifact_sizes": {name: len(body) for name, body in bodies.items()},
            "rotation_purposes": list(iter_purposes()),
        }

    def write_manifest(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.build_manifest(), indent=2, sort_keys=True),
            encoding="utf-8",
        )

    def write_artifact_bundle(self, out_dir: Path) -> dict[str, Path]:
        """Materialize every rotated artifact under `out_dir/`. Returns
        a mapping of artifact name → path. Useful for inspection from
        the CLI and for diffing across epochs."""
        if not self.is_enabled:
            raise RuntimeError("Cannot write artifacts; rotation is disabled.")
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        bodies = {
            "sudoers_compat.txt":  self.artifacts.sudoers_compat,
            "mysql_my.cnf":        self.artifacts.mysql_my_cnf,
            "ssh_banner.txt":      self.artifacts.ssh_banner,
            "motd.txt":            self.artifacts.motd,
            "ssh_config":          self.artifacts.ssh_config,
            "bash_history_extras.txt": "\n".join(self.artifacts.bash_history_pool_extras) + "\n",
            "corp_identity.json":  json.dumps(self.corp.to_dict(), indent=2, sort_keys=True),
        }
        out: dict[str, Path] = {}
        for name, body in bodies.items():
            p = out_dir / name
            p.write_text(body, encoding="utf-8")
            out[name] = p
        self.write_manifest(out_dir / "manifest.json")
        return out
