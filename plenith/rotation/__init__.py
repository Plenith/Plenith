"""Content rotation — deployment-scoped, epoch-rotatable artifact generation.

Defeats the §8 risk row "Synthetic data fingerprinting": attackers (or
red-team aggregators) recognizing a Plenith deployment by the static
content of its decoy files (sudoers fragments, mysql banners, "RSA
SHA256:..." auth-log fingerprints, "acme.corp" domain, etc.).

The rotation system layers two seeds:

  1. `deployment_id`   — set once per deployment site. Two Plenith
                         installs at different orgs produce completely
                         different decoy content from day one.
  2. `content_epoch`   — bumped quarterly by ops. Same site, new epoch =
                         all rotated content regenerated. Public IoCs of
                         the previous epoch become detection signals
                         themselves (a known-old decoy fingerprint
                         appearing in attacker tooling is its own alert).

Both seeds combine into a stable RNG that drives `corp.py` (corp
identity — domain, hostname patterns, IP range) and `artifacts.py`
(rotated file bodies that reference the corp identity).

The orchestrator looks up `ContentRotator` once at startup and consults
it whenever a side-effecting response wants to plant a decoy. When no
deployment_id is configured (e.g., in unit tests), the orchestrator
falls back to the static defaults in `responses.py` — backward-compat.
"""
from .artifacts import RotatedArtifacts
from .corp import CorpIdentity
from .rotator import ContentRotator
from .seeds import DeploymentSeed

__all__ = ["CorpIdentity", "ContentRotator", "DeploymentSeed", "RotatedArtifacts"]
