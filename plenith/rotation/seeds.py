"""Deterministic seed derivation for content rotation.

Every rotatable artifact gets its own purpose-keyed RNG. Same
(deployment_id, epoch, purpose) tuple → same bytes, forever. Different
on any axis → different bytes.

The hash is SHA-256 truncated to 64 bits — overkill collision-wise for
this workload and standard-library only.
"""
import hashlib
import random
from dataclasses import dataclass
from collections.abc import Iterator

@dataclass(frozen=True)
class DeploymentSeed:
    """Top-level deterministic seed for an entire Plenith deployment.

    Construct once at startup from config (`content.deployment_id` and
    `content.epoch`). Pass to every artifact generator that wants
    rotation. The `for_purpose("sudoers_compat")` helper derives a
    purpose-scoped sub-seed so unrelated artifacts don't share state.
    """

    deployment_id: str
    epoch: str = "default"

    def _root_int(self) -> int:
        # Combine the two strings with a separator that can't appear in
        # either by convention (we lowercase + reject \0 elsewhere).
        material = f"{self.deployment_id}\x1f{self.epoch}".encode()
        digest = hashlib.sha256(material).digest()
        # Truncate to a 63-bit int (Python's randint upper bound for
        # cross-platform safety).
        return int.from_bytes(digest[:8], "big") & ((1 << 63) - 1)

    def for_purpose(self, purpose: str) -> int:
        """Return a stable int seed for a named artifact purpose. Two
        different purposes produce independent RNG streams, so e.g.
        rotating the sudoers content doesn't perturb the mysql password."""
        material = f"{self.deployment_id}\x1f{self.epoch}\x1f{purpose}".encode()
        digest = hashlib.sha256(material).digest()
        return int.from_bytes(digest[:8], "big") & ((1 << 63) - 1)

    def rng_for(self, purpose: str) -> random.Random:
        """Convenience: a pre-seeded `random.Random` for this purpose."""
        return random.Random(self.for_purpose(purpose))

    def signature(self) -> str:
        """Short fingerprint of this seed — used in content manifests so
        ops can tell at a glance which deployment + epoch produced a file."""
        return hashlib.sha256(
            f"{self.deployment_id}\x1f{self.epoch}".encode()
        ).hexdigest()[:12]

def iter_purposes() -> Iterator[str]:
    """Canonical purpose names. Adding a new one here also requires a
    generator function — keep them lock-step. Tests assert that every
    name produces a non-empty artifact under any seed."""
    yield "corp_identity"
    yield "sudoers_compat"
    yield "mysql_my_cnf"
    yield "ssh_banner"
    yield "ssh_config"
    yield "ssh_host_fingerprint"
    yield "auth_log_fingerprint"
    yield "bash_history_pool"
    yield "motd"
