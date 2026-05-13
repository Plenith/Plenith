"""Hash-chained engagement audit log — tamper-evident on disk.

The threat: an attacker who pivots from the deception bubble onto the
real bastion host gets read-write access to `state-docker/logs/*.json`.
A naive plain-JSON log lets them delete entries that incriminate them
(or insert plausible-looking but fake entries to mask their work).

The mitigation: every `actions_taken` entry carries `prev_hash` linking
it to the SHA-256 of the previous entry, and `entry_hash` capturing
its own canonical bytes. The whole chain is summarized on the session
record as `chain_tip` + `chain_length`.

A tamper attempt has three failure modes, all detectable:

  1. **Modify an entry in place** → `entry_hash` no longer matches the
     recomputed hash → caught by verifier.
  2. **Delete an entry from the middle** → the next entry's
     `prev_hash` still references the deleted entry's hash, which no
     longer matches the recomputed prev → caught by verifier.
  3. **Delete entries from the tail** → the session-level `chain_tip`
     points to a hash that is no longer the last entry → caught by
     verifier.

The only undetectable attack is rewriting the ENTIRE chain (every
entry plus the session tip) — which is fine if the bastion is
compromised, but a separate periodic snapshot of `chain_tip` values
to a tamper-evident sink (e.g. a write-only S3 bucket, or just a
WORM volume) makes that detectable too. This module is the foundation
layer; the snapshot strategy is operator-configurable.

Cost: ~30 µs per action on a current CPU (the chain hashes a JSON-
serialized dict). The hot path is `chain_actions()` at session-write
time, not per-command — so the cost is paid once per engagement.

Compatibility: legacy (un-chained) logs are accepted by the verifier
with status `legacy` so the deployment can roll forward without
needing to back-fill old engagement files.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence


# The chain begins with this synthetic predecessor — distinguishes
# "first entry in a real chain" from "tampered prev_hash pointing nowhere."
GENESIS_HASH = "0" * 64

# Fields we strip when computing entry_hash, so the hash is over the
# entry's content (not over its own hash field).
_HASH_EXCLUDE_FIELDS = {"entry_hash"}


def canonical_hash(payload: Dict[str, Any]) -> str:
    """Stable SHA-256 over a canonical JSON serialization.

    Canonical = sorted keys, no whitespace, `default=str` so things
    like sets / datetime fall through deterministically. We strip
    `entry_hash` from the input so callers don't have to.

    This is the single source of truth for "the hash of an entry."
    """
    body = {k: v for k, v in payload.items() if k not in _HASH_EXCLUDE_FIELDS}
    blob = json.dumps(
        body, sort_keys=True, separators=(",", ":"), default=_default,
    ).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _default(obj: Any) -> Any:
    """JSON fallback. We sort sets so chain hashes are independent of
    Python's iteration order."""
    if isinstance(obj, (set, frozenset)):
        return sorted(obj, key=str)
    return str(obj)


# ---------------------------------------------------------------------------
# Building the chain
# ---------------------------------------------------------------------------

def chain_entry(entry: Dict[str, Any], prev_hash: str) -> Dict[str, Any]:
    """Stamp `prev_hash` + `entry_hash` on a single entry. Returns a new
    dict — the input is not mutated. Repeated calls are idempotent in
    the sense that the produced hash is deterministic, but they always
    overwrite the prev_hash / entry_hash fields."""
    out = dict(entry)
    out["prev_hash"] = prev_hash
    out["entry_hash"] = canonical_hash(out)
    return out


def chain_actions(
    actions: Iterable[Dict[str, Any]],
    *,
    starting_from: str = GENESIS_HASH,
) -> List[Dict[str, Any]]:
    """Re-chain a sequence of actions. Every entry gets a fresh
    `prev_hash` (referencing the previous entry's recomputed entry_hash)
    and a fresh `entry_hash`. The chain head is `starting_from`.

    Use at session-write time on `session.actions_taken`.
    """
    prev = starting_from
    out: List[Dict[str, Any]] = []
    for a in actions:
        chained = chain_entry(a, prev)
        out.append(chained)
        prev = chained["entry_hash"]
    return out


def chain_tip(actions: Sequence[Dict[str, Any]]) -> str:
    """Return the entry_hash of the last entry, or GENESIS_HASH for
    empty chains. Used as the session-level `chain_tip` field."""
    if not actions:
        return GENESIS_HASH
    tip = actions[-1].get("entry_hash")
    if not tip:
        raise ValueError("last action has no entry_hash — call chain_actions first")
    return tip


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ChainResult:
    """Outcome of verifying a chain. `ok=True` means every entry's
    prev_hash matched and every entry's entry_hash recomputed cleanly.
    `legacy=True` means the log predates the chain feature and no
    integrity assertion is being made."""
    ok: bool
    length: int
    tip: str
    legacy: bool = False
    break_at: Optional[int] = None
    reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok":       self.ok,
            "length":   self.length,
            "tip":      self.tip,
            "legacy":   self.legacy,
            "break_at": self.break_at,
            "reason":   self.reason,
        }


def verify_chain(
    actions: Sequence[Dict[str, Any]],
    *,
    expected_tip: Optional[str] = None,
) -> ChainResult:
    """Walk a chained list of actions. Returns the verification result.

    A legacy (un-chained) log — one where NO entries carry `entry_hash`
    or `prev_hash` — returns `ok=True, legacy=True` so legacy files
    aren't treated as failures during rollout. As soon as ANY entry has
    chain fields the log is treated as a v1 chained log and every entry
    is checked.

    If `expected_tip` is provided (from the session record's
    `chain_tip` field), it's also checked. Mismatches there catch
    tail-truncation attacks.
    """
    if not actions:
        # Empty engagement is trivially valid. The tip is the genesis
        # hash (or whatever expected_tip says — empty means no tip).
        if expected_tip not in (None, GENESIS_HASH):
            return ChainResult(
                ok=False, length=0, tip=GENESIS_HASH, break_at=None,
                reason="empty_chain_but_tip_claimed",
            )
        return ChainResult(ok=True, length=0, tip=GENESIS_HASH)

    # Detect legacy logs — no chain fields anywhere. We accept them as
    # OK with legacy=True so this can be enabled incrementally without
    # invalidating last week's engagements.
    has_chain_fields = any(
        ("entry_hash" in a or "prev_hash" in a) for a in actions
    )
    if not has_chain_fields:
        return ChainResult(
            ok=True, length=len(actions), tip=GENESIS_HASH, legacy=True,
        )

    prev = GENESIS_HASH
    for i, a in enumerate(actions):
        # Both fields must be present once chaining is in effect.
        if "prev_hash" not in a:
            return ChainResult(
                ok=False, length=len(actions), tip=prev, break_at=i,
                reason="missing_prev_hash",
            )
        if "entry_hash" not in a:
            return ChainResult(
                ok=False, length=len(actions), tip=prev, break_at=i,
                reason="missing_entry_hash",
            )
        if a["prev_hash"] != prev:
            return ChainResult(
                ok=False, length=len(actions), tip=prev, break_at=i,
                reason="prev_hash_mismatch",
            )
        recomputed = canonical_hash(a)
        if a["entry_hash"] != recomputed:
            return ChainResult(
                ok=False, length=len(actions), tip=prev, break_at=i,
                reason="entry_hash_mismatch",
            )
        prev = a["entry_hash"]

    if expected_tip is not None and expected_tip != prev:
        return ChainResult(
            ok=False, length=len(actions), tip=prev, break_at=None,
            reason="chain_tip_mismatch_truncation_suspected",
        )

    return ChainResult(ok=True, length=len(actions), tip=prev)


# ---------------------------------------------------------------------------
# Session-level helpers
# ---------------------------------------------------------------------------

def stamp_session_chain(session_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Take a serialized session dict (with `actions_taken`), chain
    every action, and stamp `chain_tip` + `chain_length` on the session.

    Returns a NEW dict; caller's input is unchanged. Idempotent: calling
    twice produces the same chain (modulo identical actions_taken).
    """
    out = dict(session_dict)
    actions = list(out.get("actions_taken", []) or [])
    # Strip any pre-existing chain fields so we don't double-stamp.
    stripped = [
        {k: v for k, v in a.items() if k not in {"prev_hash", "entry_hash"}}
        for a in actions
    ]
    chained = chain_actions(stripped)
    out["actions_taken"] = chained
    out["chain_tip"] = chain_tip(chained)
    out["chain_length"] = len(chained)
    out["chain_version"] = 1
    return out


def verify_session(session_dict: Dict[str, Any]) -> ChainResult:
    """Convenience: pull `actions_taken` + `chain_tip` from a session
    dict and run `verify_chain`."""
    actions = session_dict.get("actions_taken", []) or []
    expected = session_dict.get("chain_tip")
    return verify_chain(actions, expected_tip=expected)
