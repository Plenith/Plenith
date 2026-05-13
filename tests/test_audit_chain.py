"""Tests for hash-chained audit logging.

Three layers covered:

  1. `plenith.audit_chain` pure-function math — canonical_hash,
     chain_actions, verify_chain, stamp_session_chain.
  2. The integration into `session_logger.write_session_log` — a
     log file on disk has the chain fields and verifies clean.
  3. The `tools/verify_chain.py` CLI — exits 0 for clean trees, 1
     for tampered, 2 for missing paths.

Tamper scenarios specifically exercised:
  - Modify an entry in place
  - Delete an entry from the middle
  - Delete the tail entry (truncation attack)
  - Insert a fake entry
  - Re-order entries
  - Legacy (un-chained) log accepted with status=legacy
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from plenith.audit_chain import (
    GENESIS_HASH,
    canonical_hash,
    chain_actions,
    chain_entry,
    chain_tip,
    stamp_session_chain,
    verify_chain,
    verify_session,
)


# ---------------------------------------------------------------------------
# Pure-function math
# ---------------------------------------------------------------------------

class TestCanonicalHash:
    def test_stable_under_key_reordering(self):
        """Same content, different dict insertion order → same hash."""
        a = {"action": "x", "severity": "high", "rationale": "r"}
        b = {"rationale": "r", "action": "x", "severity": "high"}
        assert canonical_hash(a) == canonical_hash(b)

    def test_changes_when_content_changes(self):
        a = {"action": "x", "severity": "high"}
        b = {"action": "x", "severity": "critical"}
        assert canonical_hash(a) != canonical_hash(b)

    def test_ignores_entry_hash_field(self):
        """We strip entry_hash before hashing so callers don't need to."""
        a = {"action": "x", "entry_hash": "deadbeef"}
        b = {"action": "x", "entry_hash": "feedface"}
        assert canonical_hash(a) == canonical_hash(b)

    def test_handles_sets_deterministically(self):
        """Python sets have non-deterministic iteration order; the
        hash function sorts them so chain output is reproducible."""
        a = {"files": {"b.txt", "a.txt", "c.txt"}}
        b = {"files": {"c.txt", "a.txt", "b.txt"}}
        assert canonical_hash(a) == canonical_hash(b)

    def test_produces_64_char_hex(self):
        h = canonical_hash({"x": 1})
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)


# ---------------------------------------------------------------------------
# Building the chain
# ---------------------------------------------------------------------------

class TestChainActions:
    def test_empty_input_returns_empty(self):
        assert chain_actions([]) == []

    def test_first_entry_uses_genesis_prev_hash(self):
        chained = chain_actions([{"action": "x"}])
        assert chained[0]["prev_hash"] == GENESIS_HASH
        assert "entry_hash" in chained[0]

    def test_subsequent_entries_link_back(self):
        actions = [{"action": "a"}, {"action": "b"}, {"action": "c"}]
        chained = chain_actions(actions)
        assert chained[1]["prev_hash"] == chained[0]["entry_hash"]
        assert chained[2]["prev_hash"] == chained[1]["entry_hash"]

    def test_input_not_mutated(self):
        original = [{"action": "x"}]
        snapshot = dict(original[0])
        chain_actions(original)
        assert original[0] == snapshot   # untouched

    def test_chain_tip_helper(self):
        actions = chain_actions([{"action": "a"}, {"action": "b"}])
        assert chain_tip(actions) == actions[-1]["entry_hash"]
        assert chain_tip([]) == GENESIS_HASH


# ---------------------------------------------------------------------------
# Verification — happy path
# ---------------------------------------------------------------------------

class TestVerifyChain:
    def test_clean_chain_verifies(self):
        chained = chain_actions([{"a": 1}, {"a": 2}, {"a": 3}])
        r = verify_chain(chained)
        assert r.ok is True
        assert r.length == 3
        assert r.tip == chained[-1]["entry_hash"]
        assert r.legacy is False

    def test_empty_chain_is_valid(self):
        r = verify_chain([])
        assert r.ok is True
        assert r.length == 0
        assert r.tip == GENESIS_HASH

    def test_expected_tip_match(self):
        chained = chain_actions([{"a": 1}, {"a": 2}])
        tip = chained[-1]["entry_hash"]
        r = verify_chain(chained, expected_tip=tip)
        assert r.ok is True


# ---------------------------------------------------------------------------
# Verification — tamper scenarios
# ---------------------------------------------------------------------------

class TestTamperDetection:
    def test_modified_entry_detected(self):
        """Mutate the content of entry 1 → entry_hash no longer matches."""
        chained = chain_actions([{"a": 1}, {"a": 2}, {"a": 3}])
        chained[1]["a"] = 999    # tamper
        r = verify_chain(chained)
        assert r.ok is False
        assert r.break_at == 1
        # The first hash check that fails is the entry_hash recompute,
        # not the prev_hash chain (because prev_hash is still the
        # untouched entry_hash of #0).
        assert r.reason == "entry_hash_mismatch"

    def test_deleted_middle_entry_detected(self):
        """Drop entry 1; entry 2's prev_hash references the dropped one."""
        chained = chain_actions([{"a": 1}, {"a": 2}, {"a": 3}])
        truncated = [chained[0], chained[2]]   # remove index 1
        r = verify_chain(truncated)
        assert r.ok is False
        assert r.break_at == 1
        assert r.reason == "prev_hash_mismatch"

    def test_truncated_tail_detected_via_expected_tip(self):
        """Truncating the tail leaves the chain self-consistent, but
        the session-level `chain_tip` no longer matches."""
        chained = chain_actions([{"a": 1}, {"a": 2}, {"a": 3}])
        real_tip = chained[-1]["entry_hash"]
        truncated = chained[:-1]    # drop the tail
        r = verify_chain(truncated, expected_tip=real_tip)
        assert r.ok is False
        assert r.reason == "chain_tip_mismatch_truncation_suspected"

    def test_inserted_fake_entry_detected(self):
        chained = chain_actions([{"a": 1}, {"a": 2}])
        fake = {"a": "EVIL", "prev_hash": chained[0]["entry_hash"]}
        fake["entry_hash"] = canonical_hash(fake)
        # Splice the fake between entries 0 and 1
        with_fake = [chained[0], fake, chained[1]]
        r = verify_chain(with_fake)
        assert r.ok is False
        # The break is at index 2 — chained[1]'s prev_hash no longer
        # matches `fake`'s entry_hash.
        assert r.break_at == 2

    def test_reorder_detected(self):
        chained = chain_actions([{"a": 1}, {"a": 2}, {"a": 3}])
        reordered = [chained[0], chained[2], chained[1]]
        r = verify_chain(reordered)
        assert r.ok is False
        # chained[2] was originally entry #2 with prev_hash pointing
        # at chained[1].entry_hash. After reorder it's at slot 1, where
        # the expected prev is chained[0].entry_hash — so we break at
        # slot 1 with a prev_hash_mismatch.
        assert r.break_at == 1
        assert r.reason == "prev_hash_mismatch"

    def test_missing_chain_fields_on_v1_log(self):
        """A log claiming to be v1 (some entries chained) but missing
        chain fields on some others is broken."""
        chained = chain_actions([{"a": 1}, {"a": 2}])
        # Strip chain fields off entry 1
        chained[1].pop("entry_hash")
        r = verify_chain(chained)
        assert r.ok is False
        assert r.break_at == 1
        assert r.reason == "missing_entry_hash"


# ---------------------------------------------------------------------------
# Legacy logs
# ---------------------------------------------------------------------------

class TestLegacy:
    def test_unchained_log_accepted_as_legacy(self):
        """Logs predating the feature have no chain fields. Verifier
        returns ok=True, legacy=True so the rollout can be gradual."""
        r = verify_chain([{"action": "x"}, {"action": "y"}])
        assert r.ok is True
        assert r.legacy is True
        assert r.length == 2


# ---------------------------------------------------------------------------
# stamp_session_chain
# ---------------------------------------------------------------------------

class TestStampSession:
    def test_basic_stamp(self):
        session = {
            "id": "x",
            "actions_taken": [
                {"action": "a", "severity": "high"},
                {"action": "b", "severity": "info"},
            ],
        }
        out = stamp_session_chain(session)
        assert out["chain_length"] == 2
        assert out["chain_version"] == 1
        assert out["chain_tip"] == out["actions_taken"][-1]["entry_hash"]
        # And verify_session round-trips
        assert verify_session(out).ok is True

    def test_empty_actions(self):
        out = stamp_session_chain({"id": "x", "actions_taken": []})
        assert out["chain_tip"] == GENESIS_HASH
        assert out["chain_length"] == 0
        assert verify_session(out).ok is True

    def test_idempotent_under_re_stamp(self):
        """Stamping twice — even if the first stamp left chain fields
        in place — produces the same tip."""
        actions = [{"action": "a"}, {"action": "b"}]
        once = stamp_session_chain({"actions_taken": actions})
        twice = stamp_session_chain(once)
        assert once["chain_tip"] == twice["chain_tip"]
        assert verify_session(twice).ok is True

    def test_input_not_mutated(self):
        session = {"actions_taken": [{"action": "a"}]}
        snapshot = json.dumps(session, sort_keys=True)
        stamp_session_chain(session)
        # Original survives
        assert json.dumps(session, sort_keys=True) == snapshot


# ---------------------------------------------------------------------------
# Integration: session_logger writes chained logs
# ---------------------------------------------------------------------------

class _FakeSession:
    """The bare minimum surface `write_session_log` reads."""

    def __init__(self, eid, actions):
        self.id = "fake-id"
        self.started_at = 1700000000.0
        self.engagement_id = eid
        self._actions = list(actions)

    def to_dict(self):
        return {
            "id":           self.id,
            "engagement_id": self.engagement_id,
            "actions_taken": list(self._actions),
        }


class TestSessionLoggerIntegration:
    def test_log_file_is_chained(self, tmp_path):
        from plenith.session_logger import write_session_log

        sess = _FakeSession("eng-1", [
            {"action": "alert_credential_exfil", "severity": "high"},
            {"action": "alert_dns_exfil",        "severity": "high"},
        ])
        path = write_session_log(tmp_path, sess)
        assert path.exists()
        data = json.loads(path.read_text(encoding="utf-8"))
        # Chain fields are present
        assert "chain_tip" in data
        assert "chain_length" in data
        assert data["chain_length"] == 2
        for a in data["actions_taken"]:
            assert "prev_hash" in a
            assert "entry_hash" in a
        # And verifies clean
        assert verify_session(data).ok is True

    def test_empty_session_still_writes_chain_tip(self, tmp_path):
        from plenith.session_logger import write_session_log
        sess = _FakeSession("eng-empty", [])
        path = write_session_log(tmp_path, sess)
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["chain_tip"] == GENESIS_HASH
        assert data["chain_length"] == 0


# ---------------------------------------------------------------------------
# CLI: tools/verify_chain.py
# ---------------------------------------------------------------------------

def _load_cli():
    """Side-load tools/verify_chain.py the same way other tool tests do."""
    spec = importlib.util.spec_from_file_location(
        "verify_chain",
        Path(__file__).resolve().parent.parent / "tools" / "verify_chain.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestVerifyChainCLI:
    def test_clean_directory_exits_zero(self, tmp_path, capsys):
        # Write a clean chained log
        log = stamp_session_chain({
            "engagement_id": "eng-1",
            "actions_taken": [{"action": "a"}, {"action": "b"}],
        })
        (tmp_path / "clean.json").write_text(json.dumps(log),
                                              encoding="utf-8")

        cli = _load_cli()
        rc = cli.main([str(tmp_path)])
        out = capsys.readouterr().out
        assert rc == cli.EXIT_OK
        assert "1 OK" in out

    def test_tampered_log_exits_nonzero(self, tmp_path, capsys):
        log = stamp_session_chain({
            "engagement_id": "eng-1",
            "actions_taken": [{"action": "a"}, {"action": "b"}],
        })
        # Tamper: rewrite the rationale on action 0 without re-chaining
        log["actions_taken"][0]["action"] = "EVIL"
        (tmp_path / "tampered.json").write_text(json.dumps(log),
                                                 encoding="utf-8")

        cli = _load_cli()
        rc = cli.main([str(tmp_path)])
        out = capsys.readouterr().out
        assert rc == cli.EXIT_BROKEN
        assert "BROKEN" in out

    def test_legacy_default_passes(self, tmp_path, capsys):
        # A log with no chain fields at all
        (tmp_path / "legacy.json").write_text(json.dumps({
            "engagement_id": "eng-legacy",
            "actions_taken": [{"action": "a"}, {"action": "b"}],
        }), encoding="utf-8")

        cli = _load_cli()
        rc = cli.main([str(tmp_path)])
        out = capsys.readouterr().out
        assert rc == cli.EXIT_OK
        assert "LEGACY" in out

    def test_legacy_strict_fails(self, tmp_path, capsys):
        (tmp_path / "legacy.json").write_text(json.dumps({
            "engagement_id": "eng-legacy",
            "actions_taken": [{"action": "a"}],
        }), encoding="utf-8")

        cli = _load_cli()
        rc = cli.main([str(tmp_path), "--no-allow-legacy"])
        assert rc == cli.EXIT_BROKEN

    def test_missing_path_exits_two(self, tmp_path, capsys):
        cli = _load_cli()
        rc = cli.main([str(tmp_path / "does-not-exist")])
        err = capsys.readouterr().err
        assert rc == cli.EXIT_BAD_ARGS
        assert "does not exist" in err

    def test_json_output(self, tmp_path, capsys):
        log = stamp_session_chain({
            "engagement_id": "eng-1",
            "actions_taken": [{"action": "a"}],
        })
        (tmp_path / "ok.json").write_text(json.dumps(log), encoding="utf-8")

        cli = _load_cli()
        rc = cli.main([str(tmp_path), "--json"])
        out = capsys.readouterr().out
        payload = json.loads(out)
        assert rc == cli.EXIT_OK
        assert payload["total"] == 1
        assert payload["ok"] == 1

    def test_invalid_json_file_marked_broken(self, tmp_path, capsys):
        (tmp_path / "garbage.json").write_text("not json", encoding="utf-8")
        cli = _load_cli()
        rc = cli.main([str(tmp_path), "--json"])
        out = capsys.readouterr().out
        payload = json.loads(out)
        assert rc == cli.EXIT_BROKEN
        assert payload["broken"] == 1
        assert payload["records"][0]["status"] == "invalid_json"
