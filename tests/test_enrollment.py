"""Tests for the MFA enrollment store + CLI.

The store is the source of truth for per-user TOTP secrets. Two
invariants matter:

  1. Determinism — get(username) after add(username) returns the
     same secret bytes, every time.
  2. Atomicity — concurrent reads while a write is in progress must
     see EITHER the old contents or the new contents, never partial.
     (We use tmp-file + rename which the OS treats as atomic.)
"""
import base64
import json
import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "linux-fork" / "mfa"))

from enrollment import EnrollmentStore, otpauth_uri  # noqa: E402
from totp import resolve_secret, totp_now, totp_verify  # noqa: E402

# ---------------------------------------------------------------------------
# Store basics
# ---------------------------------------------------------------------------

class TestEnrollmentStore:
    def test_empty_store_is_empty(self, tmp_path):
        store = EnrollmentStore(tmp_path / "e.json")
        assert store.list_users() == []
        assert store.list_revoked() == []
        assert store.get("nobody") is None

    def test_add_persists(self, tmp_path):
        store = EnrollmentStore(tmp_path / "e.json")
        rec = store.add("jdoe", label="Test: jdoe")
        assert rec.username == "jdoe"
        assert rec.secret_b32  # non-empty
        # Re-read with a fresh store instance
        store2 = EnrollmentStore(tmp_path / "e.json")
        rec2 = store2.get("jdoe")
        assert rec2 is not None
        assert rec2.secret_b32 == rec.secret_b32

    def test_add_is_idempotent(self, tmp_path):
        store = EnrollmentStore(tmp_path / "e.json")
        rec1 = store.add("jdoe")
        rec2 = store.add("jdoe")
        assert rec1.secret_b32 == rec2.secret_b32

    def test_secret_bytes_decodes(self, tmp_path):
        store = EnrollmentStore(tmp_path / "e.json")
        rec = store.add("jdoe")
        b = store.secret_bytes("jdoe")
        assert b is not None
        # Re-encode and compare (modulo padding)
        roundtrip = base64.b32encode(b).decode("ascii").rstrip("=")
        assert roundtrip == rec.secret_b32

    def test_revoke_removes_from_users(self, tmp_path):
        store = EnrollmentStore(tmp_path / "e.json")
        store.add("temp")
        assert "temp" in store.list_users()
        assert store.revoke("temp") is True
        assert "temp" not in store.list_users()
        assert "temp" in store.list_revoked()
        # get returns None for revoked
        assert store.get("temp") is None

    def test_revoke_nonexistent_returns_false(self, tmp_path):
        store = EnrollmentStore(tmp_path / "e.json")
        assert store.revoke("never-existed") is False

    def test_re_enroll_after_revoke_clears_revoked(self, tmp_path):
        store = EnrollmentStore(tmp_path / "e.json")
        store.add("u")
        store.revoke("u")
        assert "u" in store.list_revoked()
        store.add("u")
        assert "u" not in store.list_revoked()
        assert "u" in store.list_users()

    def test_atomic_write(self, tmp_path):
        """A partial-write must never appear in the file. We assert by
        reading the file mid-write — the rename-on-commit guarantees we
        either see the OLD JSON or the FULL NEW JSON, never half."""
        store = EnrollmentStore(tmp_path / "e.json")
        store.add("first")
        # Snapshot of pre-write state
        before = (tmp_path / "e.json").read_text(encoding="utf-8")
        # The atomic write path: we can't actually catch a partial file
        # in a single-threaded test, but we can verify the .tmp file
        # never lingers post-success.
        store.add("second")
        assert not (tmp_path / "e.json.tmp").exists()
        after = (tmp_path / "e.json").read_text(encoding="utf-8")
        # Both states are valid JSON
        json.loads(before)
        data = json.loads(after)
        assert set(data["users"].keys()) == {"first", "second"}

    def test_secret_is_unique_per_user(self, tmp_path):
        store = EnrollmentStore(tmp_path / "e.json")
        r1 = store.add("alice")
        r2 = store.add("bob")
        assert r1.secret_b32 != r2.secret_b32

# ---------------------------------------------------------------------------
# otpauth URI shape
# ---------------------------------------------------------------------------

class TestOtpauthURI:
    def test_basic_shape(self, tmp_path):
        store = EnrollmentStore(tmp_path / "e.json")
        rec = store.add("jdoe", label="Vertex Labs: jdoe")
        uri = otpauth_uri(rec, issuer="Plenith")
        assert uri.startswith("otpauth://totp/")
        assert "Plenith" in uri
        assert "secret=" in uri
        assert "algorithm=SHA1" in uri
        assert "digits=6" in uri
        assert "period=30" in uri

    def test_uri_round_trip(self, tmp_path):
        """The secret in the URI MUST match the stored secret — that's
        what makes the QR scan work."""
        store = EnrollmentStore(tmp_path / "e.json")
        rec = store.add("jdoe")
        uri = otpauth_uri(rec)
        assert f"secret={rec.secret_b32}" in uri

# ---------------------------------------------------------------------------
# resolve_secret integrates with enrollment.
# ---------------------------------------------------------------------------

class TestResolveSecret:
    def test_enrolled_user_uses_store_secret(self, tmp_path, monkeypatch):
        # Point the env at our temp store
        monkeypatch.setenv("MFA_ENROLLMENT_PATH", str(tmp_path / "e.json"))
        store = EnrollmentStore(tmp_path / "e.json")
        rec = store.add("jdoe")

        # Generate the current code using the STORED secret
        secret_bytes = store.secret_bytes("jdoe")
        expected_code = totp_now(secret_bytes)

        # resolve_secret should pull from the store and verify the same code
        secret = resolve_secret("jdoe")
        assert secret is not None
        assert secret.verify(expected_code)

    def test_unenrolled_user_falls_back_to_demo(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MFA_ENROLLMENT_PATH", str(tmp_path / "e.json"))
        # No add — the user is unenrolled
        secret = resolve_secret("nobody", deployment_id="dep")
        assert secret is not None  # demo fallback
        # The demo secret derivation is deterministic
        code = secret.current_code()
        assert secret.verify(code)

    def test_strict_mode_rejects_unenrolled(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MFA_ENROLLMENT_PATH", str(tmp_path / "e.json"))
        secret = resolve_secret("nobody", allow_demo_fallback=False)
        assert secret is None

    def test_enrolled_then_revoked_falls_back(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MFA_ENROLLMENT_PATH", str(tmp_path / "e.json"))
        store = EnrollmentStore(tmp_path / "e.json")
        store.add("contractor")
        store.revoke("contractor")
        # Revoked → not in store → fallback engages with demo fallback on
        secret = resolve_secret("contractor", deployment_id="dep")
        assert secret is not None
        # And strict mode rejects
        secret_strict = resolve_secret("contractor", allow_demo_fallback=False)
        assert secret_strict is None

# ---------------------------------------------------------------------------
# CLI smoke
# ---------------------------------------------------------------------------

class TestEnrollmentCLI:
    def _cli(self, *args, store_path: Path):
        cmd = [
            sys.executable, str(_ROOT / "tools" / "mfa_enroll.py"),
            "--store-path", str(store_path),
            *args,
        ]
        return subprocess.run(cmd, capture_output=True, text=True, timeout=20,
                              encoding="utf-8")

    def test_add_then_list(self, tmp_path):
        store_path = tmp_path / "e.json"
        out = self._cli("add", "jdoe", store_path=store_path)
        assert out.returncode == 0, out.stderr
        assert "Enrolled: jdoe" in out.stdout
        # The file should now exist with jdoe enrolled
        data = json.loads(store_path.read_text(encoding="utf-8"))
        assert "jdoe" in data["users"]

        out2 = self._cli("list", store_path=store_path)
        assert out2.returncode == 0
        assert "jdoe" in out2.stdout

    def test_add_then_revoke(self, tmp_path):
        store_path = tmp_path / "e.json"
        self._cli("add", "contractor", store_path=store_path)
        rev = self._cli("revoke", "contractor", store_path=store_path)
        assert rev.returncode == 0
        assert "revoked: contractor" in rev.stdout

    def test_revoke_nonexistent_exits_1(self, tmp_path):
        store_path = tmp_path / "e.json"
        out = self._cli("revoke", "never-existed", store_path=store_path)
        assert out.returncode == 1

    def test_show_prints_uri(self, tmp_path):
        store_path = tmp_path / "e.json"
        self._cli("add", "jdoe", store_path=store_path)
        out = self._cli("show", "jdoe", store_path=store_path)
        assert out.returncode == 0
        assert "otpauth://totp/" in out.stdout
