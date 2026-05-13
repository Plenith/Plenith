"""JSON-backed enrollment store for MFA secrets.

Replaces the demo-secret derivation (`secret_for(username)` →
`SHA256(deployment_id ‖ username)`) with a real enrollment record:

    {
      "version": 1,
      "users": {
        "jdoe":    {"secret_b32": "JBSWY3DPEHPK3PXP", "enrolled_at": 1778600000, "label": "VertexLabs:jdoe"},
        "agarcia": {"secret_b32": "JFXGKICIM5JFG===", "enrolled_at": 1778600130, "label": "VertexLabs:agarcia"},
      },
      "revoked":   ["temp-contractor-2025"]
    }

The MFA gateway consults this file at every TOTP verify. Missing users
fall through to the demo-secret derivation (unless `strict_mode=True`),
so the dev fabric keeps working even before anyone is enrolled.

In production: replace this module with a call into your existing
enrollment service (Duo / Okta / Authy admin API). The contract is just
`get(username) -> bytes | None` and `verify(username, code) -> bool`.
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


_STORE_PATH_ENV = "MFA_ENROLLMENT_PATH"
_DEFAULT_PATH = Path("/mnt/state/mfa/enrollment.json")


@dataclass
class EnrollmentRecord:
    username: str
    secret_b32: str
    enrolled_at: int
    label: str

    def to_dict(self) -> dict:
        return {
            "secret_b32":  self.secret_b32,
            "enrolled_at": self.enrolled_at,
            "label":       self.label,
        }

    @classmethod
    def from_dict(cls, username: str, d: dict) -> "EnrollmentRecord":
        return cls(
            username=username,
            secret_b32=d["secret_b32"],
            enrolled_at=int(d.get("enrolled_at", 0)),
            label=d.get("label", username),
        )


class EnrollmentStore:
    """Atomic JSON read/write keyed on username. Concurrent writers are
    not supported — the MFA gateway is the sole writer in production
    (and even there, only via the enrollment CLI). Concurrent readers
    are fine; we re-read on every `get()` so the gateway picks up new
    enrollments without a restart."""

    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path) if path is not None else Path(
            os.environ.get(_STORE_PATH_ENV, _DEFAULT_PATH)
        )

    # --- I/O ---------------------------------------------------------

    def _read(self) -> dict:
        if not self.path.exists():
            return {"version": 1, "users": {}, "revoked": []}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"version": 1, "users": {}, "revoked": []}

    def _write(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Atomic write — render to a tmp file, then rename.
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self.path)

    # --- queries -----------------------------------------------------

    def get(self, username: str) -> Optional[EnrollmentRecord]:
        """Return the enrollment record for `username`, or None if not
        enrolled (or revoked)."""
        data = self._read()
        if username in data.get("revoked", []):
            return None
        rec = data.get("users", {}).get(username)
        if not rec:
            return None
        return EnrollmentRecord.from_dict(username, rec)

    def secret_bytes(self, username: str) -> Optional[bytes]:
        """Convenience: return the raw secret bytes (decoded base32)
        for `username`, or None if not enrolled."""
        rec = self.get(username)
        if not rec:
            return None
        # base32 may be padded or not; pad to a multiple of 8 before decode.
        padded = rec.secret_b32 + "=" * (-len(rec.secret_b32) % 8)
        try:
            return base64.b32decode(padded.upper())
        except (ValueError, binascii.Error):
            return None

    def list_users(self) -> list[str]:
        return sorted(self._read().get("users", {}).keys())

    def list_revoked(self) -> list[str]:
        return sorted(self._read().get("revoked", []))

    # --- mutations ---------------------------------------------------

    def add(self, username: str, *, label: Optional[str] = None,
            secret_b32: Optional[str] = None) -> EnrollmentRecord:
        """Enroll a user. If `secret_b32` is None, generate a fresh
        20-byte secret (RFC 6238 standard length). Idempotent: if the
        user is already enrolled, return the existing record.
        """
        data = self._read()
        users = data.setdefault("users", {})
        if username in users:
            return EnrollmentRecord.from_dict(username, users[username])

        if secret_b32 is None:
            secret_b32 = base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")

        # Un-revoke if previously revoked
        revoked = data.setdefault("revoked", [])
        if username in revoked:
            revoked.remove(username)

        rec_dict = {
            "secret_b32":  secret_b32,
            "enrolled_at": int(time.time()),
            "label":       label or username,
        }
        users[username] = rec_dict
        self._write(data)
        return EnrollmentRecord.from_dict(username, rec_dict)

    def revoke(self, username: str) -> bool:
        """Mark a user as revoked. Returns True if they were previously
        enrolled (and now they're not), False if there was nothing to do."""
        data = self._read()
        users = data.setdefault("users", {})
        if username not in users:
            return False
        del users[username]
        revoked = data.setdefault("revoked", [])
        if username not in revoked:
            revoked.append(username)
        self._write(data)
        return True


# ---------------------------------------------------------------------------
# otpauth:// URI builder — what authenticator apps scan.
# ---------------------------------------------------------------------------

def otpauth_uri(record: EnrollmentRecord, issuer: str = "Plenith") -> str:
    """Build the standard otpauth://totp/... URI a TOTP app pastes or
    scans. The QR-code CLI in tools/mfa_enroll.py renders this to a
    block-art QR you can scan from a phone camera."""
    from urllib.parse import quote
    label = quote(f"{issuer}:{record.label}")
    return (
        f"otpauth://totp/{label}"
        f"?secret={record.secret_b32}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"
    )
