"""RFC 6238 TOTP, stdlib only.

Six-digit code derived from HMAC-SHA1(secret, floor(unix_time / 30)).
Used by the MFA gateway to validate the code an SSH user types.

We accept a ±1-step (30s) window on either side of `now` to tolerate
clock skew — same default as Google Authenticator. Past that, codes
expire. That bound also defeats trivial replay (a code that worked
60 seconds ago no longer works).

For the dev demo we derive the per-user secret deterministically from
(deployment_id, username). In production, secrets come from an
enrollment service (Duo / Okta / Authy admin API) and live in a vault.
"""
import base64
import hashlib
import hmac
import os
import struct
import time
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Core TOTP
# ---------------------------------------------------------------------------

def _hotp(secret_bytes: bytes, counter: int, digits: int = 6) -> str:
    """RFC 4226 HOTP — the building block under TOTP."""
    msg = struct.pack(">Q", counter)
    h = hmac.new(secret_bytes, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = (
        ((h[offset]     & 0x7F) << 24)
        | ((h[offset + 1] & 0xFF) << 16)
        | ((h[offset + 2] & 0xFF) << 8)
        |  (h[offset + 3] & 0xFF)
    )
    return f"{code % (10 ** digits):0{digits}d}"


def totp_now(secret_bytes: bytes, period: int = 30, digits: int = 6,
             clock: float | None = None) -> str:
    """Current TOTP code at `clock` (or wall-clock if None)."""
    t = int((clock if clock is not None else time.time()) // period)
    return _hotp(secret_bytes, t, digits)


def totp_verify(secret_bytes: bytes, code: str, *, window: int = 1,
                period: int = 30, digits: int = 6,
                clock: float | None = None) -> bool:
    """Accept `code` if it matches the current step or any step in
    [now - window, now + window]. Window=1 ⇒ ±30s of skew tolerance.

    Constant-time compare to avoid microbenchmarking the per-digit match.
    """
    if not code or not code.isdigit() or len(code) != digits:
        return False
    t_now = int((clock if clock is not None else time.time()) // period)
    for delta in range(-window, window + 1):
        expected = _hotp(secret_bytes, t_now + delta, digits)
        if hmac.compare_digest(expected, code):
            return True
    return False


# ---------------------------------------------------------------------------
# Demo-secret derivation. The MFA gateway calls this so we don't need a
# real enrollment store for the dev fabric.
# ---------------------------------------------------------------------------

@dataclass
class DemoSecret:
    """Deterministic per-user secret for the dev fabric. Real deployments
    swap this out for an enrollment-backed lookup; the gateway shouldn't
    care which source it came from."""
    deployment_id: str
    username: str

    def bytes(self) -> bytes:
        # 20 bytes is the standard RFC 6238 secret length.
        material = f"{self.deployment_id}\x1f{self.username}".encode("utf-8")
        return hashlib.sha256(material).digest()[:20]

    def base32(self) -> str:
        """Format the secret as a base32 string (what Google Authenticator
        and otpauth:// URIs expect)."""
        return base64.b32encode(self.bytes()).decode("ascii").rstrip("=")

    def current_code(self, clock: float | None = None) -> str:
        return totp_now(self.bytes(), clock=clock)

    def verify(self, code: str, *, window: int = 1) -> bool:
        return totp_verify(self.bytes(), code, window=window)


def secret_for(username: str, deployment_id: str | None = None) -> DemoSecret:
    """Convenience: pick deployment_id from env if not passed explicitly.
    Falls back to `dev-fabric` so unit tests don't need env setup.

    Note: callers in the gateway hot-path should prefer `resolve_secret()`
    below, which consults the enrollment store first and falls through
    to this demo derivation only for unenrolled users."""
    dep = deployment_id or os.environ.get("PLENITH_DEPLOYMENT_ID") or "dev-fabric"
    return DemoSecret(deployment_id=dep, username=username)


def resolve_secret(username: str, deployment_id: str | None = None,
                   *, allow_demo_fallback: bool = True):
    """Return an object with a `.verify(code, window=...)` method for the
    user. Consults the JSON enrollment store first; falls back to demo
    derivation when the user isn't enrolled. Returns None when there's
    no secret available AND fallback is disabled.

    This is the single entrypoint the gateway uses, so production
    deployments can flip `allow_demo_fallback=False` and reject any
    user not in the enrollment store.
    """
    # Lazy import to keep totp.py importable without enrollment.py
    # being on PYTHONPATH (the unit tests don't need it).
    try:
        from enrollment import EnrollmentStore  # type: ignore
    except ImportError:
        EnrollmentStore = None  # type: ignore

    if EnrollmentStore is not None:
        store = EnrollmentStore()
        rec = store.get(username)
        if rec is not None:
            return _EnrolledSecret(rec, store)

    if allow_demo_fallback:
        return secret_for(username, deployment_id)
    return None


class _EnrolledSecret:
    """Wraps an EnrollmentRecord with the same `.verify(...)` /
    `.current_code(...)` shape that DemoSecret exposes, so callers
    don't have to branch on the source."""
    def __init__(self, record, store):
        self._record = record
        self._store = store
        self._bytes = store.secret_bytes(record.username)

    def bytes(self) -> bytes:
        return self._bytes or b""

    def base32(self) -> str:
        return self._record.secret_b32

    def current_code(self, clock: float | None = None) -> str:
        return totp_now(self.bytes(), clock=clock)

    def verify(self, code: str, *, window: int = 1) -> bool:
        if not self._bytes:
            return False
        return totp_verify(self._bytes, code, window=window)
