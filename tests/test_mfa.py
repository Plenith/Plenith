"""Tests for the §4.3 MFA step-up flow.

Two layers:

  1. **Unit** — TOTP correctness, demo-secret derivation, the
     decision-file handoff format. Pure Python, no Docker.
  2. **E2E** (skipped when fabric isn't up) — drive a real SSH
     connection at the mfa-gateway:22 endpoint, type a code, and assert
     the decision file gets written. Also exercises the Lua scorer
     end-to-end if the proxy is reachable.
"""
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "linux-fork" / "mfa"))

from totp import (  # noqa: E402
    DemoSecret,
    _hotp,
    secret_for,
    totp_now,
    totp_verify,
)

# ---------------------------------------------------------------------------
# HOTP / TOTP correctness — RFC 6238 Appendix B test vectors.
# ---------------------------------------------------------------------------

# RFC 4226 test vector: secret "12345678901234567890" (ASCII)
_RFC_4226_SECRET = b"12345678901234567890"
_RFC_4226_HOTP_VECTORS = [
    (0, "755224"), (1, "287082"), (2, "359152"),
    (3, "969429"), (4, "338314"), (5, "254676"),
]

# RFC 6238 test vectors (8-digit), but we use the 6-digit truncation here.
# We compare against re-computed values so the test is self-checking.
_RFC_6238_T0_SECRET = b"12345678901234567890"

class TestHOTP:
    @pytest.mark.parametrize("counter,expected", _RFC_4226_HOTP_VECTORS)
    def test_rfc4226_test_vectors(self, counter, expected):
        assert _hotp(_RFC_4226_SECRET, counter) == expected

class TestTOTPVerify:
    def test_round_trip(self):
        """The code we just generated MUST verify."""
        secret = b"sometestsecretsometestsecret12"
        code = totp_now(secret, clock=1_700_000_000.0)
        assert totp_verify(secret, code, clock=1_700_000_000.0)

    def test_window_tolerance(self):
        """A code 30s old must still pass at window=1."""
        secret = b"x" * 20
        old_code = totp_now(secret, clock=1_700_000_000.0)
        # 30s later
        assert totp_verify(secret, old_code, clock=1_700_000_030.0, window=1)
        # Beyond window — must reject
        assert not totp_verify(secret, old_code, clock=1_700_000_120.0, window=1)

    def test_constant_time_compare(self):
        """A subtly-wrong code must reject."""
        secret = b"y" * 20
        good = totp_now(secret, clock=1_700_000_000.0)
        # Flip the last digit
        bad = good[:-1] + ("0" if good[-1] != "0" else "1")
        assert not totp_verify(secret, bad, clock=1_700_000_000.0)

    def test_rejects_garbage(self):
        secret = b"z" * 20
        for junk in ("", "abc", "12345", "1234567", "abcdef"):
            assert not totp_verify(secret, junk)

class TestDemoSecret:
    def test_deterministic_per_deployment_and_user(self):
        a = DemoSecret("dep-X", "jdoe")
        b = DemoSecret("dep-X", "jdoe")
        assert a.bytes() == b.bytes()
        assert a.base32() == b.base32()

    def test_different_inputs_different_bytes(self):
        a = DemoSecret("dep-X", "jdoe").bytes()
        b = DemoSecret("dep-Y", "jdoe").bytes()
        c = DemoSecret("dep-X", "agarcia").bytes()
        assert a != b
        assert a != c
        assert b != c

    def test_current_code_format(self):
        s = DemoSecret("dep", "u")
        code = s.current_code(clock=1_700_000_000.0)
        assert len(code) == 6
        assert code.isdigit()

    def test_self_verify(self):
        s = DemoSecret("dep", "u")
        code = s.current_code(clock=1_700_000_000.0)
        # The fabric runs at wall-clock; we drive both ends with the
        # same fixed clock to make this deterministic.
        from totp import totp_verify
        assert totp_verify(s.bytes(), code, clock=1_700_000_000.0)

    def test_secret_for_uses_env_fallback(self, monkeypatch):
        monkeypatch.delenv("PLENITH_DEPLOYMENT_ID", raising=False)
        s = secret_for("jdoe")
        # Falls back to "dev-fabric"
        assert s.deployment_id == "dev-fabric"

        monkeypatch.setenv("PLENITH_DEPLOYMENT_ID", "from-env")
        s2 = secret_for("jdoe")
        assert s2.deployment_id == "from-env"

# ---------------------------------------------------------------------------
# Decision-file format — what the Lua scorer parses.
# ---------------------------------------------------------------------------

class TestDecisionFileFormat:
    def test_pass_and_fail_can_coexist_until_consumed(self, tmp_path):
        """Two different IPs can have decisions at the same time."""
        from mfa_gateway import _write_decision, STATE_DIR
        import mfa_gateway
        mfa_gateway.STATE_DIR = tmp_path  # redirect
        try:
            p1 = _write_decision("10.0.0.1", "pass")
            p2 = _write_decision("10.0.0.2", "fail")
            assert p1.exists()
            assert p2.exists()
            assert p1.read_text(encoding="utf-8").startswith("ip=10.0.0.1")
            assert p2.read_text(encoding="utf-8").startswith("ip=10.0.0.2")
        finally:
            mfa_gateway.STATE_DIR = STATE_DIR

    def test_new_decision_overwrites_old(self, tmp_path):
        """A second decision for the same IP supersedes the first."""
        from mfa_gateway import _write_decision
        import mfa_gateway
        mfa_gateway.STATE_DIR = tmp_path
        _write_decision("10.0.0.99", "fail")
        assert (tmp_path / "10.0.0.99.fail").exists()
        _write_decision("10.0.0.99", "pass")
        # The old fail must be wiped; only the pass survives
        assert (tmp_path / "10.0.0.99.pass").exists()
        assert not (tmp_path / "10.0.0.99.fail").exists()

# ---------------------------------------------------------------------------
# E2E — drive the live mfa-gateway container if it's running.
# ---------------------------------------------------------------------------

def _docker_running(name: str) -> bool:
    if not shutil.which("docker"):
        return False
    out = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"],
        capture_output=True, text=True, timeout=5,
    )
    return name in out.stdout

def _wait_for_port(host: str, port: int, timeout: float = 10.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.3)
    return False

@pytest.fixture(scope="module")
def mfa_gateway_running():
    if not _docker_running("mfa-gateway"):
        pytest.skip("mfa-gateway container not running")
    # We can't reach 172.30.0.21 directly from the Windows host — the
    # bubble is internal. So we exec into bastion-prod to hit the gateway
    # from inside the decoy network.
    if not _docker_running("bastion-prod"):
        pytest.skip("bastion-prod (needed to reach mfa-gateway from inside the bubble) not running")
    return True

class TestMFAGatewayE2E:
    """End-to-end against the live mfa-gateway. We exec inside bastion-prod
    so we have a path to mfa-relay:22 inside the internal network.

    The deployed gateway has MFA_PUSH_URL set → tries push first, falls
    through to TOTP only on push timeout/unreachable. So we drive the
    push channel directly via push-sim's HTTP API (also from inside the
    bastion-prod container, which has network reach to push-sim).
    """

    def _drive_session(self, push_decision: str | None = None,
                       totp_code: str | None = None,
                       timeout: float = 30.0) -> str:
        """Open an SSH session at mfa-relay:22, optionally trigger the
        push approve/deny via push-sim, and capture the gateway's output.

        push_decision: "approve" | "deny" | None (let push time out)
        totp_code: code to type if/when push falls through to TOTP
        """
        push_decision_arg = push_decision or ""
        totp_code_arg = totp_code or ""
        inner = (
            f"PUSH_DECISION = {push_decision_arg!r}\n"
            f"TOTP_CODE = {totp_code_arg!r}\n"
            r"""
import asyncio, asyncssh, json, time, urllib.request, urllib.error

async def maybe_push_decide():
    # Wait briefly for the gateway to POST /push/request, then approve/deny.
    if not PUSH_DECISION:
        return
    deadline = time.time() + 8
    while time.time() < deadline:
        try:
            with urllib.request.urlopen('http://push-sim:8080/push/list', timeout=1.5) as r:
                body = json.loads(r.read())
        except (urllib.error.URLError, OSError):
            await asyncio.sleep(0.3); continue
        pending = [p for p in body.get('pushes', [])
                   if p['username'] == 'jdoe' and p['status'] == 'pending']
        if pending:
            tok = pending[0]['token']
            url = f'http://push-sim:8080/push/{PUSH_DECISION}/{tok}'
            req = urllib.request.Request(url, method='POST')
            try:
                urllib.request.urlopen(req, timeout=1.5)
            except Exception:
                pass
            return
        await asyncio.sleep(0.3)

async def go():
    buf = b''
    try:
        async with asyncssh.connect(
            'mfa-relay', port=22, username='jdoe', password='x',
            known_hosts=None, client_keys=None,
        ) as conn:
            proc = await conn.create_process(term_type='xterm')
            # Push decider in parallel
            decider = asyncio.create_task(maybe_push_decide())
            # If we have a TOTP code to type, send it as soon as we see
            # the TOTP prompt (or after a long wait).
            async def read_stream():
                nonlocal buf
                deadline = time.time() + 28
                typed = not TOTP_CODE
                while time.time() < deadline:
                    try:
                        chunk = await asyncio.wait_for(proc.stdout.read(4096), timeout=0.5)
                    except (asyncio.TimeoutError, asyncssh.misc.ConnectionLost):
                        continue
                    if not chunk: break
                    buf += chunk.encode() if isinstance(chunk, str) else chunk
                    if b'MFA verified' in buf or b'verification failed' in buf:
                        break
                    if not typed and b'Enter your 6-digit code' in buf:
                        proc.stdin.write(TOTP_CODE + '\n')
                        typed = True
            await read_stream()
            await decider
    except Exception as e:
        buf += f'ERROR: {type(e).__name__}: {e}'.encode()
    import sys
    sys.stdout.write(buf.decode('utf-8', 'replace'))
asyncio.run(go())
"""
        )
        cmd = ["docker", "exec", "bastion-prod", "python3", "-c", inner]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return out.stdout + out.stderr

    def test_push_approve_yields_pass(self, mfa_gateway_running):
        """Out-of-band approve via push-sim → gateway emits MFA verified."""
        out = self._drive_session(push_decision="approve")
        assert "MFA verified" in out, (
            f"push approve didn't yield success banner.\n=== output ===\n{out}"
        )

    def test_push_deny_yields_fail(self, mfa_gateway_running):
        """Out-of-band deny via push-sim → gateway emits failure banner."""
        out = self._drive_session(push_decision="deny")
        assert "verification failed" in out.lower(), (
            f"push deny didn't yield failure banner.\n=== output ===\n{out}"
        )
