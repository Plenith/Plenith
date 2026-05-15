"""MFA step-up gateway — the §4.3 middle tier.

Inbound SSH connections that the proxy scored "borderline" (40 ≤ risk
< 70) land here. We:

  1. Accept the SSH connection (any password — the credential check
     already happened upstream; THIS is the second factor).
  2. Print a corp-flavored MFA prompt.
  3. Simulate a "push to your registered device" — denied after a few
     seconds (the dev-fabric pretends location policy denied it; real
     deployments would actually call Duo / Okta / etc.).
  4. Fall through to a 6-digit TOTP entry. ±30s clock skew tolerated.
  5. Write a single decision file under /mnt/state/mfa/<source_ip>.{pass,fail}.
     The proxy's Lua scorer consumes that file on the user's NEXT
     connection — pass → real-prod, fail → plenith (silent).
  6. Disconnect with an instruction to reconnect.

This is intentionally NOT a transparent tunnel — real corp MFA portals
work the same way ("verify your device, then come back"), and it avoids
needing the gateway to act as both SSH server and SSH client at once.

Environment:
    MFA_SSH_PORT          listen port (default 22)
    MFA_STATE_DIR         where to write decisions (default /mnt/state/mfa)
    MFA_DEPLOYMENT_ID     deployment-scoped secret (default $PLENITH_DEPLOYMENT_ID
                          or 'dev-fabric')
    MFA_PUSH_AUTO_DENY    "1" to skip the simulated-push wait (default 1)
    MFA_DEMO_LOG_CODE     "1" to log the current valid TOTP to stderr on
                          each prompt (default 1 — convenient for the
                          dev-machine; set 0 in production-flavored runs)
"""
import asyncio
import json
import logging
import os
import socket
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import asyncssh

sys.path.insert(0, str(Path(__file__).resolve().parent))
from proxy_protocol import (  # noqa: E402
    ProxyProtocolError,
    ProxyV1Header,
    read_v1_header,
)
from totp import resolve_secret, secret_for  # noqa: E402

_PROMPT_BANNER = """\
\033[1;36m=== {corp_name} — multi-factor authentication required ===\033[0m

  Risk score for this session was elevated. To continue, we need
  to verify your identity with a second factor.

"""

_PUSH_TEXT_WITH_URL = """\
  → Push notification sent to your registered device.
    Approve at: \033[1m{approve_url}\033[0m
    Deny at:    {deny_url}
    Or press Ctrl+C to cancel.
"""

_PUSH_TEXT_SIMULATED = """\
  → Push notification sent to your registered device.
    Approve the request, or press Ctrl+C to cancel.
"""

_PUSH_DENIED_TEXT = """\
  \033[33m✗ Push approval was not received ({reason}).\033[0m

  Fall back to your authenticator app:
"""

_TOTP_PROMPT = "  Enter your 6-digit code: "

_PASS_MSG = """
  \033[32m✓ MFA verified.\033[0m

  Please reconnect with the same credentials. You will be routed to the
  production jumphost. This grant expires in 5 minutes.
"""

_FAIL_MSG = """
  \033[31m✗ MFA verification failed.\033[0m

  For your security, contact the IT helpdesk if this is unexpected.
"""

_TIMEOUT_MSG = """
  \033[31m✗ MFA challenge timed out (no code received within 60s).\033[0m
"""

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PORT          = int(os.environ.get("MFA_SSH_PORT", "22"))
STATE_DIR     = Path(os.environ.get("MFA_STATE_DIR", "/mnt/state/mfa"))
DEPLOYMENT_ID = (
    os.environ.get("MFA_DEPLOYMENT_ID")
    or os.environ.get("PLENITH_DEPLOYMENT_ID")
    or "dev-fabric"
)
CORP_NAME     = os.environ.get("MFA_CORP_NAME", "Vertex Labs")
PUSH_AUTO_DENY = os.environ.get("MFA_PUSH_AUTO_DENY", "1") == "1"
# H-2 fix: default OFF. Previously defaulted to "1" which meant every
# deployment that didn't explicitly set MFA_DEMO_LOG_CODE=0 was logging
# valid TOTP codes to stderr/journald every 30 seconds. Anyone with read
# access to the log pipeline could bypass MFA for the test users.
# The CI/demo docker-compose explicitly opts in to "1" for the seeded
# demo flow; production deployments now start safe by default.
DEMO_LOG_CODE  = os.environ.get("MFA_DEMO_LOG_CODE", "0") == "1"
TOTP_WINDOW    = int(os.environ.get("MFA_TOTP_WINDOW", "1"))    # ±N steps of 30s
CHALLENGE_TIMEOUT_S = float(os.environ.get("MFA_CHALLENGE_TIMEOUT", "60"))

# PROXY protocol v1 listener port — when set, mfa-gateway dual-listens:
#   PORT (default 22) — plain SSH from inside the bubble (test exec etc.)
#   MFA_PROXY_PROTOCOL_PORT (default 2200) — PROXY-prefixed from the identity proxy
# The proxy targets the PROXY-prefixed port so every inbound connection
# carries the real client IP in a PROXY-v1 header.
MFA_PROXY_PROTOCOL_PORT = int(os.environ.get("MFA_PROXY_PROTOCOL_PORT", "2200"))
ASYNCSSH_INTERNAL_PORT  = MFA_PROXY_PROTOCOL_PORT + 10_000   # loopback-only

# Push approval simulator integration. When MFA_PUSH_URL is set, the
# gateway tries a push first; only falls through to the TOTP prompt if
# the push is denied, times out, or the service is unreachable.
MFA_PUSH_URL          = os.environ.get("MFA_PUSH_URL", "")
MFA_PUSH_TIMEOUT_S    = float(os.environ.get("MFA_PUSH_TIMEOUT", "20"))
MFA_PUSH_POLL_S       = float(os.environ.get("MFA_PUSH_POLL_INTERVAL", "1.5"))

log = logging.getLogger("mfa_gateway")

# ---------------------------------------------------------------------------
# Push API helpers. Synchronous urllib + asyncio.to_thread so we don't
# pull in aiohttp/httpx. Push-sim is on the bubble at MFA_PUSH_URL.
# ---------------------------------------------------------------------------

def _push_post_sync(path: str, body: dict | None = None) -> tuple[int, dict]:
    url = MFA_PUSH_URL.rstrip("/") + path
    data = json.dumps(body or {}).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST",
                                  headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            payload = resp.read()
            try:
                return resp.status, json.loads(payload) if payload else {}
            except json.JSONDecodeError:
                return resp.status, {}
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.reason}
    except (urllib.error.URLError, OSError) as e:
        return 0, {"error": str(e)}

def _push_get_sync(path: str) -> tuple[int, dict]:
    url = MFA_PUSH_URL.rstrip("/") + path
    try:
        with urllib.request.urlopen(url, timeout=3.0) as resp:
            payload = resp.read()
            return resp.status, json.loads(payload) if payload else {}
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.reason}
    except (urllib.error.URLError, OSError) as e:
        return 0, {"error": str(e)}

async def push_request(username: str, ip: str) -> str | None:
    """Open a push request; return the token or None on failure."""
    if not MFA_PUSH_URL:
        return None
    status, body = await asyncio.to_thread(
        _push_post_sync, "/push/request",
        {"username": username, "ip": ip, "ttl_seconds": MFA_PUSH_TIMEOUT_S},
    )
    if status == 201 and "token" in body:
        return body["token"]
    log.warning("push request failed: status=%s body=%s", status, body)
    return None

async def push_poll_until_decision(token: str, *, deadline: float) -> str:
    """Poll push-sim until the token's status leaves 'pending', or until
    `deadline` (monotonic seconds since epoch) elapses. Returns one of
    'approved', 'denied', 'expired', 'timeout', 'unreachable'."""
    while True:
        if time.time() >= deadline:
            return "timeout"
        status, body = await asyncio.to_thread(_push_get_sync, f"/push/poll/{token}")
        if status == 0:
            return "unreachable"
        if status == 404:
            return "unreachable"  # treat 404 as gone
        st = body.get("status")
        if st in ("approved", "denied", "expired"):
            return st
        await asyncio.sleep(MFA_PUSH_POLL_S)

# ---------------------------------------------------------------------------
# PROXY-protocol stripping. The listener on PORT reads the PROXY-v1
# header, opens a localhost connection to ASYNCSSH_INTERNAL_PORT, and
# bridges bytes both directions. We key the real IP by the local port
# we use to talk to asyncssh — the SSHServer below looks itself up in
# this dict via its `peername` to recover the real client IP.
# ---------------------------------------------------------------------------
_REAL_IP_BY_LOCAL_PORT: dict[int, str] = {}

def _resolve_real_ip(asyncssh_peer: tuple) -> str:
    """asyncssh sees its peer as (127.0.0.1, <ephemeral port>) when
    fronted by the PROXY-v1 stripper. We use that ephemeral port as a
    key into the dict the stripper populates. Plain SSH (lateral inside
    the bubble) hits the asyncssh listener on 0.0.0.0:22 directly and
    the peer IP is genuine — no lookup needed."""
    ip, port = asyncssh_peer
    if ip in ("127.0.0.1", "::1"):
        real = _REAL_IP_BY_LOCAL_PORT.get(port)
        if real:
            return real
    return ip

async def _proxy_strip_and_forward(reader: asyncio.StreamReader,
                                    writer: asyncio.StreamWriter) -> None:
    """Read PROXY-v1 header, then bridge to asyncssh on the internal
    loopback port. Records the real client IP so the SSHServer can
    resolve it. Drops the connection on header parse error so a
    direct-connect attacker can't bypass the PROXY-protocol assumption."""
    peer = writer.get_extra_info("peername") or ("?", 0)
    try:
        header = await read_v1_header(reader, timeout=3.0)
    except ProxyProtocolError as e:
        log.warning("rejecting connection from %s: bad PROXY header: %s",
                    peer[0], e)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return

    # UNKNOWN protocol — spec-compliant but no real IP information.
    # Fall back to the proxy's own IP rather than reject; this matches
    # haproxy semantics for non-TCP transports (e.g. UNIX domain).
    real_ip = header.src_ip if header.is_known else peer[0]
    log.info("PROXY v1 header parsed: real_ip=%s (proxy=%s)", real_ip, peer[0])

    # Open the inner connection to asyncssh
    try:
        backend_reader, backend_writer = await asyncio.open_connection(
            "127.0.0.1", ASYNCSSH_INTERNAL_PORT,
        )
    except OSError as e:
        log.error("can't reach internal asyncssh: %s", e)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return

    # Record real IP keyed by the local port we're using to talk to asyncssh.
    local_port = backend_writer.get_extra_info("sockname")[1]
    _REAL_IP_BY_LOCAL_PORT[local_port] = real_ip

    async def _copy(src: asyncio.StreamReader,
                    dst: asyncio.StreamWriter, tag: str) -> None:
        try:
            while True:
                chunk = await src.read(8192)
                if not chunk:
                    break
                dst.write(chunk)
                await dst.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            log.debug("%s: copy error: %s", tag, e)
        finally:
            try:
                dst.close()
            except Exception:
                pass

    try:
        await asyncio.gather(
            _copy(reader, backend_writer, "client→ssh"),
            _copy(backend_reader, writer, "ssh→client"),
        )
    finally:
        _REAL_IP_BY_LOCAL_PORT.pop(local_port, None)

# ---------------------------------------------------------------------------
# Decision file format. Empty file; decision encoded in the extension.
# Filename = <ip>.{pass,fail}. mtime = decision time.
# ---------------------------------------------------------------------------

def _write_decision(source_ip: str, decision: str) -> Path:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    # Wipe any prior decisions for this IP first — we want the latest one
    # to win unambiguously.
    for stale in STATE_DIR.glob(f"{source_ip}.*"):
        try:
            stale.unlink()
        except OSError:
            pass
    p = STATE_DIR / f"{source_ip}.{decision}"
    p.write_text(
        f"ip={source_ip}\ndecision={decision}\nts={int(time.time())}\n",
        encoding="utf-8",
    )
    return p

# ---------------------------------------------------------------------------
# asyncssh session — drives the interactive challenge
# ---------------------------------------------------------------------------

class _MFASession(asyncssh.SSHServerSession):
    """One connection's interactive flow. The pattern mirrors
    plenith.ssh_server.HoneypotSession so the UX is consistent."""

    def __init__(self, source_ip: str, username: str):
        self.source_ip = source_ip
        self.username = username
        self._chan = None
        self._buf = ""
        self._done = asyncio.Event()
        self._submitted: str | None = None

    def connection_made(self, chan):
        self._chan = chan
        log.info("mfa session opened ip=%s user=%s", self.source_ip, self.username)
        asyncio.create_task(self._run_challenge())

    def shell_requested(self):
        return True

    def pty_requested(self, *_a, **_kw):
        return True

    def data_received(self, data, datatype):
        # Line-edited PTY — asyncssh delivers full lines with \r\n.
        # Collect into self._buf until enter; treat first \n as submission.
        if self._chan is None:
            return
        s = data.decode("utf-8", "replace") if isinstance(data, bytes) else data
        for ch in s:
            if ch in ("\r", "\n"):
                if self._submitted is None:
                    self._submitted = self._buf.strip()
                    self._done.set()
                self._buf = ""
            else:
                self._buf += ch

    def session_started(self):
        pass

    def break_received(self, msec):
        # Treat ^C as cancellation
        self._submitted = ""
        self._done.set()
        return True

    def eof_received(self):
        self._submitted = self._submitted if self._submitted is not None else ""
        self._done.set()

    # --- the actual challenge ----------------------------------------

    async def _maybe_run_push(self) -> str:
        """Open a push request and poll for decision. Returns one of
        'approved' / 'denied' / 'timeout' / 'unreachable' / 'skipped'.
        Prints the approve/deny URLs to the SSH terminal so a user
        without a real phone-side app can still demo the flow."""
        if not MFA_PUSH_URL:
            return "skipped"
        token = await push_request(self.username, self.source_ip)
        if not token:
            return "unreachable"

        # Surface approve/deny URLs in the SSH terminal — in a real
        # deployment a push SDK would render the prompt on the user's
        # phone; in the dev fabric, the user (or a script) calls these
        # URLs out-of-band from another window.
        approve_url = f"{MFA_PUSH_URL.rstrip('/')}/push/approve/{token}"
        deny_url    = f"{MFA_PUSH_URL.rstrip('/')}/push/deny/{token}"
        self._chan.write(_PUSH_TEXT_WITH_URL.format(
            approve_url=approve_url, deny_url=deny_url,
        ))

        deadline = time.time() + MFA_PUSH_TIMEOUT_S
        outcome = await push_poll_until_decision(token, deadline=deadline)
        log.info("push outcome user=%s ip=%s token=%s → %s",
                 self.username, self.source_ip, token[:8], outcome)
        return outcome

    async def _run_challenge(self):
        try:
            self._chan.write(_PROMPT_BANNER.format(corp_name=CORP_NAME))

            # ---- Push tier --------------------------------------------
            # If MFA_PUSH_URL is configured, open a real push request
            # against push-sim and poll until decision or timeout. The
            # user (or a script representing the user's phone) can
            # approve out-of-band by hitting the approve URL.
            #
            # If push is unavailable / denied / times out, fall through
            # to the TOTP prompt below — the same fallback real corp
            # MFA flows offer.
            push_outcome = await self._maybe_run_push()
            if push_outcome == "approved":
                self._chan.write(_PASS_MSG)
                _write_decision(self.source_ip, "pass")
                log.info("mfa PASS ip=%s user=%s (via push)",
                         self.source_ip, self.username)
                self._chan.exit(0)
                return

            if push_outcome == "denied":
                # Hard deny — skip TOTP fallback. A push deny is the
                # user explicitly saying "this isn't me."
                self._chan.write(_FAIL_MSG)
                _write_decision(self.source_ip, "fail")
                log.info("mfa FAIL ip=%s user=%s (push denied)",
                         self.source_ip, self.username)
                self._chan.exit(1)
                return

            # `push_outcome` is one of: "timeout", "unreachable", "skipped".
            # All of those fall through to TOTP.
            self._chan.write(_PUSH_DENIED_TEXT.format(reason=push_outcome))

            # Resolve the user's secret. resolve_secret() consults the
            # JSON enrollment store first (real per-user secrets) and
            # falls through to the deployment-scoped demo derivation
            # when the user isn't enrolled. In production, flip the
            # MFA_STRICT_ENROLLMENT env var to reject unenrolled users
            # outright.
            strict = os.environ.get("MFA_STRICT_ENROLLMENT", "0") == "1"
            secret = resolve_secret(
                self.username, DEPLOYMENT_ID, allow_demo_fallback=not strict,
            )
            if secret is None:
                self._chan.write(_FAIL_MSG)
                _write_decision(self.source_ip, "fail")
                log.info("mfa REJECT_UNENROLLED ip=%s user=%s",
                         self.source_ip, self.username)
                self._chan.exit(1)
                return
            if DEMO_LOG_CODE:
                source = "enrollment" if not isinstance(secret, type(secret_for("_"))) else "demo"
                log.info(
                    "[demo] valid code for user=%s ip=%s right now: %s (source=%s)",
                    self.username, self.source_ip, secret.current_code(), source,
                )

            self._chan.write(_TOTP_PROMPT)

            try:
                await asyncio.wait_for(self._done.wait(), timeout=CHALLENGE_TIMEOUT_S)
            except TimeoutError:
                self._chan.write(_TIMEOUT_MSG)
                _write_decision(self.source_ip, "fail")
                log.info("mfa TIMEOUT ip=%s user=%s", self.source_ip, self.username)
                self._chan.exit(1)
                return

            code = (self._submitted or "").strip()
            if code and secret.verify(code, window=TOTP_WINDOW):
                self._chan.write(_PASS_MSG)
                _write_decision(self.source_ip, "pass")
                log.info("mfa PASS ip=%s user=%s", self.source_ip, self.username)
                self._chan.exit(0)
            else:
                self._chan.write(_FAIL_MSG)
                _write_decision(self.source_ip, "fail")
                log.info("mfa FAIL ip=%s user=%s submitted=%r",
                         self.source_ip, self.username, code[:8])
                self._chan.exit(1)
        except Exception:
            log.exception("mfa challenge crashed for ip=%s", self.source_ip)
            try:
                _write_decision(self.source_ip, "fail")
            finally:
                if self._chan is not None:
                    self._chan.exit(1)

class _MFAServer(asyncssh.SSHServer):
    """SSH server that accepts any first-factor credential — the
    second factor is what we actually check. Matches how real MFA
    portals work: assume first-factor was validated upstream."""

    def __init__(self):
        self._peer_ip = "?"
        self._username = "?"

    def connection_made(self, conn):
        peer = conn.get_extra_info("peername") or ("?", 0)
        # In PROXY mode this resolves the original client IP via the
        # stripper's `_REAL_IP_BY_LOCAL_PORT` map. In direct mode it
        # returns whatever asyncssh reported.
        self._peer_ip = _resolve_real_ip(peer)

    def begin_auth(self, username):
        self._username = username
        return True  # require auth, but the type below decides what

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        # First factor is presumed validated upstream — accept anything.
        # The second factor is the TOTP challenge inside the shell.
        self._username = username
        return True

    def public_key_auth_supported(self):
        return True

    def validate_public_key(self, username, key):
        self._username = username
        return True

    def session_requested(self):
        # asyncssh hook: return the SSHServerSession that handles this
        # connection's interactive channel. (`session_factory` was the
        # wrong name — it never fires.)
        return _MFASession(self._peer_ip, self._username)

# ---------------------------------------------------------------------------
# Top-level server
# ---------------------------------------------------------------------------

def _ensure_host_key(path: Path) -> asyncssh.SSHKey:
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        key = asyncssh.generate_private_key("ssh-rsa", key_size=2048)
        key.write_private_key(str(path))
    return asyncssh.read_private_key(str(path))

async def _serve():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s mfa: %(message)s",
    )

    host_key_path = STATE_DIR.parent / "mfa_host_key"
    key = _ensure_host_key(host_key_path)

    log.info(
        "=== MFA gateway (corp=%s, deployment=%s) ===",
        CORP_NAME, DEPLOYMENT_ID,
    )
    log.info("decision dir: %s", STATE_DIR)

    # Plain SSH listener on PORT (default 22). Used for in-bubble test
    # exec from bastion-prod and any other intra-bubble path. Lateral
    # SSH inside the decoy network never traverses the identity proxy,
    # so it has no PROXY header to parse.
    plain = await asyncssh.create_server(
        _MFAServer,
        host="0.0.0.0",
        port=PORT,
        server_host_keys=[key],
    )
    log.info("plain SSH listener on 0.0.0.0:%d", PORT)

    # PROXY-protocol listener on MFA_PROXY_PROTOCOL_PORT (default 2200).
    # The identity proxy hits this port with `proxy_protocol on;`.
    internal = await asyncssh.create_server(
        _MFAServer,
        host="127.0.0.1",
        port=ASYNCSSH_INTERNAL_PORT,
        server_host_keys=[key],
    )
    log.info("internal asyncssh listener on 127.0.0.1:%d (PROXY-stripped traffic)",
             ASYNCSSH_INTERNAL_PORT)

    pp = await asyncio.start_server(
        _proxy_strip_and_forward,
        host="0.0.0.0",
        port=MFA_PROXY_PROTOCOL_PORT,
    )
    log.info("PROXY-v1 stripping listener on 0.0.0.0:%d", MFA_PROXY_PROTOCOL_PORT)

    async with plain, internal, pp:
        await asyncio.gather(
            plain.wait_closed(),
            internal.wait_closed(),
            pp.wait_closed(),
        )

def main():
    try:
        asyncio.run(_serve())
    except KeyboardInterrupt:
        log.info("shutting down")

if __name__ == "__main__":
    main()
