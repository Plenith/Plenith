import asyncio
import hashlib
import logging
import os
import sys
from pathlib import Path

import asyncssh

from .persona import load_persona
from .proxy_protocol import ProxyProtocolError, read_v1_header
from .session import Session
from .session_logger import write_session_log

log = logging.getLogger("plenith.ssh")

# PROXY-protocol-v1 support. When the agent sits behind nginx-stream with
# `proxy_protocol on;` (the §4.3 identity proxy does this for MFA
# routing, and may do it globally), each inbound connection arrives with
# a CRLF-terminated PROXY header naming the original client IP.
#
# We use a SEPARATE listener port for PROXY-prefixed traffic so plain
# lateral SSH inside the bubble (bastion-prod → db-prod-01) still works
# on port 22 untouched. The PROXY-stripping listener fronts asyncssh on
# a local loopback port and stashes the real client IP keyed by that
# port — HoneypotSession.connection_made resolves it via _resolve_real_ip().
_REAL_IP_BY_LOCAL_PORT: dict[int, str] = {}

def _resolve_real_ip(asyncssh_peer):
    """If asyncssh sees its peer as loopback (which it will when fronted
    by the PROXY stripper) and we have a recorded real IP for that
    ephemeral port, return the real IP. Otherwise return the asyncssh
    peer IP unchanged."""
    ip, port = asyncssh_peer
    if ip in ("127.0.0.1", "::1"):
        real = _REAL_IP_BY_LOCAL_PORT.get(port)
        if real:
            return real
    return ip

class HoneypotSession(asyncssh.SSHServerSession):
    def __init__(self, server):
        self._server = server
        self._chan = None
        self._session = None
        self._queue = None
        self._worker = None
        self._closed = False

    def connection_made(self, chan):
        self._chan = chan
        raw_peer = chan.get_extra_info("peername") or ("?", 0)
        # When fronted by the PROXY-v1 stripper, the asyncssh-reported
        # peer is (127.0.0.1, <ephemeral port>). The stripper recorded
        # the real client IP for that port — recover it.
        peer = (_resolve_real_ip(raw_peer), raw_peer[1])
        username = self._server.username or "anonymous"
        persona = load_persona(self._server.cfg["paths"]["personas_dir"], username)
        orch = self._server.orchestrator
        self._session = Session(
            claimed_user=username,
            source_ip=peer[0],
            persona=persona,
            state_store=getattr(self._server, "state_store", None),
            sim_bot=getattr(orch, "sim_bot", None),
            rotator=getattr(orch, "rotator", None),
        )
        self._queue = asyncio.Queue()
        restored = " (RESTORED)" if self._session._restored_from_state else ""
        log.info(
            "session %s opened user=%s ip=%s engagement=%s conn#%d%s",
            self._session.id[:8], username, peer[0],
            self._session.engagement_id[:8], self._session.connection_count,
            restored,
        )
        chan.write(self._banner())
        chan.write(self._prompt())
        self._worker = asyncio.create_task(self._run_worker())

    def shell_requested(self):
        return True

    def pty_requested(self, *args, **kwargs):
        return True

    def session_started(self):
        pass

    def data_received(self, data, datatype):
        # asyncssh's line editor (enabled by default with a PTY) accumulates
        # keystrokes, echoes them, handles backspace/arrows, and delivers the
        # completed line (with trailing CR/LF) to this callback. We must NOT
        # echo again — the editor already did that.
        if self._closed or self._queue is None:
            return
        for raw_line in data.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
            cmd = raw_line.strip()
            if cmd or raw_line == "":
                self._queue.put_nowait(cmd)

    async def _run_worker(self):
        try:
            while True:
                cmd = await self._queue.get()
                if self._closed:
                    break
                if not cmd:
                    self._safe_write(self._prompt())
                    continue
                if cmd in ("exit", "logout", "quit"):
                    self._safe_write("logout\r\n")
                    self._closed = True
                    self._chan.close()
                    return
                try:
                    response, source = await self._server.orchestrator.handle_command(
                        self._session, cmd
                    )
                    self._session.record_command(cmd, source, response or "")
                    if response:
                        normalized = response if response.endswith("\n") else response + "\n"
                        self._safe_write(normalized.replace("\n", "\r\n"))
                    # Live-flush the session log after each command so the
                    # dashboard's 3-second SSE tick sees the engagement
                    # mid-session.  Best-effort: a failed write here mustn't
                    # take down the live session.
                    try:
                        write_session_log(
                            self._server.cfg["paths"]["logs_dir"],
                            self._session,
                        )
                    except Exception:
                        log.exception("incremental session-log write failed")
                except Exception:
                    log.exception("error handling command %r", cmd)
                    self._safe_write("bash: internal error\r\n")
                self._safe_write(self._prompt())
        except asyncio.CancelledError:
            pass

    def _safe_write(self, text):
        if self._closed or self._chan is None:
            return
        try:
            self._chan.write(text)
        except (BrokenPipeError, OSError):
            self._closed = True

    def connection_lost(self, exc):
        self._closed = True
        if self._worker is not None:
            self._worker.cancel()
        if self._session is None:
            return
        # Save engagement state BEFORE the session log so a reconnect always
        # sees the latest VFS even if log writing fails.
        store = getattr(self._server, "state_store", None)
        if store is not None:
            try:
                store.save(
                    self._session.source_ip,
                    self._session.claimed_user,
                    self._session.to_persistent_state(),
                )
            except Exception:
                log.exception("failed to save engagement state")
        try:
            path = write_session_log(self._server.cfg["paths"]["logs_dir"], self._session)
            log.info("session %s closed; %d cmds; log=%s",
                     self._session.id[:8], len(self._session.commands), path)
        except Exception:
            log.exception("failed to write session log")

    def _banner(self):
        return (
            f"Welcome to {self._server.cfg['ssh']['banner']}\r\n"
            "Last login: Tue May 11 09:14:22 2026 from 10.10.5.7\r\n"
        )

    def _prompt(self):
        s = self._session
        if s is None:
            return "$ "
        cwd = s.cwd
        if cwd.startswith(s.persona.home):
            cwd = "~" + cwd[len(s.persona.home):]
        return f"{s.persona.username}@{s.persona.hostname}:{cwd}$ "

class HoneypotServer(asyncssh.SSHServer):
    cfg = None
    orchestrator = None
    state_store = None

    def __init__(self):
        self.username = None

    def connection_made(self, conn):
        peer = conn.get_extra_info("peername") or ("?", 0)
        log.info("connection from %s", peer[0])

    def begin_auth(self, username):
        self.username = username
        return True  # require auth (we'll accept any password)

    def password_auth_supported(self):
        return True

    def public_key_auth_supported(self):
        return False

    def validate_password(self, username, password):
        # H-3 fix: never log cleartext passwords. Two failure modes
        # this guards against:
        #   1. Real operators occasionally fat-finger their actual
        #      production credentials against the honeypot (port-scan
        #      automation, password manager misfires) — those would
        #      otherwise persist forever in journald/loki/elastic.
        #   2. Honeypot deployments often live in shared log pipelines.
        #      Cleartext passwords there are a soft-secrets leak into
        #      whichever tenant or analyst can read the logs.
        # The hash preserves the only forensically useful signal
        # (same-password-seen-twice-from-different-IPs) without storing
        # the cleartext.
        pw_hash = hashlib.blake2b(
            password.encode("utf-8", errors="replace"), digest_size=8,
        ).hexdigest()
        log.info("auth attempt user=%s password_hash=%s", username, pw_hash)
        return True  # accept anything; this is a honeypot

    def session_requested(self):
        return HoneypotSession(self)

async def _proxy_strip_and_forward(reader: asyncio.StreamReader,
                                    writer: asyncio.StreamWriter,
                                    internal_port: int) -> None:
    """Read PROXY-v1 header, then bridge to the asyncssh listener on
    127.0.0.1:<internal_port>. Records the real client IP keyed by the
    ephemeral local port we open to asyncssh, so HoneypotSession can
    resolve it via _resolve_real_ip()."""
    peer = writer.get_extra_info("peername") or ("?", 0)
    try:
        header = await read_v1_header(reader, timeout=3.0)
    except ProxyProtocolError as e:
        log.warning("rejecting PROXY connection from %s: %s", peer[0], e)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return

    real_ip = header.src_ip if header.is_known else peer[0]
    log.info("PROXY-v1 inbound: real_ip=%s (proxy=%s)", real_ip, peer[0])

    try:
        backend_reader, backend_writer = await asyncio.open_connection(
            "127.0.0.1", internal_port,
        )
    except OSError as e:
        log.error("internal asyncssh on %d unreachable: %s", internal_port, e)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return

    local_port = backend_writer.get_extra_info("sockname")[1]
    _REAL_IP_BY_LOCAL_PORT[local_port] = real_ip

    async def _copy(src, dst, tag):
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
            log.debug("%s: %s", tag, e)
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

async def serve(cfg, orchestrator, state_store=None):
    HoneypotServer.cfg = cfg
    HoneypotServer.orchestrator = orchestrator
    HoneypotServer.state_store = state_store
    key_path = Path(cfg["ssh"]["host_key_path"])
    key_path.parent.mkdir(parents=True, exist_ok=True)
    if not key_path.exists():
        log.info("generating host key at %s", key_path)
        key = asyncssh.generate_private_key("ssh-rsa", key_size=3072)
        key.write_private_key(str(key_path))

    # Primary listener — plain SSH on cfg.ssh.port. Lateral SSH between
    # agents inside the bubble hits this directly; nothing to parse.
    primary = await asyncssh.create_server(
        HoneypotServer,
        cfg["ssh"]["host"],
        cfg["ssh"]["port"],
        server_host_keys=[str(key_path)],
    )
    log.info("Plenith honeypot listening on %s:%d (plain SSH)",
             cfg["ssh"]["host"], cfg["ssh"]["port"])

    # Optional PROXY-protocol listener. When the identity proxy is
    # configured with `proxy_protocol on;`, it prepends a PROXY-v1
    # header on every outbound connection. We accept those on a
    # separate port so we can sniff & strip the header before letting
    # asyncssh have the socket. Internal asyncssh (for stripped traffic)
    # binds to a loopback-only port.
    pp_port = int(os.environ.get("PLENITH_PROXY_PROTOCOL_PORT", "0"))
    if pp_port > 0:
        internal_port = pp_port + 10_000  # e.g. 2200 → 12200 (loopback)
        # Internal asyncssh listener
        internal = await asyncssh.create_server(
            HoneypotServer,
            "127.0.0.1",
            internal_port,
            server_host_keys=[str(key_path)],
        )
        log.info("Plenith internal SSH listener on 127.0.0.1:%d (for PROXY traffic)",
                 internal_port)

        # PROXY-stripping front-end
        async def _proxy_handler(r, w):
            await _proxy_strip_and_forward(r, w, internal_port)
        pp_server = await asyncio.start_server(
            _proxy_handler,
            host=cfg["ssh"]["host"],
            port=pp_port,
        )
        log.info("PROXY-v1 stripping listener on %s:%d → internal :%d",
                 cfg["ssh"]["host"], pp_port, internal_port)

        async with primary, internal, pp_server:
            await asyncio.gather(
                primary.wait_closed(),
                internal.wait_closed(),
                pp_server.wait_closed(),
            )
    else:
        async with primary:
            await primary.wait_closed()

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stdout,
    )
