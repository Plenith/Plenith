"""TCP listeners for non-SSH decoy services.

Inside each Plenith agent container, this script binds extra ports
beyond 2222/SSH. When an attacker — having found credentials in the
planted /etc/mysql/my.cnf — runs `mysql -uroot -pM3taD4ta!2026 -h
db-prod-01`, they get a real TCP handshake against a real port. The
banner we return is the planted my.cnf content, the prompt looks right,
and any data they send is logged.

The point isn't to FAITHFULLY emulate MySQL/HTTP — it's to keep the
TCP-level fingerprint plausible (real SYN-ACK, real banner, realistic
timing) while we capture the attempt as an alert in the orchestrator's
event stream.

Currently supports:
    mysql:PORT  — minimal mysql native-protocol handshake + always-deny
    http:PORT   — minimal HTTP/1.1 server with realistic Server header
    https:PORT  — self-signed TLS + minimal HTTPS responder

All events (connect / auth-attempt / data-received) are appended as JSON
lines to ${STATE_DIR}/logs/${HOSTNAME}/fake-service-events.jsonl so the
audit tool can ingest them alongside SSH session logs in a future pass.

Run as:
    python3 fake_service.py \\
        --hostname db-prod-01 \\
        --state-dir /mnt/state \\
        mysql:3306,http:80
"""
import argparse
import asyncio
import datetime as dt
import json
import os
import ssl
import struct
import sys
from pathlib import Path

def _ts():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

class EventLog:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, event):
        event = dict(event)
        event.setdefault("ts_utc", _ts())
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")

# --- MySQL native-protocol stub ---------------------------------------------

# A minimal Initial Handshake Packet (protocol v10) crafted to look like
# MySQL 8.0.30-0ubuntu0.22.04.1. We always send the same packet and then
# immediately drop the connection on the next read — but the banner does
# the work: the attacker sees a real-looking mysqld, captures the version,
# and the SOC gets an alert with their auth attempt.

def _make_mysql_handshake():
    server_version = b"8.0.30-0ubuntu0.22.04.1\x00"
    thread_id = struct.pack("<I", 12345)
    auth_plugin_data_1 = os.urandom(8)
    capabilities_lower = struct.pack("<H", 0xFFFE)  # most caps
    charset = b"\x21"  # utf8_general_ci
    status_flags = struct.pack("<H", 0x0002)
    capabilities_upper = struct.pack("<H", 0x807F)
    auth_data_len = struct.pack("<B", 21)
    reserved = b"\x00" * 10
    auth_plugin_data_2 = os.urandom(12) + b"\x00"
    auth_plugin_name = b"caching_sha2_password\x00"

    payload = (
        b"\x0a" +                       # protocol version
        server_version +
        thread_id +
        auth_plugin_data_1 +
        b"\x00" +                       # filler
        capabilities_lower +
        charset +
        status_flags +
        capabilities_upper +
        auth_data_len +
        reserved +
        auth_plugin_data_2 +
        auth_plugin_name
    )
    # 3-byte length + 1-byte sequence
    header = struct.pack("<I", len(payload))[:3] + b"\x00"
    return header + payload

async def mysql_handler(log, reader, writer):
    peer = writer.get_extra_info("peername")
    log.write({"event": "mysql.connect", "peer": peer})
    try:
        writer.write(_make_mysql_handshake())
        await writer.drain()
        # Read up to the first packet of auth attempt
        try:
            data = await asyncio.wait_for(reader.read(2048), timeout=5.0)
            log.write({
                "event": "mysql.auth_attempt",
                "peer": peer,
                "bytes": len(data),
                # First few bytes for fingerprinting; redact rest
                "preview_hex": data[:32].hex(),
            })
        except asyncio.TimeoutError:
            pass
        # Send Access Denied packet (ERR packet)
        err = b"\x15\x00\x00\x02" + b"\xff" + struct.pack("<H", 1045)
        err += b"#28000Access denied for user 'root'@'" + peer[0].encode() + b"' (using password: YES)"
        writer.write(err[:0x15 + 4])  # rough length match
        await writer.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, asyncio.CancelledError):
            pass
        log.write({"event": "mysql.close", "peer": peer})

# --- HTTP minimal responder -------------------------------------------------

_HTTP_PAGES = {
    "/": b"<html><body><h1>internal</h1><p>nginx</p></body></html>",
    "/health": b'{"status":"ok","build":"2026.05.01-3ab21cf","uptime":"14d"}',
    "/version": b'{"app":"acme-internal","version":"3.8.1"}',
}

def _http_response(status, body, headers=None):
    h = headers or {}
    h.setdefault("Server", "nginx/1.18.0 (Ubuntu)")
    h.setdefault("Content-Type", "application/json; charset=utf-8")
    h.setdefault("Content-Length", str(len(body)))
    h.setdefault("Connection", "close")
    head = f"HTTP/1.1 {status}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items()) + "\r\n"
    return head.encode("ascii") + body

async def http_handler(log, reader, writer):
    peer = writer.get_extra_info("peername")
    try:
        line = await asyncio.wait_for(reader.readline(), timeout=5.0)
        method, _, rest = line.decode("latin-1", errors="replace").partition(" ")
        path, _, _ = rest.partition(" ")
        path = path.strip()
        # Read headers (we don't strictly need them)
        headers = {}
        while True:
            h_line = await asyncio.wait_for(reader.readline(), timeout=3.0)
            if not h_line or h_line in (b"\r\n", b"\n"):
                break
            k, _, v = h_line.decode("latin-1", errors="replace").partition(":")
            headers[k.strip().lower()] = v.strip()

        log.write({
            "event": "http.request",
            "peer": peer,
            "method": method,
            "path": path[:200],
            "user_agent": headers.get("user-agent", "")[:200],
        })

        body = _HTTP_PAGES.get(path, b'{"error":"not found"}')
        status = "200 OK" if path in _HTTP_PAGES else "404 Not Found"
        if "html" in path or path == "/":
            ct = "text/html; charset=utf-8"
        else:
            ct = "application/json; charset=utf-8"
        writer.write(_http_response(status, body, {"Content-Type": ct}))
        await writer.drain()
    except (ConnectionError, asyncio.TimeoutError, asyncio.CancelledError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, asyncio.CancelledError):
            pass

# --- main -------------------------------------------------------------------

# ---- OT/ICS decoys ---------------------------------------------------------
# Lazy-import the OT protocol speakers so this module stays importable when
# ot_decoys.py is missing (e.g. older agent images). When loaded, the OT
# handlers wrap so they fit the (log, reader, writer) signature this module
# uses, and they emit JSON-line events into the same log as mysql/http.

def _make_ot_wrapper(handler_fn):
    """Adapt an ot_decoys handler (reader, writer) → (log, reader, writer)
    by routing its JSONL IoC writes through our EventLog instead of its
    own _IOC_PATH path."""
    async def _wrapped(log, reader, writer):
        # Re-point the OT module's IoC logger at our path for this run.
        import ot_decoys as _ot
        _ot._IOC_PATH = log.path
        await handler_fn(reader, writer)
    return _wrapped

def _register_ot_handlers(handlers: dict) -> None:
    """Pull the OT handlers out of ot_decoys if it's importable. Done at
    module-load time but inside a try so an old image without ot_decoys.py
    can still run mysql/http."""
    try:
        import ot_decoys as _ot
    except ImportError:
        return
    handlers["modbus"] = _make_ot_wrapper(_ot._modbus_handle)
    handlers["s7"]     = _make_ot_wrapper(_ot._s7_handle)
    handlers["dnp3"]   = _make_ot_wrapper(_ot._dnp3_handle)

_HANDLERS = {"mysql": mysql_handler, "http": http_handler}
_register_ot_handlers(_HANDLERS)

async def serve_one(proto, port, log):
    handler = _HANDLERS.get(proto)
    if not handler:
        print(f"fake_service: unsupported proto {proto!r}", file=sys.stderr)
        return
    server = await asyncio.start_server(
        lambda r, w: handler(log, r, w), "0.0.0.0", port
    )
    print(f"fake_service: {proto} listening on 0.0.0.0:{port}", flush=True)
    async with server:
        await server.serve_forever()

async def amain(services, log):
    tasks = []
    for entry in services.split(","):
        proto, _, port_s = entry.strip().partition(":")
        if not proto or not port_s:
            continue
        tasks.append(asyncio.create_task(serve_one(proto.lower(), int(port_s), log)))
    if tasks:
        await asyncio.gather(*tasks)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("services", help="comma-separated proto:port (e.g. mysql:3306,http:80)")
    ap.add_argument("--hostname", required=True)
    ap.add_argument("--state-dir", required=True)
    args = ap.parse_args()
    log_path = Path(args.state_dir) / "logs" / args.hostname / "fake-service-events.jsonl"
    log = EventLog(log_path)
    log.write({"event": "fake_service.start", "hostname": args.hostname,
               "services": args.services})
    try:
        asyncio.run(amain(args.services, log))
    except KeyboardInterrupt:
        log.write({"event": "fake_service.stop"})

if __name__ == "__main__":
    main()
