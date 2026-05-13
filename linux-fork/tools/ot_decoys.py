"""Operational-technology / industrial decoys.

Stub implementations of the three OT protocols an attacker probing
"the prod-ICS network" would expect to find:

  Modbus/TCP    port 502   — the most common; widely targeted
  Siemens S7    port 102   — PLC management; Stuxnet-era
  DNP3          port 20000 — utility grid SCADA

Each speaker is a minimal asyncio server that:
  - Parses the inbound request enough to identify function/intent.
  - Returns a structurally-valid, plausibly-empty response.
  - Logs every parsed request as a structured JSONL IoC line.

The goal is NOT to BE a real PLC — the goal is to make `nmap -sV
192.0.2.5 -p 502` say "Modbus/TCP" and have the attacker's scanning
tooling fingerprint us as a real industrial device worth probing more.
Continued interaction generates rich IoCs (which registers they read,
which coils they tried to write) without exposing any real control
plane.

References:
  Modbus: https://modbus.org/docs/Modbus_Messaging_Implementation_Guide_V1_0b.pdf
  S7:     https://wiki.wireshark.org/S7comm
  DNP3:   IEEE 1815, app-layer summary in scapy-dnp3
"""
from __future__ import annotations

import argparse
import asyncio
import datetime
import io
import json
import logging
import os
import struct
import sys
from pathlib import Path
from typing import Optional

log = logging.getLogger("ot_decoys")


# ---------------------------------------------------------------------------
# IoC logging — JSONL stream the audit pipeline can tail
# ---------------------------------------------------------------------------

_IOC_PATH: Optional[Path] = None


def _ioc_log(event: dict) -> None:
    """Append one JSONL record to the IoC log if configured."""
    if _IOC_PATH is None:
        return
    # Python 3.12+ deprecates utcnow() in favor of timezone-aware now(UTC).
    # We strip the "+00:00" offset and replace with "Z" so the IoC log keeps
    # a stable ISO-8601 shape that downstream tools (audit, SIEM) can parse.
    event["ts"] = (
        datetime.datetime.now(datetime.timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )
    try:
        _IOC_PATH.parent.mkdir(parents=True, exist_ok=True)
        with _IOC_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, sort_keys=True) + "\n")
    except OSError as e:
        log.debug("ioc log write failed: %s", e)


# ===========================================================================
# Modbus/TCP — RFC: Modbus Messaging Implementation Guide v1.0b
# ===========================================================================
#
# Wire frame (MBAP header + PDU):
#
#   bytes 0-1 : transaction id (echo)
#   bytes 2-3 : protocol id    (always 0)
#   bytes 4-5 : length         (bytes after this field)
#   byte  6   : unit id        (0xFF for TCP slave)
#   byte  7+  : PDU = function code (1 byte) + data
#
# We respond to enough function codes that nmap, modscan, and basic
# pentesting tools see a plausible device. Anything we don't know
# returns a Modbus exception (function | 0x80, exception code 1).
# ---------------------------------------------------------------------------

# Synthetic register/coil state — never changes, just looks live.
_MODBUS_COILS    = [False] * 256
_MODBUS_DISCRETES = [False] * 256
_MODBUS_HOLDING  = [0] * 256
_MODBUS_INPUTS   = [0] * 256
# Seed a few plausible holding-register values (e.g. SCADA tag IDs)
for i, v in enumerate([1900, 230, 175, 50, 12345, 0, 1, 0, 0, 0]):
    _MODBUS_HOLDING[i] = v


def _modbus_exception(tid: int, unit: int, function: int, code: int) -> bytes:
    """Build a Modbus exception response."""
    pdu = struct.pack(">BB", function | 0x80, code)
    length = len(pdu) + 1   # +1 for unit id
    return struct.pack(">HHHB", tid, 0, length, unit) + pdu


def _modbus_handle_pdu(pdu: bytes, tid: int, unit: int, peer: str) -> bytes:
    """Dispatch by function code. Returns the full response frame."""
    if not pdu:
        return _modbus_exception(tid, unit, 0, 1)
    fn = pdu[0]
    event = {
        "proto": "modbus", "peer": peer, "unit_id": unit,
        "function": fn, "function_hex": f"0x{fn:02x}",
        "raw_pdu_len": len(pdu),
    }

    # ---- 0x01 Read Coils, 0x02 Read Discrete Inputs ----
    if fn in (0x01, 0x02) and len(pdu) >= 5:
        addr, count = struct.unpack(">HH", pdu[1:5])
        event.update({"function_name":
                       "read_coils" if fn == 0x01 else "read_discrete_inputs",
                       "address": addr, "count": count})
        _ioc_log(event)
        # Pack a byte array of `count` bits, all zero for safety.
        n_bytes = (count + 7) // 8
        body = bytes(n_bytes)
        pdu_resp = struct.pack(">BB", fn, n_bytes) + body
        length = len(pdu_resp) + 1
        return struct.pack(">HHHB", tid, 0, length, unit) + pdu_resp

    # ---- 0x03 Read Holding Registers, 0x04 Read Input Registers ----
    if fn in (0x03, 0x04) and len(pdu) >= 5:
        addr, count = struct.unpack(">HH", pdu[1:5])
        event.update({"function_name":
                       "read_holding" if fn == 0x03 else "read_input",
                       "address": addr, "count": count})
        _ioc_log(event)
        # Source from the synthetic register pool, clamped
        regs = (_MODBUS_HOLDING if fn == 0x03 else _MODBUS_INPUTS)
        chunk = regs[addr:addr + count]
        if len(chunk) < count:
            chunk = chunk + [0] * (count - len(chunk))
        body = b"".join(struct.pack(">H", v) for v in chunk)
        pdu_resp = struct.pack(">BB", fn, len(body)) + body
        length = len(pdu_resp) + 1
        return struct.pack(">HHHB", tid, 0, length, unit) + pdu_resp

    # ---- 0x05 Write Single Coil ----
    if fn == 0x05 and len(pdu) >= 5:
        addr, value = struct.unpack(">HH", pdu[1:5])
        event.update({"function_name": "write_single_coil",
                       "address": addr, "value": value})
        _ioc_log(event)
        # Echo the request verbatim — Modbus spec for successful WSC
        return struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu

    # ---- 0x06 Write Single Register ----
    if fn == 0x06 and len(pdu) >= 5:
        addr, value = struct.unpack(">HH", pdu[1:5])
        event.update({"function_name": "write_single_register",
                       "address": addr, "value": value})
        _ioc_log(event)
        return struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu

    # ---- 0x10 Write Multiple Registers ----
    if fn == 0x10 and len(pdu) >= 6:
        addr, count = struct.unpack(">HH", pdu[1:5])
        event.update({"function_name": "write_multiple_registers",
                       "address": addr, "count": count})
        _ioc_log(event)
        # Successful response: echo function, address, count
        pdu_resp = struct.pack(">BHH", fn, addr, count)
        length = len(pdu_resp) + 1
        return struct.pack(">HHHB", tid, 0, length, unit) + pdu_resp

    # ---- Unknown / unsupported: exception ----
    event["function_name"] = "unknown"
    _ioc_log(event)
    return _modbus_exception(tid, unit, fn, 1)   # 1 = illegal function


async def _modbus_handle(reader: asyncio.StreamReader,
                          writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername") or ("?", 0)
    peer_s = f"{peer[0]}:{peer[1]}"
    log.info("modbus connection from %s", peer_s)
    _ioc_log({"proto": "modbus", "peer": peer_s, "event": "connect"})
    try:
        while True:
            # Read MBAP header (7 bytes)
            header = await reader.readexactly(7)
            tid, _proto, length, unit = struct.unpack(">HHHB", header)
            # length includes the unit byte already consumed; the PDU is
            # (length - 1) bytes after.
            pdu = await reader.readexactly(max(0, length - 1))
            resp = _modbus_handle_pdu(pdu, tid, unit, peer_s)
            writer.write(resp)
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        log.warning("modbus error from %s: %s", peer_s, e)
    finally:
        _ioc_log({"proto": "modbus", "peer": peer_s, "event": "disconnect"})
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


# ===========================================================================
# Siemens S7 (TPKT/COTP/S7comm) — with function-code parsing
# ===========================================================================
#
# Wire stack: TPKT (ISO-on-TCP, RFC 1006) → COTP → S7comm.
#
# After the COTP Connection Request/Confirm handshake, every payload is
# a COTP DT (Data Transfer) PDU `02 f0 80` followed by the S7comm header:
#
#     byte  0   : 0x32     protocol id
#     byte  1   : ROSCTR   1=Job request, 2=Ack, 3=Ack-data, 7=UserData
#     bytes 2-3 : redundancy id (always 0)
#     bytes 4-5 : PDU reference
#     bytes 6-7 : parameter length
#     bytes 8-9 : data length
#     byte  10  : function code (the bit we log + dispatch on)
#
# Function codes we identify and log:
#     0x00 CPU services
#     0x04 Read Var          ← reads area data (DB, M, I, Q, E, A, T, C, ...)
#     0x05 Write Var         ← writes — actual control surface
#     0x1A Request Download
#     0x1B Download Block
#     0x1C Download Ended
#     0x1D Start Upload
#     0x1E Upload
#     0x1F End Upload
#     0x28 PLC Start         ← dangerous: starts the CPU
#     0x29 PLC Stop          ← dangerous: stops the CPU
#     0xF0 Setup Communication
#
# For Read Var (the most-probed code), we parse the item count and
# emit synthetic data of the right shape. Other codes get a valid
# ACK with empty data plus the IoC log entry.
# ---------------------------------------------------------------------------

_S7_TPKT_HEADER = b"\x03\x00"  # version=3, reserved=0

_S7_FUNCTION_NAMES = {
    0x00: "cpu_services",
    0x04: "read_var",
    0x05: "write_var",
    0x1A: "request_download",
    0x1B: "download_block",
    0x1C: "download_ended",
    0x1D: "start_upload",
    0x1E: "upload",
    0x1F: "end_upload",
    0x28: "plc_start",
    0x29: "plc_stop",
    0xF0: "setup_communication",
}

# S7 memory area codes — what `read_var` targets
_S7_AREA_NAMES = {
    0x03: "SystemInfo",
    0x05: "SystemFlags",
    0x06: "AnalogInputs",
    0x07: "AnalogOutputs",
    0x1C: "Counter",
    0x1D: "Timer",
    0x81: "Inputs",          # I/E
    0x82: "Outputs",         # Q/A
    0x83: "Flags",           # M
    0x84: "DataBlock",       # DB
    0x85: "InstanceDB",      # DI
    0x86: "LocalData",       # L
}


def _s7_dispatch_function(body: bytes, peer_s: str) -> Optional[bytes]:
    """Inspect the S7comm payload, log the function code, and return a
    structurally-valid Ack-Data response payload (without the COTP/TPKT
    framing — caller wraps it). Returns None on malformed input."""
    # body starts with COTP DT header `02 f0 80` then the S7comm header.
    if len(body) < 13 or body[:3] != b"\x02\xf0\x80":
        return None
    s7 = body[3:]
    if s7[0] != 0x32:
        return None
    rosctr = s7[1]
    pdu_ref = struct.unpack(">H", s7[4:6])[0]
    if len(s7) < 11:
        return None
    fn = s7[10]

    event = {
        "proto":         "s7",
        "peer":          peer_s,
        "event":         "function",
        "rosctr":        rosctr,
        "pdu_ref":       pdu_ref,
        "function":      fn,
        "function_hex":  f"0x{fn:02x}",
        "function_name": _S7_FUNCTION_NAMES.get(fn, "unknown"),
    }

    # ---- Read Var (function 0x04) — parse item descriptors --------------
    if fn == 0x04 and len(s7) >= 19:
        item_count = s7[11]
        # Each item is 12 bytes starting at offset 12 (after fn+count)
        items = []
        offset = 12
        for _ in range(min(item_count, 8)):  # cap to avoid runaway
            if offset + 12 > len(s7):
                break
            item = s7[offset:offset + 12]
            # S7 item descriptor layout (12 bytes):
            #   [0] spec=0x12  [1] length=0x0a  [2] syntax=0x10
            #   [3] transport  [4-5] count       [6-7] db_num
            #   [8] area       [9-11] address (24-bit)
            area  = item[8] if len(item) >= 9 else 0
            count = struct.unpack(">H", item[4:6])[0] if len(item) >= 6 else 0
            items.append({
                "area":      area,
                "area_name": _S7_AREA_NAMES.get(area, f"unknown_0x{area:02x}"),
                "count":     count,
            })
            offset += 12
        event["read_items"] = items
        _ioc_log(event)
        # Build a minimal Ack-Data response: header + per-item data block
        # with success flag + zero values.
        return _s7_build_read_var_response(pdu_ref, items)

    # ---- PLC control (start/stop) — REAL alarm-worthy probes ------------
    if fn in (0x28, 0x29):
        event["security_concern"] = (
            "remote PLC start/stop attempted — would halt or restart "
            "the physical process in a real ICS"
        )
        _ioc_log(event)
        return _s7_build_simple_ack(pdu_ref, fn, error_code=0x0000)

    # ---- Download / Upload (firmware modification surface) --------------
    if fn in (0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F):
        event["security_concern"] = (
            "block download/upload attempted — would replace PLC firmware "
            "or read sensitive program logic"
        )
        _ioc_log(event)
        return _s7_build_simple_ack(pdu_ref, fn, error_code=0x0000)

    # ---- Setup Communication / unknown — minimal Ack --------------------
    _ioc_log(event)
    return _s7_build_simple_ack(pdu_ref, fn, error_code=0x0000)


def _s7_build_simple_ack(pdu_ref: int, fn: int, error_code: int = 0) -> bytes:
    """Build a minimal S7comm Ack-Data response with 0 bytes of data."""
    # COTP DT header + S7 header (ROSCTR=3 Ack-Data, param-len=2, data-len=0,
    # error-class=0, error-code=0) + function code
    return (
        b"\x02\xf0\x80"                           # COTP DT
        + struct.pack(">B", 0x32)                 # S7 proto id
        + struct.pack(">B", 0x03)                 # ROSCTR = Ack-Data
        + struct.pack(">H", 0)                    # redundancy id
        + struct.pack(">H", pdu_ref)              # PDU ref
        + struct.pack(">H", 2)                    # param len
        + struct.pack(">H", 0)                    # data len
        + struct.pack(">H", error_code)           # error class + code
        + struct.pack(">B", fn)                   # echo function code
        + struct.pack(">B", 0)                    # function reserved
    )


def _s7_build_read_var_response(pdu_ref: int, items: list) -> bytes:
    """Build a Read-Var Ack-Data response with synthetic zero data for
    each requested item. Real PLC data would be the live sensor/coil
    values; we return zeros, which still looks valid to the attacker's
    tooling but doesn't leak any plausible-sensor-value information."""
    n = len(items)
    # Per-item data section: 4-byte header + `count` data bytes (rounded
    # to even byte count for word-aligned reads).
    data_section = b""
    for it in items:
        word_count = it["count"]
        byte_count = word_count * 2  # word transport
        data_section += bytes([
            0xFF,                       # return code: success
            0x04,                       # transport size: byte/word
            (byte_count >> 8) & 0xFF,
            byte_count & 0xFF,
        ]) + b"\x00" * byte_count
        # Pad to even length
        if byte_count % 2:
            data_section += b"\x00"

    param = bytes([0x04, n])           # echo fn + count
    data_len = len(data_section)
    return (
        b"\x02\xf0\x80"                           # COTP DT
        + struct.pack(">B", 0x32)                 # S7 proto id
        + struct.pack(">B", 0x03)                 # ROSCTR = Ack-Data
        + struct.pack(">H", 0)                    # redundancy id
        + struct.pack(">H", pdu_ref)              # PDU ref
        + struct.pack(">H", len(param))           # param len
        + struct.pack(">H", data_len)             # data len
        + struct.pack(">H", 0)                    # error class+code = 0
        + param
        + data_section
    )


async def _s7_handle(reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername") or ("?", 0)
    peer_s = f"{peer[0]}:{peer[1]}"
    log.info("s7 connection from %s", peer_s)
    _ioc_log({"proto": "s7", "peer": peer_s, "event": "connect"})
    try:
        # Read TPKT header (4 bytes)
        tpkt = await reader.readexactly(4)
        if tpkt[0] != 0x03:
            log.debug("s7: non-TPKT bytes from %s", peer_s)
            return
        total_len = (tpkt[2] << 8) | tpkt[3]
        body = await reader.readexactly(max(0, total_len - 4))

        # COTP Connection Request (type 0xE0)
        if len(body) >= 2 and body[1] == 0xE0:
            _ioc_log({"proto": "s7", "peer": peer_s,
                      "event": "cotp_conn_request",
                      "body_len": len(body)})
            cotp_tail = body[7:18] if len(body) >= 18 else b"\x00" * 11
            cotp_cc = (
                b"\x11" b"\xd0" b"\x00\x01" b"\x00\x02" b"\x00" + cotp_tail
            )
            tpkt_resp = _S7_TPKT_HEADER + struct.pack(">H", 4 + len(cotp_cc)) + cotp_cc
            writer.write(tpkt_resp)
            await writer.drain()

        # Continue reading TPKT frames — now they should be COTP-DT
        # carrying S7comm PDUs.
        while True:
            tpkt = await reader.readexactly(4)
            if tpkt[0] != 0x03:
                break
            total_len = (tpkt[2] << 8) | tpkt[3]
            body = await reader.readexactly(max(0, total_len - 4))
            resp_payload = _s7_dispatch_function(body, peer_s)
            if resp_payload is None:
                # Malformed — close politely
                break
            tpkt_resp = _S7_TPKT_HEADER + struct.pack(">H", 4 + len(resp_payload)) + resp_payload
            writer.write(tpkt_resp)
            await writer.drain()

    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        log.warning("s7 error from %s: %s", peer_s, e)
    finally:
        _ioc_log({"proto": "s7", "peer": peer_s, "event": "disconnect"})
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


# ===========================================================================
# DNP3 (IEEE 1815) — application-layer function-code parsing
# ===========================================================================
#
# Frame layout (data-link, transport, application):
#
#   sync(2)=0x0564 | length(1) | ctrl(1) | dst(2) | src(2) | CRC(2)
#       — data-link header (10 bytes total)
#   transport(1)
#       — TH byte; bits: FIR / FIN / 6-bit sequence
#   app_ctrl(1)
#       — FIR / FIN / CON / UNS / 4-bit sequence
#   func(1)
#       — application-layer function code (the bit we log + dispatch on)
#
# Function codes we parse:
#     0x00 CONFIRM          (master ACK)
#     0x01 READ             (read object groups — the most-common probe)
#     0x02 WRITE
#     0x03 SELECT
#     0x04 OPERATE          ← DIRECT control: would actually flip relays
#     0x05 DIRECT_OPERATE
#     0x06 DIRECT_OPERATE_NR
#     0x0D COLD_RESTART     ← DANGEROUS: reboots the device
#     0x0E WARM_RESTART
#     0x17 START_APPL
#     0x18 STOP_APPL
#     0x1B DISABLE_UNSOLICITED
#     0x1C ENABLE_UNSOLICITED
#
# When parsing READ, we also extract the requested object group/variation
# pair — that tells the SOC which sensor type the attacker was reading
# (Group 1 = binary inputs, Group 30 = analog inputs, Group 50 = time, etc.).
# ---------------------------------------------------------------------------

_DNP3_FUNCTION_NAMES = {
    0x00: "confirm",
    0x01: "read",
    0x02: "write",
    0x03: "select",
    0x04: "operate",
    0x05: "direct_operate",
    0x06: "direct_operate_nr",
    0x07: "immediate_freeze",
    0x09: "freeze_clear",
    0x0D: "cold_restart",
    0x0E: "warm_restart",
    0x0F: "initialize_data",
    0x10: "initialize_application",
    0x11: "start_application",
    0x12: "stop_application",
    0x13: "save_configuration",
    0x14: "enable_unsolicited",
    0x15: "disable_unsolicited",
    0x17: "start_appl",
    0x18: "stop_appl",
    0x81: "response",
    0x82: "unsolicited_response",
}

# Most-probed DNP3 object groups (g.var → human label)
_DNP3_OBJECT_GROUPS = {
    1:  "Binary Input",
    2:  "Binary Input Event",
    10: "Binary Output",
    11: "Binary Output Event",
    12: "Binary Output Command",     # ← attacker control surface
    20: "Counter",
    21: "Frozen Counter",
    30: "Analog Input",
    32: "Analog Input Event",
    40: "Analog Output Status",
    41: "Analog Output",             # ← attacker control surface
    50: "Time and Date",
    60: "Class Data",
    80: "Internal Indications",
    110: "Octet String Object",
}

_DNP3_DANGEROUS_FUNCS = {
    0x04: "OPERATE — actual relay flip on a real RTU",
    0x05: "DIRECT_OPERATE — no SELECT pre-step",
    0x06: "DIRECT_OPERATE_NR — no response requested",
    0x0D: "COLD_RESTART — full device reboot",
    0x0E: "WARM_RESTART",
    0x12: "STOP_APPL — halt the device application",
    0x18: "STOP_APPL — alias variant",
}


def _dnp3_parse_objects(payload: bytes) -> list:
    """Walk the application-layer object-block headers. Each block is
    a 3-byte header `group, variation, qualifier` followed by an
    object range / data. We extract the group+variation only — the
    payload bytes are opaque to us."""
    objects = []
    i = 0
    while i + 3 <= len(payload) and len(objects) < 10:
        group = payload[i]
        variation = payload[i + 1]
        qualifier = payload[i + 2]
        objects.append({
            "group":     group,
            "variation": variation,
            "qualifier": qualifier,
            "group_name": _DNP3_OBJECT_GROUPS.get(group, f"unknown_g{group}"),
        })
        # The qualifier determines the next field's length; we skip the
        # full object data via a coarse heuristic (move forward 8 bytes
        # per block). Real parsers walk the prefix/range fields.
        i += 3 + 8
    return objects


async def _dnp3_handle(reader: asyncio.StreamReader,
                        writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername") or ("?", 0)
    peer_s = f"{peer[0]}:{peer[1]}"
    log.info("dnp3 connection from %s", peer_s)
    _ioc_log({"proto": "dnp3", "peer": peer_s, "event": "connect"})
    try:
        while True:
            sync = await reader.readexactly(2)
            if sync != b"\x05\x64":
                log.debug("dnp3: bad sync from %s: %r", peer_s, sync)
                break
            header = await reader.readexactly(8)
            length = header[0]
            ctrl   = header[1]
            dst    = header[2] | (header[3] << 8)
            src    = header[4] | (header[5] << 8)
            remaining = max(0, length - 5)
            payload = await reader.readexactly(remaining + 2)  # +2 trailing CRC

            # Application-layer parse — strip transport-header byte(s)
            # (transport is 1 byte: TH; then app_ctrl + func + objects)
            app_payload = payload[:-2]   # drop trailing CRC
            event = {
                "proto":     "dnp3",
                "peer":      peer_s,
                "event":     "request",
                "length":    length,
                "ctrl":      ctrl,
                "dst":       dst,
                "src":       src,
            }
            if len(app_payload) >= 3:
                _th       = app_payload[0]
                app_ctrl  = app_payload[1]
                func      = app_payload[2]
                event["app_ctrl"]     = app_ctrl
                event["function"]     = func
                event["function_hex"] = f"0x{func:02x}"
                event["function_name"] = _DNP3_FUNCTION_NAMES.get(func, "unknown")
                if func in _DNP3_DANGEROUS_FUNCS:
                    event["security_concern"] = _DNP3_DANGEROUS_FUNCS[func]
                # For READ / WRITE / OPERATE the payload includes object headers
                if func in (0x01, 0x02, 0x04, 0x05, 0x06):
                    event["objects"] = _dnp3_parse_objects(app_payload[3:])
            _ioc_log(event)

            # Build a minimal RESPONSE frame: flip src/dst, function 0x81 (RESPONSE),
            # IIN bits = 0 (no exceptions), no objects.
            resp_app = bytes([
                app_payload[1] if len(app_payload) >= 2 else 0xC0,   # app_ctrl echo
                0x81,    # RESPONSE function
                0x00,    # IIN1
                0x00,    # IIN2
            ])
            resp_payload = bytes([app_payload[0] if app_payload else 0xC0]) + resp_app
            resp_header = bytes([
                0x05, 0x64,
                len(resp_payload) + 5,
                0xC4,                                # ctrl: response
                src & 0xFF, (src >> 8) & 0xFF,       # dst = old src
                dst & 0xFF, (dst >> 8) & 0xFF,       # src = old dst
                0x00, 0x00,                          # CRC (we don't compute)
            ])
            writer.write(resp_header + resp_payload + b"\x00\x00")
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        log.warning("dnp3 error from %s: %s", peer_s, e)
    finally:
        _ioc_log({"proto": "dnp3", "peer": peer_s, "event": "disconnect"})
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


# ===========================================================================
# Top-level orchestration
# ===========================================================================

PROTO_HANDLERS = {
    "modbus": (_modbus_handle, 502),
    "s7":     (_s7_handle,     102),
    "dnp3":   (_dnp3_handle,   20000),
}


async def _run(host: str, protocols: list) -> None:
    """Start every requested listener and run forever."""
    servers = []
    for spec in protocols:
        name, _, port_s = spec.partition(":")
        if name not in PROTO_HANDLERS:
            log.error("unknown protocol %r — choices: %s",
                      name, list(PROTO_HANDLERS))
            continue
        handler, default_port = PROTO_HANDLERS[name]
        port = int(port_s) if port_s else default_port
        srv = await asyncio.start_server(handler, host, port)
        log.info("OT decoy: %s listening on %s:%d", name, host, port)
        servers.append(srv)
    if not servers:
        log.error("no listeners started; exiting")
        return
    try:
        await asyncio.gather(*[s.serve_forever() for s in servers])
    except asyncio.CancelledError:
        for s in servers:
            s.close()
        log.info("shutting down")


def main(argv=None) -> int:
    global _IOC_PATH
    p = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--protocols", default="modbus,s7,dnp3",
                   help="comma-separated list of <proto>[:<port>] (default modbus,s7,dnp3)")
    p.add_argument("--ioc-log", type=Path,
                   default=os.environ.get("OT_IOC_LOG", "/mnt/state/logs/ot_iocs.jsonl"),
                   help="where to append JSONL IoC records (default /mnt/state/logs/ot_iocs.jsonl)")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s ot: %(message)s",
    )

    _IOC_PATH = args.ioc_log
    log.info("IoC log: %s", _IOC_PATH)

    try:
        asyncio.run(_run(args.host, args.protocols.split(",")))
    except KeyboardInterrupt:
        log.info("interrupted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
