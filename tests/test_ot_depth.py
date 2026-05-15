"""Tests for the deepened OT protocol coverage (S7 + DNP3).

The shallow `test_ot_decoys.py` covered:
  - Modbus PDU dispatch + async server round-trip
  - JSONL IoC log shape

This module adds depth tests for:
  - S7comm function-code parsing (Read Var, PLC Stop, Download, etc.)
  - S7 Read Var response shape (per-item byte_count + data)
  - DNP3 application-layer parsing (function code, object groups)
  - DNP3 dangerous-function detection (cold-restart, operate, etc.)
"""
import json
import struct
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "linux-fork" / "tools"))

import ot_decoys

# ---------------------------------------------------------------------------
# S7comm function-code dispatch
# ---------------------------------------------------------------------------

def _wrap_s7_in_cotp(s7_pdu: bytes) -> bytes:
    """Helper — prepend the COTP DT header for tests."""
    return b"\x02\xf0\x80" + s7_pdu

def _build_s7_job(function: int, item_count: int = 0,
                   items: bytes = b"", pdu_ref: int = 1) -> bytes:
    """Build a minimal valid S7 Job (ROSCTR=1) request."""
    param = struct.pack(">BB", function, item_count) + items
    s7_hdr = (
        struct.pack(">B", 0x32)                # proto
        + struct.pack(">B", 0x01)              # ROSCTR = Job
        + struct.pack(">H", 0)                 # redundancy
        + struct.pack(">H", pdu_ref)
        + struct.pack(">H", len(param))        # param len
        + struct.pack(">H", 0)                 # data len
        + param
    )
    return _wrap_s7_in_cotp(s7_hdr)

class TestS7DispatchReadVar:
    def test_read_var_parses_items(self, tmp_path):
        # Build a Read Var (fn 0x04) requesting 1 item from DataBlock area
        # Item descriptor (12 bytes):
        #   spec(1)=0x12, length(1)=0x0a, syntax(1)=0x10, transport(1)=0x02,
        #   count(2)=4, db_num(2)=1, area(1)=0x84 (DB), addr(3)=0
        item = bytes([
            0x12, 0x0a, 0x10, 0x02,
            0x00, 0x04,           # word count = 4
            0x00, 0x01,           # db num = 1
            0x84,                 # area = DataBlock
            0x00, 0x00, 0x00,     # address
        ])
        pdu = _build_s7_job(function=0x04, item_count=1, items=item)
        ot_decoys._IOC_PATH = tmp_path / "ioc.jsonl"
        try:
            resp = ot_decoys._s7_dispatch_function(pdu, peer_s="test:1234")
        finally:
            ot_decoys._IOC_PATH = None

        assert resp is not None
        # IoC log should contain the read item with parsed area
        log = (tmp_path / "ioc.jsonl").read_text(encoding="utf-8").strip().split("\n")
        events = [json.loads(l) for l in log]
        read_events = [e for e in events if e.get("function") == 0x04]
        assert read_events
        e = read_events[0]
        assert e["function_name"] == "read_var"
        assert e["read_items"]
        assert e["read_items"][0]["area"] == 0x84
        assert e["read_items"][0]["area_name"] == "DataBlock"
        assert e["read_items"][0]["count"] == 4

    def test_read_var_response_has_correct_shape(self):
        # Two-item read, 4 words and 2 words → byte_counts 8 and 4
        items = [
            {"area": 0x84, "area_name": "DataBlock", "count": 4},
            {"area": 0x83, "area_name": "Flags",     "count": 2},
        ]
        resp = ot_decoys._s7_build_read_var_response(pdu_ref=42, items=items)
        # COTP DT (3) + S7 hdr (10) + param (2) + data section
        # Each item data: 4-byte header + byte_count
        # Items 1 + 2: 4+8=12 and 4+4=8 → 20 bytes data section
        # Plus minor alignment padding
        assert len(resp) >= 3 + 10 + 2 + 12 + 8

class TestS7DispatchDangerous:
    def test_plc_stop_logs_security_concern(self, tmp_path):
        pdu = _build_s7_job(function=0x29)  # PLC Stop
        ot_decoys._IOC_PATH = tmp_path / "ioc.jsonl"
        try:
            ot_decoys._s7_dispatch_function(pdu, peer_s="bad:9999")
        finally:
            ot_decoys._IOC_PATH = None
        events = [json.loads(l) for l in
                  (tmp_path / "ioc.jsonl").read_text().strip().split("\n")]
        e = events[0]
        assert e["function_name"] == "plc_stop"
        assert "security_concern" in e
        assert "stop" in e["security_concern"].lower() or "halt" in e["security_concern"].lower()

    def test_plc_start_logs_security_concern(self, tmp_path):
        pdu = _build_s7_job(function=0x28)
        ot_decoys._IOC_PATH = tmp_path / "ioc.jsonl"
        try:
            ot_decoys._s7_dispatch_function(pdu, peer_s="bad:9999")
        finally:
            ot_decoys._IOC_PATH = None
        events = [json.loads(l) for l in
                  (tmp_path / "ioc.jsonl").read_text().strip().split("\n")]
        assert "security_concern" in events[0]

    def test_download_logs_security_concern(self, tmp_path):
        for fn in (0x1A, 0x1B, 0x1C):
            pdu = _build_s7_job(function=fn)
            ot_decoys._IOC_PATH = tmp_path / f"ioc-{fn}.jsonl"
            try:
                ot_decoys._s7_dispatch_function(pdu, peer_s="bad:9999")
            finally:
                ot_decoys._IOC_PATH = None
            events = [json.loads(l) for l in
                      (tmp_path / f"ioc-{fn}.jsonl").read_text().strip().split("\n")]
            assert "security_concern" in events[0]

class TestS7DispatchMisc:
    def test_malformed_pdu_rejected(self):
        # Too short / no COTP header
        assert ot_decoys._s7_dispatch_function(b"\x00", "x:1") is None
        assert ot_decoys._s7_dispatch_function(b"\x02\xf0\x80\x99", "x:1") is None

    def test_unknown_function_still_logged(self, tmp_path):
        pdu = _build_s7_job(function=0x99)  # not in our table
        ot_decoys._IOC_PATH = tmp_path / "ioc.jsonl"
        try:
            resp = ot_decoys._s7_dispatch_function(pdu, peer_s="x:1")
        finally:
            ot_decoys._IOC_PATH = None
        assert resp is not None  # still returns a valid Ack
        events = [json.loads(l) for l in
                  (tmp_path / "ioc.jsonl").read_text().strip().split("\n")]
        assert events[0]["function"] == 0x99
        assert events[0]["function_name"] == "unknown"

# ---------------------------------------------------------------------------
# DNP3 application-layer
# ---------------------------------------------------------------------------

def _build_dnp3_request(function: int, object_blocks: bytes = b"") -> bytes:
    """Build a DNP3 request payload: [transport, app_ctrl, function, objects]
    + 2 trailing CRC bytes that we don't compute (test stubs)."""
    th = 0xC0          # FIR + FIN + sequence 0
    app_ctrl = 0xC0    # FIR + FIN + CON + sequence 0
    payload = bytes([th, app_ctrl, function]) + object_blocks
    return payload + b"\x00\x00"  # fake CRC

class TestDNP3ObjectParsing:
    def test_binary_input_read_parses_group_1(self):
        # Object block header: group=1, variation=2, qualifier=6
        obj_block = bytes([1, 2, 6, 0, 0, 0, 0, 0, 0, 0, 0])
        objs = ot_decoys._dnp3_parse_objects(obj_block)
        assert len(objs) == 1
        assert objs[0]["group"] == 1
        assert objs[0]["variation"] == 2
        assert objs[0]["qualifier"] == 6
        assert objs[0]["group_name"] == "Binary Input"

    def test_analog_input_parses_group_30(self):
        obj_block = bytes([30, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        objs = ot_decoys._dnp3_parse_objects(obj_block)
        assert objs[0]["group_name"] == "Analog Input"

    def test_binary_output_command_flagged(self):
        # Group 12 = Binary Output Command — what an attacker uses to actually flip relays
        obj_block = bytes([12, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0])
        objs = ot_decoys._dnp3_parse_objects(obj_block)
        assert objs[0]["group_name"] == "Binary Output Command"

    def test_unknown_group_name_falls_back(self):
        obj_block = bytes([99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        objs = ot_decoys._dnp3_parse_objects(obj_block)
        assert objs[0]["group_name"].startswith("unknown_g")

    def test_empty_payload_returns_empty(self):
        assert ot_decoys._dnp3_parse_objects(b"") == []

# ---------------------------------------------------------------------------
# DNP3 dangerous-function detection (via async server)
# ---------------------------------------------------------------------------

class TestDNP3DangerousFunctions:
    def test_function_name_table_has_dangerous(self):
        for fn in (0x04, 0x05, 0x06, 0x0D, 0x0E, 0x18):
            assert fn in ot_decoys._DNP3_FUNCTION_NAMES
        assert ot_decoys._DNP3_FUNCTION_NAMES[0x0D] == "cold_restart"
        assert ot_decoys._DNP3_FUNCTION_NAMES[0x04] == "operate"

    def test_object_group_table_has_control_surfaces(self):
        # Groups 12 + 41 = binary + analog output commands (what attackers OPERATE on)
        assert 12 in ot_decoys._DNP3_OBJECT_GROUPS
        assert 41 in ot_decoys._DNP3_OBJECT_GROUPS

    def test_dangerous_function_map(self):
        # The dangerous-funcs map must include the worst codes
        for fn in (0x04, 0x0D, 0x0E):
            assert fn in ot_decoys._DNP3_DANGEROUS_FUNCS

    @pytest.mark.asyncio
    async def test_dnp3_async_handle_logs_cold_restart(self, tmp_path):
        """Drive a real DNP3 frame through the async server and verify
        the cold-restart function is logged with security_concern."""
        import asyncio

        ot_decoys._IOC_PATH = tmp_path / "ioc.jsonl"
        server = await asyncio.start_server(ot_decoys._dnp3_handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            r, w = await asyncio.open_connection("127.0.0.1", port)
            # Build a full DNP3 frame: sync + data-link header + payload
            payload = _build_dnp3_request(function=0x0D)  # COLD_RESTART
            frame = (
                b"\x05\x64"
                + bytes([5 + len(payload) - 2,  # length excludes trailing CRC
                          0xC4, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00])
                + payload
            )
            w.write(frame)
            await w.drain()
            # Read response (don't care about content)
            try:
                await asyncio.wait_for(r.read(64), timeout=1.0)
            except TimeoutError:
                pass
            w.close()
            await w.wait_closed()
        finally:
            server.close()
            await server.wait_closed()
            ot_decoys._IOC_PATH = None

        log_path = tmp_path / "ioc.jsonl"
        events = [json.loads(l) for l in
                  log_path.read_text(encoding="utf-8").strip().split("\n")]
        # Should have at least connect + request events
        request_events = [e for e in events if e.get("event") == "request"]
        assert request_events
        e = request_events[0]
        assert e.get("function") == 0x0D
        assert e.get("function_name") == "cold_restart"
        assert "security_concern" in e
