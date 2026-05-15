"""Tests for the OT/ICS protocol decoys.

Modbus is the protocol most worth testing (it's well-specified and
attackers actually probe it). S7 and DNP3 tests are more about packet
SHAPE validity than full protocol-spec compliance — the decoys exist
to make `nmap -sV` fingerprint us, not to BE a real PLC.
"""
import asyncio
import json
import struct
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "linux-fork" / "tools"))

import ot_decoys  # noqa: E402
from ot_decoys import (  # noqa: E402
    _modbus_exception,
    _modbus_handle_pdu,
)

# ---------------------------------------------------------------------------
# Modbus PDU handling — synchronous, no socket needed
# ---------------------------------------------------------------------------

class TestModbusPDU:
    def _resp_fn(self, resp: bytes) -> int:
        """Pull the function-code byte out of a Modbus response frame."""
        # MBAP header is 7 bytes; PDU starts at byte 7.
        return resp[7]

    def test_read_holding_registers(self):
        # function 0x03, addr=0, count=2 — read 2 regs starting at 0
        pdu = struct.pack(">BHH", 0x03, 0, 2)
        resp = _modbus_handle_pdu(pdu, tid=1, unit=0xFF, peer="test:1234")
        # MBAP: tid(2) proto(2) length(2) unit(1) — then PDU
        tid, proto, length, unit = struct.unpack(">HHHB", resp[:7])
        assert tid == 1
        assert proto == 0
        assert unit == 0xFF
        # PDU: fn(1) byte_count(1) data...
        assert resp[7] == 0x03
        byte_count = resp[8]
        assert byte_count == 4   # 2 regs × 2 bytes
        # Data: first 2 holding regs from the seeded pool
        regs = struct.unpack(">HH", resp[9:9 + 4])
        assert regs == (1900, 230)

    def test_read_coils_returns_zero_bytes(self):
        pdu = struct.pack(">BHH", 0x01, 0, 16)
        resp = _modbus_handle_pdu(pdu, tid=2, unit=1, peer="test:1234")
        assert resp[7] == 0x01
        # byte_count = ceil(16/8) = 2
        assert resp[8] == 2

    def test_unknown_function_returns_exception(self):
        # Function 0x99 is not implemented
        pdu = struct.pack(">B", 0x99)
        resp = _modbus_handle_pdu(pdu, tid=3, unit=1, peer="test:1234")
        # Exception response: function | 0x80
        assert resp[7] == 0x99 | 0x80
        # Exception code: 1 = illegal function
        assert resp[8] == 1

    def test_write_single_register_echoes(self):
        pdu = struct.pack(">BHH", 0x06, 5, 0xABCD)
        resp = _modbus_handle_pdu(pdu, tid=4, unit=1, peer="test:1234")
        # Modbus spec: WSR success echoes the request PDU
        assert resp[7] == 0x06
        echoed_addr, echoed_val = struct.unpack(">HH", resp[8:12])
        assert echoed_addr == 5
        assert echoed_val == 0xABCD

    def test_write_multiple_registers_echoes_count(self):
        # PDU: fn(1) addr(2) count(2) byte_count(1) data...
        pdu = struct.pack(">BHHB", 0x10, 10, 2, 4) + struct.pack(">HH", 1, 2)
        resp = _modbus_handle_pdu(pdu, tid=5, unit=1, peer="test:1234")
        assert resp[7] == 0x10
        addr, count = struct.unpack(">HH", resp[8:12])
        assert addr == 10
        assert count == 2

    def test_empty_pdu_returns_exception(self):
        resp = _modbus_handle_pdu(b"", tid=6, unit=1, peer="test:1234")
        # Exception response with function=0|0x80 = 0x80
        assert resp[7] == 0x80

class TestModbusException:
    def test_exception_frame_structure(self):
        frame = _modbus_exception(tid=7, unit=0xFF, function=0x03, code=2)
        tid, proto, length, unit = struct.unpack(">HHHB", frame[:7])
        assert tid == 7
        assert proto == 0
        assert unit == 0xFF
        assert length == 3   # unit(1) + fn(1) + code(1)
        assert frame[7] == 0x03 | 0x80
        assert frame[8] == 2

# ---------------------------------------------------------------------------
# IoC logging
# ---------------------------------------------------------------------------

class TestIoCLog:
    def test_log_appends_jsonl(self, tmp_path):
        log_path = tmp_path / "ot.jsonl"
        ot_decoys._IOC_PATH = log_path
        try:
            ot_decoys._ioc_log({"proto": "modbus", "function": 3})
            ot_decoys._ioc_log({"proto": "s7", "event": "connect"})
        finally:
            ot_decoys._IOC_PATH = None

        lines = log_path.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 2
        for line in lines:
            d = json.loads(line)
            assert "ts" in d
            assert d["ts"].endswith("Z")

    def test_log_handles_no_path_set(self):
        """When _IOC_PATH is None, log is a no-op."""
        ot_decoys._IOC_PATH = None
        ot_decoys._ioc_log({"proto": "modbus"})  # Should not raise

# ---------------------------------------------------------------------------
# Modbus async server — round-trip a frame
# ---------------------------------------------------------------------------

class TestModbusAsyncServer:
    @pytest.mark.asyncio
    async def test_round_trip(self, tmp_path):
        """Spin up the Modbus handler on an ephemeral port and drive
        one read-holding-registers request through a real socket."""
        ot_decoys._IOC_PATH = tmp_path / "ioc.jsonl"
        server = await asyncio.start_server(
            ot_decoys._modbus_handle, "127.0.0.1", 0,
        )
        port = server.sockets[0].getsockname()[1]

        async def client():
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            # MBAP + PDU for "read 2 holding registers @ addr 0"
            req = struct.pack(">HHHB", 1, 0, 6, 0xFF) + struct.pack(">BHH", 0x03, 0, 2)
            writer.write(req)
            await writer.drain()
            # Response: 7-byte MBAP + PDU (fn + byte_count + 4 bytes)
            data = await reader.readexactly(7 + 6)
            writer.close()
            await writer.wait_closed()
            return data

        async with server:
            data = await client()
            server.close()

        # Verify response
        assert data[7] == 0x03   # function echo
        assert data[8] == 4      # byte count
        regs = struct.unpack(">HH", data[9:13])
        assert regs == (1900, 230)

        # And the IoC log captured the request
        log = (tmp_path / "ioc.jsonl").read_text(encoding="utf-8").strip().split("\n")
        # Should have at least the connect + the read event
        events = [json.loads(l) for l in log]
        proto_events = [e for e in events if e.get("proto") == "modbus"]
        assert any(e.get("function") == 0x03 for e in proto_events)

# ---------------------------------------------------------------------------
# CLI smoke
# ---------------------------------------------------------------------------

class TestCLI:
    def test_help_listed(self, capsys):
        with pytest.raises(SystemExit) as ei:
            ot_decoys.main(["--help"])
        assert ei.value.code == 0
        captured = capsys.readouterr()
        assert "modbus" in captured.out.lower() or "modbus" in captured.err.lower()
