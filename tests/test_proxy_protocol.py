"""Tests for the PROXY-protocol v1 parser used by §4.3.

The parser is the security boundary between "what the gateway thinks
the client IP is" and "what the proxy actually told it." A malformed
header MUST reject, not silently fall back to socket-peer info — that
would let an attacker connecting directly to a backend bypass the
identity-proxy scoring entirely.
"""
import asyncio

import pytest

from plenith.proxy_protocol import (
    MAX_HEADER_BYTES,
    ProxyProtocolError,
    ProxyV1Header,
    parse_v1,
    read_v1_header,
)


# ---------------------------------------------------------------------------
# Happy-path parsing
# ---------------------------------------------------------------------------

class TestParseV1Valid:
    def test_basic_tcp4(self):
        hdr = parse_v1(b"PROXY TCP4 192.0.2.99 10.0.0.50 49234 22\r\n")
        assert hdr.protocol == "TCP4"
        assert hdr.src_ip == "192.0.2.99"
        assert hdr.dst_ip == "10.0.0.50"
        assert hdr.src_port == 49234
        assert hdr.dst_port == 22
        assert hdr.is_known

    def test_basic_tcp6(self):
        hdr = parse_v1(b"PROXY TCP6 2001:db8::1 2001:db8::2 49234 22\r\n")
        assert hdr.protocol == "TCP6"
        assert hdr.src_ip == "2001:db8::1"
        assert hdr.dst_ip == "2001:db8::2"
        assert hdr.is_known

    def test_unknown_is_valid_but_not_known(self):
        hdr = parse_v1(b"PROXY UNKNOWN\r\n")
        assert hdr.protocol == "UNKNOWN"
        assert hdr.src_ip is None
        assert hdr.dst_ip is None
        assert not hdr.is_known

    def test_unknown_with_trailing_text(self):
        """Spec says UNKNOWN can have arbitrary trailing data; we accept."""
        hdr = parse_v1(b"PROXY UNKNOWN some random junk\r\n")
        assert hdr.protocol == "UNKNOWN"
        assert not hdr.is_known

    def test_max_length_at_boundary(self):
        # 107-byte header should be accepted
        # "PROXY TCP4 " (11) + 15+15 IPs + 5+5 ports + 4 spaces + 2 CRLF = 57
        hdr = parse_v1(b"PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n")
        assert hdr.src_ip == "255.255.255.255"


# ---------------------------------------------------------------------------
# Rejection paths — every malformed header MUST raise.
# ---------------------------------------------------------------------------

class TestParseV1Reject:
    def test_no_prefix(self):
        with pytest.raises(ProxyProtocolError, match="PROXY prefix"):
            parse_v1(b"GET /admin HTTP/1.1\r\n")

    def test_no_crlf(self):
        with pytest.raises(ProxyProtocolError, match="CRLF"):
            parse_v1(b"PROXY TCP4 192.0.2.99 10.0.0.50 49234 22")

    def test_only_lf(self):
        with pytest.raises(ProxyProtocolError, match="CRLF"):
            parse_v1(b"PROXY TCP4 192.0.2.99 10.0.0.50 49234 22\n")

    def test_too_long(self):
        # 200-byte header — over the 107 limit
        line = b"PROXY TCP4 " + b"1" * 180 + b"\r\n"
        with pytest.raises(ProxyProtocolError, match="too long"):
            parse_v1(line)

    def test_wrong_protocol(self):
        with pytest.raises(ProxyProtocolError, match="unknown protocol"):
            parse_v1(b"PROXY TCP5 192.0.2.99 10.0.0.50 49234 22\r\n")

    def test_too_few_tokens(self):
        with pytest.raises(ProxyProtocolError, match="expected 5"):
            parse_v1(b"PROXY TCP4 192.0.2.99 10.0.0.50 49234\r\n")

    def test_non_integer_port(self):
        with pytest.raises(ProxyProtocolError, match="non-integer"):
            parse_v1(b"PROXY TCP4 192.0.2.99 10.0.0.50 abc 22\r\n")

    def test_port_out_of_range(self):
        with pytest.raises(ProxyProtocolError, match="out of range"):
            parse_v1(b"PROXY TCP4 192.0.2.99 10.0.0.50 70000 22\r\n")

    def test_tcp4_with_colon_ip(self):
        with pytest.raises(ProxyProtocolError, match="non-dotted"):
            parse_v1(b"PROXY TCP4 2001:db8::1 10.0.0.50 49234 22\r\n")

    def test_tcp6_with_dotted_ip(self):
        with pytest.raises(ProxyProtocolError, match="non-colon"):
            parse_v1(b"PROXY TCP6 192.0.2.99 10.0.0.50 49234 22\r\n")

    def test_non_bytes_input(self):
        with pytest.raises(ProxyProtocolError, match="must be bytes"):
            parse_v1("PROXY TCP4 192.0.2.99 10.0.0.50 49234 22\r\n")  # type: ignore

    def test_non_ascii(self):
        with pytest.raises(ProxyProtocolError, match="non-ASCII"):
            parse_v1(b"PROXY TCP4 \xff\xfe ... \r\n")


# ---------------------------------------------------------------------------
# Async reader
# ---------------------------------------------------------------------------

class _FakeReader:
    """Tiny async-reader stub for testing read_v1_header without a real
    socket. Buffers bytes and serves them via readuntil()."""
    def __init__(self, data: bytes):
        self._buf = data

    async def readuntil(self, sep: bytes) -> bytes:
        idx = self._buf.find(sep)
        if idx < 0:
            raise asyncio.IncompleteReadError(self._buf, None)
        out, self._buf = self._buf[:idx + len(sep)], self._buf[idx + len(sep):]
        return out


class TestReadV1Header:
    @pytest.mark.asyncio
    async def test_reads_and_parses(self):
        r = _FakeReader(b"PROXY TCP4 1.2.3.4 5.6.7.8 1000 22\r\nextra-bytes-here")
        hdr = await read_v1_header(r)  # type: ignore
        assert hdr.src_ip == "1.2.3.4"

    @pytest.mark.asyncio
    async def test_truncated_raises(self):
        r = _FakeReader(b"PROXY TCP4 1.2.3")
        with pytest.raises(ProxyProtocolError, match="mid-header"):
            await read_v1_header(r)  # type: ignore


# ---------------------------------------------------------------------------
# Wire test — gateway-side resolve via shared dict
# ---------------------------------------------------------------------------

class TestResolveRealIP:
    def test_loopback_peer_resolves_via_dict(self):
        """When asyncssh reports a loopback peer and we have a recorded
        real IP, _resolve_real_ip returns the real IP."""
        from plenith.ssh_server import _REAL_IP_BY_LOCAL_PORT, _resolve_real_ip
        _REAL_IP_BY_LOCAL_PORT[54321] = "192.0.2.99"
        try:
            assert _resolve_real_ip(("127.0.0.1", 54321)) == "192.0.2.99"
        finally:
            _REAL_IP_BY_LOCAL_PORT.pop(54321, None)

    def test_non_loopback_returns_unchanged(self):
        from plenith.ssh_server import _resolve_real_ip
        assert _resolve_real_ip(("10.0.0.5", 12345)) == "10.0.0.5"

    def test_loopback_no_record_returns_loopback(self):
        from plenith.ssh_server import _resolve_real_ip
        assert _resolve_real_ip(("127.0.0.1", 99999)) == "127.0.0.1"
