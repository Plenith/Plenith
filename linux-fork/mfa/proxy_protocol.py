"""PROXY-protocol v1 parser (haproxy.org spec).

PROXY v1 is a tiny text header an upstream load balancer prepends to a
TCP stream so the backend learns the *original* client's IP. Without
this, the gateway behind the nginx-stream proxy sees the proxy's IP as
the source — which breaks our `<ip>.{pass,fail}` decision-file keying.

Spec: https://www.haproxy.org/download/2.4/doc/proxy-protocol.txt §2.1.

Header looks like:

    PROXY TCP4 192.0.2.99 10.0.0.50 49234 22\\r\\n
    PROXY TCP6 2001:db8::1 2001:db8::2 49234 22\\r\\n
    PROXY UNKNOWN\\r\\n

Constraints we honor:
  - Header is the FIRST bytes on the connection, before any TLS / SSH.
  - Maximum length is 107 bytes including CRLF.
  - Must terminate with the LITERAL two-byte sequence "\\r\\n".
  - Two fewer than 6 tokens or non-numeric ports → reject as malformed.
  - "PROXY UNKNOWN" is a valid header — falls back to socket-peer IP.

We parse defensively: a malformed header rejects the connection rather
than silently treating it as legitimate SSH (which would let an attacker
who can speak directly to the gateway bypass IP-based scoring).
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Optional


MAX_HEADER_BYTES = 107  # spec ceiling
PREFIX = b"PROXY "


@dataclass(frozen=True)
class ProxyV1Header:
    """Parsed PROXY-v1 header. `protocol` is "TCP4" / "TCP6" / "UNKNOWN".
    For UNKNOWN, all the address fields are None and callers should fall
    back to the socket-level peer info."""
    protocol: str
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    raw_length: int

    @property
    def is_known(self) -> bool:
        return self.protocol in ("TCP4", "TCP6") and self.src_ip is not None


class ProxyProtocolError(ValueError):
    """Raised on malformed PROXY-v1 headers — caller MUST close the
    connection. Don't silently fall back to socket peer info because
    that would let a directly-connected attacker bypass IP scoring."""


def parse_v1(line: bytes) -> ProxyV1Header:
    """Parse a single CRLF-terminated PROXY v1 header line.

    `line` MUST include the trailing b"\\r\\n". Anything else raises
    ProxyProtocolError.
    """
    if not isinstance(line, (bytes, bytearray)):
        raise ProxyProtocolError("header must be bytes")
    if len(line) > MAX_HEADER_BYTES:
        raise ProxyProtocolError(f"header too long: {len(line)} > {MAX_HEADER_BYTES}")
    if not line.endswith(b"\r\n"):
        raise ProxyProtocolError("header missing CRLF terminator")
    if not line.startswith(PREFIX):
        raise ProxyProtocolError("header missing PROXY prefix")

    body = line[len(PREFIX):-2]  # strip "PROXY " and CRLF
    try:
        text = body.decode("ascii")
    except UnicodeDecodeError as e:
        raise ProxyProtocolError(f"non-ASCII in header: {e}") from None

    parts = text.split(" ")
    if not parts:
        raise ProxyProtocolError("empty body")
    proto = parts[0]

    if proto == "UNKNOWN":
        # Spec allows any trailing junk (up to MAX_HEADER_BYTES) here.
        return ProxyV1Header(
            protocol="UNKNOWN",
            src_ip=None, dst_ip=None, src_port=None, dst_port=None,
            raw_length=len(line),
        )

    if proto not in ("TCP4", "TCP6"):
        raise ProxyProtocolError(f"unknown protocol token {proto!r}")

    if len(parts) != 5:
        raise ProxyProtocolError(
            f"expected 5 tokens for {proto}, got {len(parts)}: {parts!r}"
        )

    src_ip, dst_ip, src_port_s, dst_port_s = parts[1], parts[2], parts[3], parts[4]
    try:
        src_port = int(src_port_s)
        dst_port = int(dst_port_s)
    except ValueError:
        raise ProxyProtocolError(f"non-integer port: {src_port_s} / {dst_port_s}")

    if not (0 <= src_port <= 65535 and 0 <= dst_port <= 65535):
        raise ProxyProtocolError("port out of range")

    # Belt-and-suspenders: reject anything that obviously isn't an IP.
    if proto == "TCP4":
        if src_ip.count(".") != 3 or dst_ip.count(".") != 3:
            raise ProxyProtocolError(f"TCP4 with non-dotted IP: {src_ip} / {dst_ip}")
    else:  # TCP6
        if ":" not in src_ip or ":" not in dst_ip:
            raise ProxyProtocolError(f"TCP6 with non-colon IP: {src_ip} / {dst_ip}")

    return ProxyV1Header(
        protocol=proto,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        raw_length=len(line),
    )


async def read_v1_header(
    reader: asyncio.StreamReader,
    *,
    timeout: float = 3.0,
) -> ProxyV1Header:
    """Read & parse a PROXY-v1 header from `reader`. Blocks up to
    `timeout` seconds for the CRLF; raises ProxyProtocolError on any
    failure (caller should close the connection)."""
    try:
        line = await asyncio.wait_for(
            reader.readuntil(b"\r\n"),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        raise ProxyProtocolError("timed out waiting for PROXY header") from None
    except asyncio.IncompleteReadError as e:
        raise ProxyProtocolError(
            f"connection closed mid-header (read {len(e.partial)} bytes)"
        ) from None
    except asyncio.LimitOverrunError:
        # readuntil's buffer was too small; we'd see this only if the
        # peer sent >64KB without CRLF — definitely not PROXY-v1.
        raise ProxyProtocolError("buffer overrun — no CRLF in first 64KB") from None
    return parse_v1(line)
