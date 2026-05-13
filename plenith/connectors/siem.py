"""SIEM transports — Splunk HEC, Elasticsearch bulk, syslog over UDP/TCP.

Pure transports. Each takes an alert dict, formats it via `formats.py`,
and ships it to the target endpoint. Failures are non-fatal (logged,
not raised) so SIEM-down doesn't kill the orchestrator.

  SplunkHEC      — POST /services/collector with HEC token header
  ElasticBulk    — POST /_bulk with NDJSON envelope
  SyslogUDP      — UDP datagram (lossy but ubiquitous)
  SyslogTCP      — TCP framed with octet-counting (RFC 6587)
  GenericWebhook — POST <json_event> to any URL

All transports are async — the orchestrator's hot path is async; we
don't want to block on a flaky SIEM. A tiny in-memory ring buffer is
included for batching, since SIEM ingest APIs are MUCH happier with
chunked POSTs.
"""
from __future__ import annotations

import asyncio
import json
import logging
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

from . import formats

log = logging.getLogger("plenith.connectors.siem")


# ---------------------------------------------------------------------------
# Splunk HEC (HTTP Event Collector)
# ---------------------------------------------------------------------------

@dataclass
class SplunkHEC:
    """Splunk HTTP Event Collector client.

    Spec: https://docs.splunk.com/Documentation/Splunk/latest/Data/HECRESTendpoints
    Endpoint:  POST <hec_url>/services/collector/event
    Auth:      `Authorization: Splunk <token>`
    Payload:   {"event": {...}, "sourcetype": "...", "source": "...", "host": "...", "time": <epoch>}

    Batching: HEC accepts NEWLINE-DELIMITED events in one POST. We
    accumulate up to `batch_size` events or `batch_window_seconds`
    before flushing, whichever comes first.
    """
    url: str                    # e.g. https://splunk.example.com:8088
    token: str
    verify_tls: bool = True
    sourcetype: str = "plenith:alert"
    index: Optional[str] = None
    batch_size: int = 16
    batch_window_seconds: float = 5.0
    timeout_seconds: float = 10.0
    _pending: List[Dict[str, Any]] = field(default_factory=list)
    _last_flush: float = field(default_factory=time.time)

    @property
    def collector_endpoint(self) -> str:
        return self.url.rstrip("/") + "/services/collector/event"

    def _format(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        env = formats.to_json_event(alert, sourcetype=self.sourcetype)
        # Splunk wants `time` as epoch seconds, not ISO; remap.
        env["time"] = time.time()
        if self.index:
            env["index"] = self.index
        return env

    async def emit(self, alert: Dict[str, Any]) -> None:
        """Buffer one alert; flush if batch is full or window expired."""
        self._pending.append(self._format(alert))
        if (
            len(self._pending) >= self.batch_size
            or (time.time() - self._last_flush) > self.batch_window_seconds
        ):
            await self.flush()

    async def flush(self) -> int:
        """POST all buffered events. Returns number flushed."""
        if not self._pending:
            return 0
        body = "\n".join(json.dumps(e, separators=(",", ":")) for e in self._pending)
        n = len(self._pending)
        self._pending.clear()
        self._last_flush = time.time()
        try:
            async with httpx.AsyncClient(verify=self.verify_tls,
                                          timeout=self.timeout_seconds) as c:
                r = await c.post(
                    self.collector_endpoint,
                    headers={"Authorization": f"Splunk {self.token}"},
                    content=body,
                )
                r.raise_for_status()
        except Exception as e:
            log.warning("Splunk HEC flush failed (%d events lost): %s", n, e)
            return 0
        return n


# ---------------------------------------------------------------------------
# Elasticsearch bulk
# ---------------------------------------------------------------------------

@dataclass
class ElasticBulk:
    """Elasticsearch / OpenSearch bulk indexing client.

    Spec: https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-bulk.html
    Endpoint:  POST <es_url>/_bulk
    Payload:   action-line + source-line repeated (NDJSON)

    Uses ES 7+/8+ compatibility (no `_type` field). For a Wazuh
    Elasticsearch backend, the index pattern is normally `wazuh-alerts-*`.
    """
    url: str
    index: str = "plenith-alerts"
    api_key: Optional[str] = None
    basic_auth: Optional[tuple] = None     # (user, pass)
    verify_tls: bool = True
    batch_size: int = 32
    batch_window_seconds: float = 5.0
    timeout_seconds: float = 10.0
    _pending: List[Dict[str, Any]] = field(default_factory=list)
    _last_flush: float = field(default_factory=time.time)

    @property
    def bulk_endpoint(self) -> str:
        return self.url.rstrip("/") + "/_bulk"

    def _format(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        env = formats.to_json_event(alert)
        return env["event"]

    async def emit(self, alert: Dict[str, Any]) -> None:
        self._pending.append(self._format(alert))
        if (
            len(self._pending) >= self.batch_size
            or (time.time() - self._last_flush) > self.batch_window_seconds
        ):
            await self.flush()

    async def flush(self) -> int:
        if not self._pending:
            return 0
        # Build NDJSON: index-action + source repeating
        lines = []
        for doc in self._pending:
            lines.append(json.dumps({"index": {"_index": self.index}}))
            lines.append(json.dumps(doc, separators=(",", ":")))
        body = "\n".join(lines) + "\n"

        headers = {"Content-Type": "application/x-ndjson"}
        auth = None
        if self.api_key:
            headers["Authorization"] = f"ApiKey {self.api_key}"
        elif self.basic_auth:
            auth = self.basic_auth

        n = len(self._pending)
        self._pending.clear()
        self._last_flush = time.time()
        try:
            async with httpx.AsyncClient(verify=self.verify_tls,
                                          timeout=self.timeout_seconds) as c:
                r = await c.post(self.bulk_endpoint, headers=headers,
                                 content=body, auth=auth)
                r.raise_for_status()
        except Exception as e:
            log.warning("Elastic bulk flush failed (%d events lost): %s", n, e)
            return 0
        return n


# ---------------------------------------------------------------------------
# Syslog UDP / TCP
# ---------------------------------------------------------------------------

@dataclass
class SyslogUDP:
    """RFC 5424 syslog over UDP. Wraps CEF or LEEF as the message body.

    Lossy by design — most SIEM ingest topologies use UDP-syslog as a
    "best effort tap" and don't care about retransmits."""
    host: str
    port: int = 514
    body_format: str = "cef"          # cef | leef | plain
    facility_hostname: Optional[str] = None
    _sock: Optional[socket.socket] = None

    def _ensure_sock(self) -> socket.socket:
        if self._sock is None:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return self._sock

    async def emit(self, alert: Dict[str, Any]) -> None:
        line = formats.to_syslog_5424(
            alert, hostname=self.facility_hostname, body_format=self.body_format,
        )
        try:
            # sendto is fast — run in default executor to keep this async-clean
            await asyncio.get_event_loop().run_in_executor(
                None, lambda: self._ensure_sock().sendto(line.encode("utf-8"), (self.host, self.port)),
            )
        except Exception as e:
            log.warning("Syslog UDP send failed: %s", e)

    async def flush(self) -> int:
        return 0


@dataclass
class SyslogTCP:
    """RFC 6587 octet-counted framing over TCP. Reliable; modern SIEMs prefer it."""
    host: str
    port: int = 6514
    body_format: str = "cef"
    facility_hostname: Optional[str] = None
    _reader: Optional[asyncio.StreamReader] = None
    _writer: Optional[asyncio.StreamWriter] = None
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def _ensure_conn(self) -> Optional[asyncio.StreamWriter]:
        if self._writer is None or self._writer.is_closing():
            try:
                r, w = await asyncio.wait_for(
                    asyncio.open_connection(self.host, self.port), timeout=5.0,
                )
                self._reader, self._writer = r, w
            except (OSError, asyncio.TimeoutError) as e:
                log.warning("Syslog TCP connect failed: %s", e)
                self._reader = self._writer = None
        return self._writer

    async def emit(self, alert: Dict[str, Any]) -> None:
        line = formats.to_syslog_5424(
            alert, hostname=self.facility_hostname, body_format=self.body_format,
        )
        async with self._lock:
            w = await self._ensure_conn()
            if w is None:
                return
            try:
                # Octet-counted framing: "<len> <msg>"
                msg_bytes = line.encode("utf-8")
                frame = f"{len(msg_bytes)} ".encode("ascii") + msg_bytes
                w.write(frame)
                await w.drain()
            except Exception as e:
                log.warning("Syslog TCP send failed: %s", e)
                # Reconnect next time
                self._writer = None

    async def flush(self) -> int:
        return 0


# ---------------------------------------------------------------------------
# Generic webhook (any URL accepting JSON)
# ---------------------------------------------------------------------------

@dataclass
class GenericWebhook:
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    timeout_seconds: float = 5.0

    async def emit(self, alert: Dict[str, Any]) -> None:
        env = formats.to_json_event(alert)
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as c:
                r = await c.post(self.url, json=env, headers=self.headers)
                r.raise_for_status()
        except Exception as e:
            log.warning("Generic webhook POST failed: %s", e)

    async def flush(self) -> int:
        return 0


# ---------------------------------------------------------------------------
# Convenience — multi-emitter fan-out
# ---------------------------------------------------------------------------

@dataclass
class FanOut:
    """Send every alert to every configured emitter, in parallel.
    Emitter failures are isolated — a dead Splunk doesn't block ELK."""
    emitters: List[Any] = field(default_factory=list)

    async def emit(self, alert: Dict[str, Any]) -> None:
        await asyncio.gather(
            *(e.emit(alert) for e in self.emitters),
            return_exceptions=True,
        )

    async def flush(self) -> int:
        n = 0
        results = await asyncio.gather(
            *(e.flush() for e in self.emitters),
            return_exceptions=True,
        )
        for r in results:
            if isinstance(r, int):
                n += r
        return n


# ---------------------------------------------------------------------------
# Factory — build from config.yaml
# ---------------------------------------------------------------------------

def build_from_config(cfg: Optional[Dict[str, Any]]) -> Optional[FanOut]:
    """Build a FanOut of every connector enabled in `config.connectors`.

    Config schema:
        connectors:
          splunk_hec:
            url:    https://splunk.example.com:8088
            token:  abcd-1234-...
            index:  plenith
          elastic_bulk:
            url:    https://elastic.example.com:9200
            index:  plenith-alerts
            api_key: encoded-key
          syslog_udp:
            host:   syslog.example.com
            port:   514
            body_format: cef
          syslog_tcp:
            host:   syslog.example.com
            port:   6514
            body_format: leef
          webhook:
            url:    https://soar.example.com/incoming
            headers:
              X-Auth: secret

    Returns None when no connectors are configured (zero overhead path
    for dev fabric / unit tests)."""
    if not cfg:
        return None
    block = cfg.get("connectors") if isinstance(cfg, dict) else None
    if not block:
        return None
    emitters = []
    if block.get("splunk_hec", {}).get("url"):
        s = block["splunk_hec"]
        emitters.append(SplunkHEC(
            url=s["url"], token=s.get("token", ""),
            sourcetype=s.get("sourcetype", "plenith:alert"),
            index=s.get("index"),
            verify_tls=bool(s.get("verify_tls", True)),
        ))
    if block.get("elastic_bulk", {}).get("url"):
        e = block["elastic_bulk"]
        emitters.append(ElasticBulk(
            url=e["url"], index=e.get("index", "plenith-alerts"),
            api_key=e.get("api_key"),
            basic_auth=tuple(e["basic_auth"]) if e.get("basic_auth") else None,
            verify_tls=bool(e.get("verify_tls", True)),
        ))
    if block.get("syslog_udp", {}).get("host"):
        s = block["syslog_udp"]
        emitters.append(SyslogUDP(
            host=s["host"], port=int(s.get("port", 514)),
            body_format=s.get("body_format", "cef"),
        ))
    if block.get("syslog_tcp", {}).get("host"):
        s = block["syslog_tcp"]
        emitters.append(SyslogTCP(
            host=s["host"], port=int(s.get("port", 6514)),
            body_format=s.get("body_format", "cef"),
        ))
    if block.get("webhook", {}).get("url"):
        w = block["webhook"]
        emitters.append(GenericWebhook(
            url=w["url"], headers=w.get("headers", {}),
        ))
    if not emitters:
        return None
    return FanOut(emitters=emitters)
