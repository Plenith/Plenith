# ADR 003: CEF as the primary SIEM wire format

**Status:** Accepted
**Date:** 2026-05

## Context

To ingest into the SIEM the buyer already runs, Plenith alerts need
a wire format the SIEM understands. The candidates:

- **CEF** (Common Event Format) — ArcSight-originated, broadly adopted
- **LEEF** (Log Event Extended Format) — IBM QRadar-specific
- **Plain syslog** — universal, but unstructured
- **JSON** (Splunk HEC / Elastic / Datadog) — modern, but per-vendor
- **STIX 2.1** — for IoCs, not alerts

## Decision

**CEF is the primary outbound format**, with parallel emitters for
LEEF (QRadar) and JSON (Splunk HEC / Elastic). RFC 5424 syslog wraps
CEF or LEEF as the message body.

## Why CEF

1. **Splunk Common Information Model maps CEF fields natively** —
   `src`, `suser`, `dhost`, `cs1` / `cs1Label` for custom strings,
   `cn1` / `cn1Label` for custom numbers. Zero per-deployment mapping
   work for the buyer.
2. **QRadar accepts CEF** (as well as LEEF) — one format covers both
   Splunk and QRadar without per-buyer customization.
3. **ArcSight, LogRhythm, Sumo Logic, Devo, Datadog Logs all parse CEF.**
4. **It's text-based**, so it survives transport in ways binary
   protocols don't (rsyslog forwarding, network taps, log mirrors).

## Why not JSON-only

JSON is what every modern SOC vendor's own pipeline expects, but:
- Older deployments (the 60% of enterprises still running ArcSight or
  QRadar) consume CEF/LEEF natively and treat JSON as third-class.
- Splunk HEC accepts JSON; we have a dedicated emitter for that
  (`SplunkHEC`) in addition to CEF.

## Consequences

- **CEF escaping is fiddly** — `|`, `=`, `\`, newlines all need escaping
  per the spec. `plenith/connectors/formats.py` has 100 lines of
  test coverage for the escapes.
- **Custom fields (cs1, cs2, cn1) require label pairs** — `cs1Label`
  must accompany `cs1`, and labels are per-deployment-specific.
- **JSON parallel emitter exists** — `to_json_event()` in formats.py —
  so the buyer never has to choose; both are sent in parallel via FanOut.

## File pointers

- `plenith/connectors/formats.py::to_cef`
- `plenith/connectors/formats.py::to_leef`
- `plenith/connectors/formats.py::to_syslog_5424` — wraps either
