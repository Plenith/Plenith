"""Standardized event-format emitters — CEF, LEEF, RFC 5424 syslog.

Single canonical input (the dict shape Plenith alerts produce) →
the wire format the SIEM expects. This is what makes us ingestible by
*every* commercial SIEM without writing a Splunk app, an ArcSight
SmartConnector, or a QRadar DSM.

  CEF (Common Event Format)
      Owned by ArcSight, supported natively by Splunk Common
      Information Model, IBM QRadar, LogRhythm, Sumo Logic, Devo,
      and most newer SIEMs. THE most-portable enterprise event format.
      Spec: https://docs.microfocus.com/SM/9.62/Hybrid/CEF_specification.pdf

  LEEF (Log Event Extended Format)
      IBM QRadar's preferred ingest format. Similar shape to CEF but
      uses a tab-separated key=value tail.

  RFC 5424 syslog
      Works with rsyslog, syslog-ng, Wazuh, Graylog, basically any
      Unix-shaped pipeline. Carries CEF or LEEF as the message body
      to chain the formats.

Every emitter is a PURE function (alert dict in, str out) so they're
trivial to test and can be composed with any transport (UDP/TCP syslog,
HTTP, file-tail). Transport-bearing emitters live in `siem.py`.
"""
from __future__ import annotations

import datetime
import socket
from typing import Any

# ---------------------------------------------------------------------------
# Canonical alert dict — the shape plenith emits. Documented here so
# downstream emitters can rely on a stable contract.
# ---------------------------------------------------------------------------
# {
#   "action":       "alert_credential_exfil",       # str, required
#   "severity":     "high",                          # critical|high|medium|info
#   "rationale":    "Attacker read planted creds",  # str, optional
#   "engagement_id": "abcd1234-...",                # str, optional
#   "source_ip":    "192.0.2.99",                   # str, optional
#   "claimed_user": "jdoe",                          # str, optional
#   "hostname":     "bastion-prod",                  # str, optional
#   "ts_offset_s":  12.3,                            # float, optional
#   "triggered_by": "cat ~/.aws/credentials",        # str, optional
# }
# Plus arbitrary extra fields (passed through as extensions).

_SEVERITY_TO_CEF_SCORE = {
    "critical": 10,
    "high":     7,
    "medium":   5,
    "info":     3,
    "low":      2,
}
_SEVERITY_TO_SYSLOG_PRI = {
    # PRI = facility * 8 + severity. Facility 16 = local0.
    "critical": 16 * 8 + 2,   # critical
    "high":     16 * 8 + 3,   # error
    "medium":   16 * 8 + 4,   # warning
    "info":     16 * 8 + 6,   # info
    "low":      16 * 8 + 6,
}

_VENDOR  = "Plenith"
_PRODUCT = "DeceptionPlatform"
_VERSION = "1.0"

def _utcnow_isoformat() -> str:
    """RFC-3339-style timestamp with explicit Z. Used by RFC 5424."""
    return (
        datetime.datetime.now(datetime.UTC)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )

def _escape_cef_value(s: Any) -> str:
    """CEF spec — escape `|`, `\\`, `=`, and `\\n` inside extension values.
    The header section uses `|` as delimiter so `|` must be `\\|` there too."""
    s = str(s)
    return (
        s.replace("\\", "\\\\")
         .replace("|", "\\|")
         .replace("=", "\\=")
         .replace("\n", "\\n")
         .replace("\r", "\\r")
    )

def _escape_cef_header(s: Any) -> str:
    """Headers use `|` as separator — same escapes minus `=`."""
    s = str(s)
    return (
        s.replace("\\", "\\\\")
         .replace("|", "\\|")
         .replace("\n", " ")
         .replace("\r", " ")
    )

# ---------------------------------------------------------------------------
# CEF
# ---------------------------------------------------------------------------

def to_cef(alert: dict[str, Any], *,
           device_vendor: str = _VENDOR,
           device_product: str = _PRODUCT,
           device_version: str = _VERSION,
           signature_prefix: str = "MC") -> str:
    """Format an alert dict as a CEF v0 line.

    Layout (per the ArcSight spec):
        CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension

    Extensions are space-separated `key=value` pairs (with CEF-escaped
    values). We map the canonical alert fields to CEF Common Information
    Model field names where they exist (`src`, `suser`, `dhost`,
    `cs1`/`cs1Label` for custom strings, `rt` for timestamp).
    """
    action      = alert.get("action", "unknown")
    severity    = alert.get("severity", "info")
    rationale   = alert.get("rationale", "")
    cef_score   = _SEVERITY_TO_CEF_SCORE.get(severity, 3)

    # SignatureID — stable per-rule identifier. Used by SIEM correlation
    # rules to key on alert type. Prepend a vendor prefix so we don't
    # collide with other CEF emitters.
    sig_id = f"{signature_prefix}-{action}"
    name   = action.replace("_", " ").title()

    header = "|".join([
        "CEF:0",
        _escape_cef_header(device_vendor),
        _escape_cef_header(device_product),
        _escape_cef_header(device_version),
        _escape_cef_header(sig_id),
        _escape_cef_header(name),
        str(cef_score),
    ])

    # Build extension key=value pairs
    ext_pairs = []
    field_map = [
        ("src",          alert.get("source_ip")),
        ("suser",        alert.get("claimed_user")),
        ("dhost",        alert.get("hostname")),
        ("act",          action),
        ("msg",          rationale),
        ("cs1",          alert.get("engagement_id")),
        ("cs1Label",     "EngagementID"),
        ("cs2",          alert.get("triggered_by")),
        ("cs2Label",     "TriggerCommand"),
        ("cn1",          alert.get("ts_offset_s")),
        ("cn1Label",     "SessionOffsetSec"),
    ]
    for k, v in field_map:
        if v is None or v == "":
            continue
        ext_pairs.append(f"{k}={_escape_cef_value(v)}")

    # Pass through ATT&CK technique if present
    technique = alert.get("mitre_technique")
    if technique:
        ext_pairs.append(f"cs3={_escape_cef_value(technique)}")
        ext_pairs.append("cs3Label=MitreTechnique")

    return header + "|" + " ".join(ext_pairs)

# ---------------------------------------------------------------------------
# LEEF (IBM QRadar's native ingest format)
# ---------------------------------------------------------------------------

def to_leef(alert: dict[str, Any], *,
            vendor: str = _VENDOR,
            product: str = _PRODUCT,
            version: str = _VERSION,
            separator: str = "\t") -> str:
    """Format an alert dict as a LEEF 2.0 line.

    Layout:
        LEEF:2.0|Vendor|Product|Version|EventID|<sep>|key=value<sep>key=value

    Default sep is tab. QRadar autodetects.
    """
    action   = alert.get("action", "unknown")
    severity = alert.get("severity", "info")

    sep_field = f"x{ord(separator):02x}"  # LEEF encodes the separator hex
    header = "|".join([
        "LEEF:2.0",
        vendor,
        product,
        version,
        action,
        sep_field,
    ])

    pairs = []
    pairs.append(f"sev={_SEVERITY_TO_CEF_SCORE.get(severity, 3)}")
    pairs.append(f"severity={severity}")
    for k_leef, src_key in [
        ("src",           "source_ip"),
        ("usrName",       "claimed_user"),
        ("devHost",       "hostname"),
        ("cat",           "action"),
        ("msg",           "rationale"),
        ("identSrc",      "engagement_id"),
        ("cmd",           "triggered_by"),
    ]:
        v = alert.get(src_key)
        if v is None or v == "":
            continue
        # LEEF k=v escape: replace separator inside values with space
        pairs.append(f"{k_leef}={str(v).replace(separator, ' ')}")
    technique = alert.get("mitre_technique")
    if technique:
        pairs.append(f"mitreTechnique={technique}")

    return header + separator + separator.join(pairs)

# ---------------------------------------------------------------------------
# RFC 5424 syslog (carries CEF/LEEF as the message)
# ---------------------------------------------------------------------------

def to_syslog_5424(alert: dict[str, Any], *,
                    hostname: str | None = None,
                    app_name: str = "plenith",
                    msgid: str | None = None,
                    body_format: str = "cef") -> str:
    """Wrap a CEF or LEEF line in an RFC 5424 syslog frame.

    Format:
        <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD-ELEMENT MSG

    body_format: "cef" | "leef" | "plain"
    """
    severity = alert.get("severity", "info")
    pri = _SEVERITY_TO_SYSLOG_PRI.get(severity, 22 * 8 + 6)
    version = 1
    ts = _utcnow_isoformat()
    host = hostname or alert.get("hostname") or socket.gethostname()
    procid = "-"   # no process id
    msgid = msgid or alert.get("action", "-")
    sd = "-"       # no structured data

    if body_format == "cef":
        body = to_cef(alert)
    elif body_format == "leef":
        body = to_leef(alert)
    else:
        body = alert.get("rationale", alert.get("action", ""))

    return (
        f"<{pri}>{version} {ts} {host} {app_name} {procid} {msgid} {sd} {body}"
    )

# ---------------------------------------------------------------------------
# Generic JSON (for Splunk HEC, ELK bulk, Datadog logs intake, etc.)
# ---------------------------------------------------------------------------

def to_json_event(alert: dict[str, Any], *,
                   sourcetype: str = "plenith:alert") -> dict[str, Any]:
    """A JSON envelope suitable for Splunk HEC (event field), Elastic
    bulk (_source), Datadog, Sumo, etc. The transport in `siem.py` is
    what actually POSTs this to the right endpoint."""
    out = {
        "sourcetype":  sourcetype,
        "source":      "plenith",
        "host":        alert.get("hostname", "plenith"),
        "time":        _utcnow_isoformat(),
        "event": {
            "action":         alert.get("action"),
            "severity":       alert.get("severity"),
            "rationale":      alert.get("rationale"),
            "engagement_id":  alert.get("engagement_id"),
            "source_ip":      alert.get("source_ip"),
            "claimed_user":   alert.get("claimed_user"),
            "hostname":       alert.get("hostname"),
            "triggered_by":   alert.get("triggered_by"),
            "ts_offset_s":    alert.get("ts_offset_s"),
        },
    }
    # Pass through MITRE info
    if alert.get("mitre_technique"):
        out["event"]["mitre"] = {
            "technique":      alert.get("mitre_technique"),
            "tactic":         alert.get("mitre_tactic"),
            "technique_name": alert.get("mitre_technique_name"),
        }
    # Drop nulls — Splunk and Elastic both prefer absent over null
    out["event"] = {k: v for k, v in out["event"].items() if v is not None}
    return out
