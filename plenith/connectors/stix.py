"""STIX 2.1 bundle export for IoC sharing.

STIX (Structured Threat Information eXpression) is the standard format
for sharing threat intelligence across orgs. The MISP, OpenCTI,
TheHive, and Anomali ThreatStream platforms all consume it natively;
ISACs (FS-ISAC, H-ISAC, etc.) require it for any IoC contribution.

We produce STIX 2.1 (the current spec) Bundle objects from a list of
Plenith engagements. Each engagement's IoCs become SDO/SCO objects:

  - source IP   → ipv4-addr observable + indicator pattern
  - exfil URL   → url observable + indicator pattern
  - file hashes → file observable + indicator pattern
  - attacker TTPs → attack-pattern (linked to MITRE technique)

Reference: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html

Pure stdlib — no `stix2` dep needed for the producer side. Consumers
will need a real STIX library or be happy with the JSON.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import uuid
from typing import Any
from collections.abc import Iterable

_NAMESPACE = "plenith--"

def _utcnow() -> str:
    """RFC 3339 timestamp in the STIX-required format."""
    return (
        datetime.datetime.now(datetime.UTC)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )

def _stable_id(prefix: str, key: str) -> str:
    """Deterministic STIX id (UUIDv5-like) so re-running on the same
    engagement produces the same identifier. Useful for de-duping at
    the consumer side."""
    h = hashlib.sha1(key.encode("utf-8")).digest()
    # Re-shape into a UUID
    bits = list(h[:16])
    bits[6] = (bits[6] & 0x0F) | 0x50  # version 5
    bits[8] = (bits[8] & 0x3F) | 0x80  # variant 10
    return f"{prefix}--{uuid.UUID(bytes=bytes(bits))}"

# ---------------------------------------------------------------------------
# STIX object builders
# ---------------------------------------------------------------------------

def _identity_object() -> dict[str, Any]:
    """The Plenith "identity" SDO — the producer of all our IoCs."""
    return {
        "type": "identity",
        "spec_version": "2.1",
        "id": _stable_id("identity", "plenith-platform"),
        "created":  _utcnow(),
        "modified": _utcnow(),
        "name":     "Plenith Deception Platform",
        "identity_class": "system",
    }

def _ipv4_indicator(ip: str, label: str = "attacker") -> dict[str, Any]:
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": _stable_id("indicator", f"ipv4:{ip}"),
        "created":  _utcnow(),
        "modified": _utcnow(),
        "name":     f"Attacker IP {ip}",
        "indicator_types": ["malicious-activity"],
        "pattern_type": "stix",
        "pattern":  f"[ipv4-addr:value = '{ip}']",
        "valid_from": _utcnow(),
        "labels": [label],
    }

def _url_indicator(url: str) -> dict[str, Any]:
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": _stable_id("indicator", f"url:{url}"),
        "created":  _utcnow(),
        "modified": _utcnow(),
        "name":     f"Exfil URL {url}",
        "indicator_types": ["malicious-activity"],
        "pattern_type": "stix",
        "pattern":  f"[url:value = {json.dumps(url)}]",
        "valid_from": _utcnow(),
        "labels": ["exfil"],
    }

def _domain_indicator(domain: str) -> dict[str, Any]:
    # H-1 fix: use json.dumps to escape the domain value the same way
    # _url_indicator already does on the line above. Pre-fix, a single
    # quote in the attacker-controlled subdomain would break out of the
    # STIX pattern expression (`[domain-name:value = 'a'; or true; --']`)
    # and downstream consumers that compile STIX patterns (sigma-converter,
    # OpenCTI, Anomali) would treat the value as an expression. Embedded
    # nulls/newlines also corrupt parsers. json.dumps produces a
    # correctly-quoted JSON string, which is also valid in STIX 2.1
    # pattern values.
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": _stable_id("indicator", f"domain:{domain}"),
        "created":  _utcnow(),
        "modified": _utcnow(),
        "name":     f"Suspicious domain {domain}",
        "indicator_types": ["malicious-activity"],
        "pattern_type": "stix",
        "pattern":  f"[domain-name:value = {json.dumps(domain)}]",
        "valid_from": _utcnow(),
        "labels": ["c2", "exfil"],
    }

def _attack_pattern(mitre_technique: str, mitre_name: str) -> dict[str, Any]:
    return {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": _stable_id("attack-pattern", f"mitre:{mitre_technique}"),
        "created":  _utcnow(),
        "modified": _utcnow(),
        "name":     mitre_name,
        "external_references": [{
            "source_name": "mitre-attack",
            "external_id": mitre_technique,
            "url": f"https://attack.mitre.org/techniques/{mitre_technique.replace('.', '/')}/",
        }],
    }

def _observed_data(observable: dict[str, Any], first_seen: str, last_seen: str) -> dict[str, Any]:
    """STIX 2.1 observed-data SDO wrapping one or more SCOs."""
    return {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": _stable_id("observed-data", json.dumps(observable, sort_keys=True)),
        "created":   _utcnow(),
        "modified":  _utcnow(),
        "first_observed": first_seen,
        "last_observed":  last_seen,
        "number_observed": 1,
        "objects":   {"0": observable},
    }

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

# Suspicious-domain markers we detect in exfil URLs
_EXFIL_TLDS = (
    ".oast.live", ".oast.site", ".oast.pro",
    ".burpcollaborator.net",
    ".interactsh.com", ".interact.sh",
    ".requestcatcher.com",
    ".ngrok.io", ".ngrok.app",
    ".webhook.site",
)

def _extract_domain(url_or_cmd: str) -> str | None:
    """Pull out a known-suspicious TLD from a curl/wget/dig command line."""
    low = url_or_cmd.lower()
    for tld in _EXFIL_TLDS:
        if tld in low:
            idx = low.find(tld)
            # Walk left to a space/quote to find the FQDN start
            start = idx
            while start > 0 and low[start - 1] not in " \"'`(":
                start -= 1
            # Walk right to end-of-fqdn
            end = idx + len(tld)
            while end < len(low) and low[end] not in " \"'`)/?":
                end += 1
            return low[start:end]
    return None

def bundle_from_engagements(engagements: Iterable[dict[str, Any]],
                              *, include_attack_patterns: bool = True) -> dict[str, Any]:
    """Build a STIX 2.1 Bundle from a list of engagement dicts.

    Inputs: the same engagement dicts `audit.load_engagements()` produces.
    Output: a STIX 2.1 Bundle object as a Python dict — caller dumps to
    JSON for sharing.
    """
    bundle_id = _stable_id("bundle", str(uuid.uuid4()))
    objects: list[dict[str, Any]] = [_identity_object()]
    seen_ids: set = set()

    def add(obj: dict[str, Any]) -> None:
        if obj["id"] not in seen_ids:
            objects.append(obj)
            seen_ids.add(obj["id"])

    # MITRE-mapping import is lazy to avoid a circular dep if mitre.py
    # ever needs stix helpers.
    from . import mitre as mitre_mod

    for eng in engagements:
        eng_id = eng.get("engagement_id", "")
        src_ip = eng.get("source_ip")
        first_seen = _utcnow()      # we don't have per-event timestamps
        last_seen  = _utcnow()

        # Attacker IP
        if src_ip:
            add(_ipv4_indicator(src_ip))

        # Exfil URLs / domains from observed dict
        obs = eng.get("observed", {}) or {}
        for cmd in (obs.get("dns_exfil_commands", []) or []):
            domain = _extract_domain(cmd)
            if domain:
                add(_domain_indicator(domain))

        # Attack patterns from the actions taken
        if include_attack_patterns:
            for action in eng.get("actions_taken", []) or []:
                name = action.get("action") if isinstance(action, dict) else None
                if not name:
                    continue
                mappings = mitre_mod.all_techniques_for(name)
                for m in mappings:
                    # Skip non-ATT&CK pseudo-mappings (mitigations, MC-AI-*)
                    if not m.technique.startswith("T"):
                        continue
                    add(_attack_pattern(m.technique, m.technique_name))

    return {
        "type":         "bundle",
        "id":           bundle_id,
        "objects":      objects,
    }

def write_bundle(engagements: Iterable[dict[str, Any]], path) -> None:
    """Convenience: build + dump JSON to a file."""
    from pathlib import Path
    bundle = bundle_from_engagements(engagements)
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")
