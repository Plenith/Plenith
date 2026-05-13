"""SIEM / SOAR / MFA / ChatOps connector ecosystem.

The story: Plenith alerts only matter if they show up in the buyer's
existing dashboard. Every commercial deception competitor (Acalvio,
Illusive, Attivo, Splunk DECEIVE) ships with native connectors into the
SIEM/SOAR/identity stack the SOC already runs. This package is the
equivalent for our platform — one canonical alert dict in, many wire
formats out.

Modules:
    formats       — CEF (ArcSight), LEEF (QRadar), syslog RFC 5424
    siem          — Splunk HEC, Elasticsearch bulk, generic webhook
    chatops       — Slack, Teams, PagerDuty native payloads
    mitre         — ATT&CK technique mapping + Sigma tag helpers
    mfa_providers — real Duo / Okta / Authy SDK shapes
    stix          — STIX 2.1 IoC bundle export
"""
from . import (  # noqa: F401
    chatops, formats, mfa_providers, mitre, siem, soar, stix, taxii,
)

__all__ = [
    "chatops", "formats", "mfa_providers", "mitre", "siem",
    "soar", "stix", "taxii",
]
