"""Compliance attestation reporting.

Generates evidence-mapped reports for the three frameworks SOCs actually
get audited against:

  SOC 2 Trust Services Criteria (TSC 2017)
      Common Criteria (CC1.1 → CC9.2)
      Plus availability (A1.1-A1.3), confidentiality (C1.1-C1.2),
      processing integrity (PI1.1-PI1.5), privacy (P1.1-P8.1).
      We focus on Security (Common) since deception is a Security control.

  ISO/IEC 27001:2022 Annex A
      93 controls across 4 themes (Organizational, People, Physical,
      Technological). We map to the Technological subset (A.8.x)
      where Plenith is most relevant.

  NIS2 Directive (EU 2022/2555)
      Article 21 cybersecurity risk-management measures (10 categories).
      Required of EU "essential" and "important" entities from
      October 2024 onward.

The reporter pulls from real engagement state (via audit.py) to produce
control-level evidence — not just "we have a control" but "here's the
JSONL log of every time it fired in the last 90 days."

Module layout:
    controls.py     — the control-to-evidence-source mapping table
    evidence.py     — pulls evidence from engagement state, IoC log,
                      isolation probes, MFA decisions, content rotation
    report.py       — renders Markdown/HTML/JSON
"""
from . import controls, evidence, report, runbooks  # noqa: F401

__all__ = ["controls", "evidence", "report", "runbooks"]
