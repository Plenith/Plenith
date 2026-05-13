"""Compliance attestation renderer — Markdown / HTML / JSON.

Takes a `ControlMapping` list + an `EvidenceReport` and produces a
human-readable (Markdown), browser-renderable (HTML), or machine-
parseable (JSON) attestation. The Markdown variant is what auditors
attach to their evidence binder; HTML is what's shared with the audit
committee; JSON is what feeds an upstream GRC platform (OneTrust,
ServiceNow GRC, Workiva).
"""
from __future__ import annotations

import datetime
import html
import json
from dataclasses import asdict
from typing import Any, Iterable, List

from .controls import ControlMapping, all_controls
from .evidence import EvidenceReport, evidence_value


# ---------------------------------------------------------------------------
# Per-control assessment — does this control have ANY evidence backing it?
# ---------------------------------------------------------------------------

def _has_meaningful_evidence(value: Any) -> bool:
    """Heuristic — True iff the evidence value is non-empty / non-zero."""
    if value is None:
        return False
    if isinstance(value, (int, float)):
        return value > 0
    if isinstance(value, (list, set, tuple, str)):
        return len(value) > 0
    if isinstance(value, dict):
        if not value:
            return False
        # All-zero dict = no evidence
        return any(_has_meaningful_evidence(v) for v in value.values())
    return True


def _assess(control: ControlMapping, rep: EvidenceReport) -> dict:
    """Return {status, evidence_collected} for one control."""
    coll: dict = {}
    any_evidence = False
    for ev_type in control.evidence:
        val = evidence_value(rep, ev_type)
        coll[ev_type] = val
        if _has_meaningful_evidence(val):
            any_evidence = True
    if not control.evidence:
        status = "out-of-band"     # control intentionally not auto-mapped
    elif any_evidence:
        status = "evidence-present"
    else:
        status = "no-evidence-this-period"
    return {"status": status, "evidence": coll}


# ---------------------------------------------------------------------------
# Markdown renderer
# ---------------------------------------------------------------------------

_STATUS_SYMBOL = {
    "evidence-present":        "✓ EVIDENCE",
    "no-evidence-this-period": "○ NO DATA",
    "out-of-band":             "— OUT-OF-BAND",
}


def to_markdown(controls: Iterable[ControlMapping],
                rep: EvidenceReport,
                *, title: str = "Plenith Compliance Attestation") -> str:
    """Build a Markdown attestation report."""
    period_start = datetime.datetime.fromtimestamp(rep.period_start_ts).isoformat(timespec="seconds")
    period_end   = datetime.datetime.fromtimestamp(rep.period_end_ts).isoformat(timespec="seconds")

    lines: List[str] = []
    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"**Reporting period:** {period_start} → {period_end}")
    lines.append("")

    # --- Summary block ---
    framework_counts: dict = {}
    by_status: dict = {"evidence-present": 0, "no-evidence-this-period": 0, "out-of-band": 0}
    for c in controls:
        a = _assess(c, rep)
        by_status[a["status"]] += 1
        framework_counts.setdefault(c.framework, {"total": 0, "with-evidence": 0})
        framework_counts[c.framework]["total"] += 1
        if a["status"] == "evidence-present":
            framework_counts[c.framework]["with-evidence"] += 1

    lines.append("## Summary")
    lines.append("")
    lines.append("| Framework | Controls in scope | With evidence this period |")
    lines.append("|---|---:|---:|")
    for fw, c in sorted(framework_counts.items()):
        pct = (c["with-evidence"] / c["total"] * 100) if c["total"] else 0
        lines.append(f"| {fw} | {c['total']} | {c['with-evidence']} ({pct:.0f}%) |")
    lines.append("")
    lines.append(f"**Status totals:** "
                 f"{by_status['evidence-present']} evidence-present, "
                 f"{by_status['no-evidence-this-period']} no-data, "
                 f"{by_status['out-of-band']} out-of-band")
    lines.append("")

    # --- Platform-wide facts ---
    lines.append("## Platform facts (period-end snapshot)")
    lines.append("")
    lines.append(f"- Engagements observed: **{rep.engagement_count}**")
    if rep.alerts_by_severity:
        sev_summary = ", ".join(f"{k}={v}" for k, v in sorted(rep.alerts_by_severity.items()))
        lines.append(f"- Alerts fired: {sev_summary}")
    lines.append(f"- Active policy engine: `{rep.policy_engine}`")
    lines.append(f"- ATT&CK techniques covered: {len(rep.mitre_techniques)}")
    lines.append(f"- ATT&CK tactics covered: {len(rep.mitre_tactics)}")
    if rep.siem_connectors:
        lines.append(f"- SIEM/SOAR connectors configured: {', '.join(rep.siem_connectors)}")
    if rep.mfa_decisions:
        lines.append(f"- MFA decisions in period: {rep.mfa_decisions}")
    if rep.rotation_epochs:
        lines.append(f"- Content-rotation epochs: {', '.join(rep.rotation_epochs)}")
    if rep.counter_ai_detections:
        lines.append(f"- Counter-AI detections (likely-LLM attackers): "
                     f"{rep.counter_ai_detections} "
                     f"({rep.counter_ai_proven_via_trap} proven via trap)")
    lines.append("")

    # --- Per-control table ---
    by_fw: dict = {}
    for c in controls:
        by_fw.setdefault(c.framework, []).append(c)
    for fw in sorted(by_fw):
        lines.append(f"## {fw}")
        lines.append("")
        for c in by_fw[fw]:
            a = _assess(c, rep)
            status_text = _STATUS_SYMBOL.get(a["status"], "?")
            lines.append(f"### {c.control_id} — {c.title}    `{status_text}`")
            lines.append("")
            lines.append(f"> {c.statement}")
            lines.append("")
            if c.notes:
                lines.append(f"**Implementation:** {c.notes}")
                lines.append("")
            if c.evidence:
                lines.append("**Evidence collected:**")
                lines.append("")
                for ev_type, val in a["evidence"].items():
                    pretty = _format_evidence_value(val)
                    lines.append(f"- `{ev_type}`: {pretty}")
                lines.append("")
            else:
                lines.append("_Evidence for this control is collected out-of-band "
                             "(e.g. via the operator runbook or upstream GRC platform)._")
                lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _format_evidence_value(val: Any) -> str:
    if val is None:
        return "_(no data this period)_"
    if isinstance(val, (int, float)):
        return f"`{val}`"
    if isinstance(val, dict):
        if not val:
            return "_(empty)_"
        return ", ".join(f"`{k}={v}`" for k, v in sorted(val.items()))
    if isinstance(val, list):
        if not val:
            return "_(empty)_"
        return "`" + "`, `".join(map(str, val)) + "`"
    return f"`{val}`"


# ---------------------------------------------------------------------------
# HTML renderer — wraps Markdown in a minimal stylesheet
# ---------------------------------------------------------------------------

_HTML_CSS = """
* { box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
       max-width: 900px; margin: 2em auto; padding: 0 1em;
       color: #1d1d1f; line-height: 1.5; }
h1 { border-bottom: 2px solid #1d1d1f; padding-bottom: 6px; }
h2 { margin-top: 2em; color: #1d3a8a; }
h3 { margin-top: 1.5em; font-size: 1.1em; }
table { border-collapse: collapse; margin: 1em 0; }
th, td { padding: 6px 12px; border: 1px solid #d1d1d6; text-align: left; }
th { background: #f5f5f7; }
code { background: #f5f5f7; padding: 1px 6px; border-radius: 3px;
       font-family: 'SF Mono', Menlo, monospace; font-size: 0.9em; }
blockquote { border-left: 3px solid #1d3a8a; margin: 8px 0; padding: 4px 12px;
             background: #f5f8ff; color: #555; }
.status-evidence-present { color: #1c7430; font-weight: 600; }
.status-no-evidence-this-period { color: #8a6d3b; }
.status-out-of-band { color: #6c757d; }
"""


def to_html(controls: Iterable[ControlMapping], rep: EvidenceReport,
            *, title: str = "Plenith Compliance Attestation") -> str:
    """Render the same content as `to_markdown` but as a self-contained
    HTML page (no JS, no external CSS). Useful for sharing with the
    audit committee."""
    md = to_markdown(controls, rep, title=title)
    # Tiny Markdown → HTML — handles the subset our generator produces.
    html_body = _markdown_to_html(md)
    return (
        "<!doctype html><html><head>"
        f"<meta charset='utf-8'><title>{html.escape(title)}</title>"
        f"<style>{_HTML_CSS}</style>"
        "</head><body>"
        f"{html_body}"
        "</body></html>"
    )


def _markdown_to_html(md: str) -> str:
    """Minimal Markdown → HTML for the limited shapes our generator emits.
    Handles: h1/h2/h3, tables, blockquotes, lists, inline code, bold."""
    out: List[str] = []
    in_list = False
    in_table = False
    table_buf: List[str] = []

    def flush_list():
        nonlocal in_list
        if in_list:
            out.append("</ul>")
            in_list = False

    def flush_table():
        nonlocal in_table
        if in_table and table_buf:
            out.append("<table>")
            for i, row in enumerate(table_buf):
                cells = [c.strip() for c in row.strip("|").split("|")]
                if i == 1 and all(c.replace("-", "").replace(":", "").strip() == "" for c in cells):
                    continue  # markdown separator
                tag = "th" if i == 0 else "td"
                out.append("<tr>" + "".join(f"<{tag}>{_inline(c)}</{tag}>" for c in cells) + "</tr>")
            out.append("</table>")
        in_table = False
        table_buf.clear()

    def _inline(s: str) -> str:
        s = html.escape(s)
        # Re-apply inline code spans (backticks)
        import re
        s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
        s = re.sub(r"\*\*([^\*]+)\*\*", r"<b>\1</b>", s)
        s = re.sub(r"_([^_]+)_", r"<i>\1</i>", s)
        return s

    for line in md.splitlines():
        stripped = line.rstrip()
        if stripped.startswith("# "):
            flush_list(); flush_table()
            out.append(f"<h1>{_inline(stripped[2:])}</h1>")
        elif stripped.startswith("## "):
            flush_list(); flush_table()
            out.append(f"<h2>{_inline(stripped[3:])}</h2>")
        elif stripped.startswith("### "):
            flush_list(); flush_table()
            # H3 lines have a status pill — pull it out
            text = stripped[4:]
            cls = ""
            if "EVIDENCE" in text:
                cls = "status-evidence-present"
            elif "NO DATA" in text:
                cls = "status-no-evidence-this-period"
            elif "OUT-OF-BAND" in text:
                cls = "status-out-of-band"
            out.append(f"<h3 class='{cls}'>{_inline(text)}</h3>")
        elif stripped.startswith("> "):
            flush_list(); flush_table()
            out.append(f"<blockquote>{_inline(stripped[2:])}</blockquote>")
        elif stripped.startswith("- "):
            flush_table()
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{_inline(stripped[2:])}</li>")
        elif stripped.startswith("|") and stripped.endswith("|"):
            flush_list()
            in_table = True
            table_buf.append(stripped)
        elif not stripped:
            flush_list(); flush_table()
        else:
            flush_list(); flush_table()
            out.append(f"<p>{_inline(stripped)}</p>")
    flush_list(); flush_table()
    return "\n".join(out)


# ---------------------------------------------------------------------------
# JSON renderer — for GRC platform ingest
# ---------------------------------------------------------------------------

def to_json(controls: Iterable[ControlMapping], rep: EvidenceReport,
            *, title: str = "Plenith Compliance Attestation") -> str:
    """JSON representation of the same data. Schema:
        {
          "title": ...,
          "period": {"start": ..., "end": ...},
          "evidence_report": <EvidenceReport dict>,
          "controls": [ {framework, control_id, title, statement, notes,
                         status, evidence: { ... }}, ... ]
        }
    """
    controls = list(controls)
    payload = {
        "title":  title,
        "period": {
            "start": datetime.datetime.fromtimestamp(rep.period_start_ts).isoformat(),
            "end":   datetime.datetime.fromtimestamp(rep.period_end_ts).isoformat(),
        },
        "evidence_report": asdict(rep),
        "controls":        [],
    }
    for c in controls:
        a = _assess(c, rep)
        payload["controls"].append({
            "framework":  c.framework,
            "control_id": c.control_id,
            "title":      c.title,
            "statement":  c.statement,
            "notes":      c.notes,
            "status":     a["status"],
            "evidence":   a["evidence"],
        })
    return json.dumps(payload, indent=2, sort_keys=True, default=str)
