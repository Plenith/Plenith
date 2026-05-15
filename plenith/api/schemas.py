"""Pydantic schemas for the Plenith REST API.

These models do double duty:
  1. Request/response validation in FastAPI handlers
  2. Auto-generated OpenAPI schemas (consumed by Swagger UI, the
     Python SDK, and any code-gen client downstream consumers run)

Field names match the canonical engagement / alert dict shapes used
throughout the rest of the codebase, so the API surface is just a
typed view of state we already have.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Health / status
# ---------------------------------------------------------------------------

class HealthResponse(BaseModel):
    """Liveness probe. Returns 200 + this body when the API process
    is responsive — independent of the underlying fabric."""
    status: str = Field("ok", examples=["ok"])

class ReadyResponse(BaseModel):
    """Readiness probe. Returns 200 only when Plenith can serve
    real traffic — typically gates k8s readinessProbe."""
    status: str = Field(..., examples=["ready", "starting", "degraded"])
    components: dict[str, str] = Field(
        default_factory=dict,
        description="Per-component status (state-dir, logs-dir, policy, llm, ...)",
    )

class VersionResponse(BaseModel):
    version: str   = Field(..., examples=["1.0.0"])
    api_version: str = Field("v1", examples=["v1"])
    deployment_id: str | None = None
    content_epoch: str | None = None
    corp_name:    str | None = None
    policy_engine: str = Field("heuristic", examples=["heuristic", "trained_rl"])

# ---------------------------------------------------------------------------
# Engagements
# ---------------------------------------------------------------------------

class AlertSummary(BaseModel):
    """Compact alert representation for listing endpoints."""
    action:        str
    severity:      str = Field(..., examples=["critical", "high", "medium", "info"])
    rationale:     str | None = None
    ts_offset_s:   float | None = None
    triggered_by:  str | None = None
    mitre_technique: str | None = None
    mitre_tactic:    str | None = None

class EngagementSummary(BaseModel):
    """One row of the engagement-list endpoint."""
    engagement_id:    str
    claimed_user:     str
    source_ip:        str
    persona:          str | None = None
    first_seen_at:    float | None = None
    last_seen_at:     float | None = None
    dwell_seconds:    float | None = None
    connection_count: int = 1
    severity_max:     str = Field("info")
    alert_count:      int = 0
    counter_ai_confidence: float | None = None
    counter_ai_proven: bool = False

class EngagementDetail(BaseModel):
    """Full engagement detail. Includes everything in the persisted
    state plus computed fields (severity_max, alert_count, etc.)."""
    engagement_id:    str
    claimed_user:     str
    source_ip:        str
    persona:          str | None = None
    first_seen_at:    float | None = None
    last_seen_at:     float | None = None
    dwell_seconds:    float | None = None
    connection_count: int = 1
    cwd:              str | None = None
    observed:         dict[str, Any] = Field(default_factory=dict)
    actions_taken:    list[dict[str, Any]] = Field(default_factory=list)
    commands:         list[dict[str, Any]] = Field(default_factory=list)
    iocs_extracted:   list[str] = Field(default_factory=list)

class EngagementListResponse(BaseModel):
    engagements: list[EngagementSummary]
    total: int

class NarrativeResponse(BaseModel):
    engagement_id: str
    narrative:     str
    generated_at:  datetime

# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

class AlertListResponse(BaseModel):
    alerts: list[AlertSummary]
    total:  int

# ---------------------------------------------------------------------------
# Isolation / probes
# ---------------------------------------------------------------------------

class IsolationProbeResult(BaseModel):
    pass_count: int
    fail_count: int
    total:      int
    output:     str = Field(..., description="Full stdout from validate.sh")
    succeeded:  bool

# ---------------------------------------------------------------------------
# MFA
# ---------------------------------------------------------------------------

class MFADecisionInjection(BaseModel):
    decision: str = Field(..., examples=["pass", "fail"],
                           description="Either 'pass' or 'fail'.")
    reason:   str | None = Field(None,
        description="Human-readable note attached to the audit trail.")

class MFADecisionResponse(BaseModel):
    ip:       str
    decision: str
    written:  bool
    path:     str

# ---------------------------------------------------------------------------
# Acknowledgement — Phase 2 of docs/design/UI_WIRING.md
# ---------------------------------------------------------------------------

class AckRequest(BaseModel):
    action_name: str = Field(..., min_length=1,
        description="The action_taken name to ack (e.g. alert_dns_exfil).")
    op_id: str | None = Field(None,
        description="Identifier for the analyst recording the ack. "
                    "Defaults to 'anonymous' in open-mode.")
    note: str | None = Field(None,
        description="Optional markdown context for the ack — visible to "
                    "the next operator on shift.")

class AckResponse(BaseModel):
    engagement_id:   str
    action_name:     str
    acknowledged_at: float
    acknowledged_by: str

class AckRemovedResponse(BaseModel):
    removed: bool

class BatchAckRequest(BaseModel):
    ids: list[str] = Field(..., min_length=1,
        description="Engagement IDs to ack.")
    action_name: str = Field(..., min_length=1,
        description="Specific action_taken name to ack across all engagements. "
                    "Cannot be omitted — the API refuses 'ack everything' to "
                    "avoid unintentionally clearing the SOC queue.")
    op_id: str | None = None
    note:  str | None = None

class BatchAckResponse(BaseModel):
    acked:   int
    skipped: int

# ---------------------------------------------------------------------------
# Notes / Snapshot / Kill / Escalate — Phase 3 of UI_WIRING.md
# ---------------------------------------------------------------------------

class NoteCreate(BaseModel):
    body:   str = Field(..., min_length=1,
                         description="Markdown body of the note.")
    author: str | None = Field(None,
        description="Identifier for the analyst posting the note. "
                    "Defaults to 'anonymous' in open-mode.")

class NoteOut(BaseModel):
    id:     str
    author: str
    ts:     float
    body:   str

class NoteListResponse(BaseModel):
    engagement_id: str
    notes: list[NoteOut]

class NoteDeleteResponse(BaseModel):
    removed: bool

class SnapshotRequest(BaseModel):
    op_id: str | None = None
    note:  str | None = Field(None,
        description="Optional context — appears in the archive's manifest.")

class SnapshotResponse(BaseModel):
    engagement_id: str
    path:          str
    name:          str
    size:          int
    sha256:        str
    captured_at:   float
    captured_by:   str
    members:       int
    note:          str

class SnapshotListResponse(BaseModel):
    engagement_id: str
    snapshots:     list[dict]

class KillRequest(BaseModel):
    op_id:  str | None = None
    reason: str | None = Field(None,
        description="Why this session is being killed — analyst note.")

class KillResponse(BaseModel):
    engagement_id: str
    status:        str       # "pending" | "killed" | already-killed
    requested_at:  float
    requested_by:  str
    reason:        str

class EscalateRequest(BaseModel):
    tier:    str = Field("L2",
        description="Escalation tier — 'L2' or 'L3'.  L3 bumps severity "
                    "to critical regardless of underlying alert.")
    message: str | None = Field(None,
        description="Optional context appended to the chatops body.")

class EscalateResponse(BaseModel):
    engagement_id:     str
    tier:              str
    connectors_fired:  list[str]
    connectors_failed: list[dict]

# ---------------------------------------------------------------------------
# Policy / content
# ---------------------------------------------------------------------------

class PolicyInfo(BaseModel):
    engine:        str = Field(..., examples=["heuristic", "rl", "trained_rl"])
    model_path:    str | None = None
    n_actions:     int = 16
    obs_features:  int = 21

class ContentManifest(BaseModel):
    """Same shape as ContentRotator.build_manifest() returns."""
    enabled:           bool
    deployment_id:     str | None = None
    epoch:             str | None = None
    signature:         str | None = None
    corp:              dict[str, Any] = Field(default_factory=dict)
    artifact_hashes:   dict[str, str] = Field(default_factory=dict)
    artifact_sizes:    dict[str, int] = Field(default_factory=dict)

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class APIError(BaseModel):
    error:   str
    code:    int
    detail:  str | None = None

# Allow Pydantic to be lax about extra fields in observed dicts —
# we want to surface whatever the orchestrator wrote without losing data.
for _cls in (EngagementDetail, EngagementSummary):
    _cls.model_config = ConfigDict(extra="allow")
