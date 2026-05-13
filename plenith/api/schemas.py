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
from typing import Any, Dict, List, Optional

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
    components: Dict[str, str] = Field(
        default_factory=dict,
        description="Per-component status (state-dir, logs-dir, policy, llm, ...)",
    )


class VersionResponse(BaseModel):
    version: str   = Field(..., examples=["1.0.0"])
    api_version: str = Field("v1", examples=["v1"])
    deployment_id: Optional[str] = None
    content_epoch: Optional[str] = None
    corp_name:    Optional[str] = None
    policy_engine: str = Field("heuristic", examples=["heuristic", "trained_rl"])


# ---------------------------------------------------------------------------
# Engagements
# ---------------------------------------------------------------------------

class AlertSummary(BaseModel):
    """Compact alert representation for listing endpoints."""
    action:        str
    severity:      str = Field(..., examples=["critical", "high", "medium", "info"])
    rationale:     Optional[str] = None
    ts_offset_s:   Optional[float] = None
    triggered_by:  Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_tactic:    Optional[str] = None


class EngagementSummary(BaseModel):
    """One row of the engagement-list endpoint."""
    engagement_id:    str
    claimed_user:     str
    source_ip:        str
    persona:          Optional[str] = None
    first_seen_at:    Optional[float] = None
    last_seen_at:     Optional[float] = None
    dwell_seconds:    Optional[float] = None
    connection_count: int = 1
    severity_max:     str = Field("info")
    alert_count:      int = 0
    counter_ai_confidence: Optional[float] = None
    counter_ai_proven: bool = False


class EngagementDetail(BaseModel):
    """Full engagement detail. Includes everything in the persisted
    state plus computed fields (severity_max, alert_count, etc.)."""
    engagement_id:    str
    claimed_user:     str
    source_ip:        str
    persona:          Optional[str] = None
    first_seen_at:    Optional[float] = None
    last_seen_at:     Optional[float] = None
    dwell_seconds:    Optional[float] = None
    connection_count: int = 1
    cwd:              Optional[str] = None
    observed:         Dict[str, Any] = Field(default_factory=dict)
    actions_taken:    List[Dict[str, Any]] = Field(default_factory=list)
    commands:         List[Dict[str, Any]] = Field(default_factory=list)
    iocs_extracted:   List[str] = Field(default_factory=list)


class EngagementListResponse(BaseModel):
    engagements: List[EngagementSummary]
    total: int


class NarrativeResponse(BaseModel):
    engagement_id: str
    narrative:     str
    generated_at:  datetime


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

class AlertListResponse(BaseModel):
    alerts: List[AlertSummary]
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
    reason:   Optional[str] = Field(None,
        description="Human-readable note attached to the audit trail.")


class MFADecisionResponse(BaseModel):
    ip:       str
    decision: str
    written:  bool
    path:     str


# ---------------------------------------------------------------------------
# Policy / content
# ---------------------------------------------------------------------------

class PolicyInfo(BaseModel):
    engine:        str = Field(..., examples=["heuristic", "rl", "trained_rl"])
    model_path:    Optional[str] = None
    n_actions:     int = 16
    obs_features:  int = 21


class ContentManifest(BaseModel):
    """Same shape as ContentRotator.build_manifest() returns."""
    enabled:           bool
    deployment_id:     Optional[str] = None
    epoch:             Optional[str] = None
    signature:         Optional[str] = None
    corp:              Dict[str, Any] = Field(default_factory=dict)
    artifact_hashes:   Dict[str, str] = Field(default_factory=dict)
    artifact_sizes:    Dict[str, int] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class APIError(BaseModel):
    error:   str
    code:    int
    detail:  Optional[str] = None


# Allow Pydantic to be lax about extra fields in observed dicts —
# we want to surface whatever the orchestrator wrote without losing data.
for _cls in (EngagementDetail, EngagementSummary):
    _cls.model_config = ConfigDict(extra="allow")
