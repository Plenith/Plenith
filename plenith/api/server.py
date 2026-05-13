"""FastAPI application — Plenith REST API.

`build_app(cfg, ...)` constructs the FastAPI instance with config-
driven auth + state-dir resolution. The CLI `tools/api_server.py`
wraps this with uvicorn.

Every route handler is intentionally small — it pulls state via the
same helpers `tools/audit.py` and the dashboard use, validates via
the Pydantic schemas in `schemas.py`, and returns. No business logic
lives in the API layer; it's a typed view over state.
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse, PlainTextResponse

from .auth import APIAuth, make_dependency
from .metrics import RequestCounters, render_metrics
from .schemas import (
    AlertListResponse,
    AlertSummary,
    APIError,
    ContentManifest,
    EngagementDetail,
    EngagementListResponse,
    EngagementSummary,
    HealthResponse,
    IsolationProbeResult,
    MFADecisionInjection,
    MFADecisionResponse,
    NarrativeResponse,
    PolicyInfo,
    ReadyResponse,
    VersionResponse,
)


_VERSION = "1.0.0"
_API_VERSION = "v1"


# ---------------------------------------------------------------------------
# State loader — shared helper that walks the state dirs once
# ---------------------------------------------------------------------------

_AUDIT_MODULE = None


def _audit():
    """Lazy-load the audit module so the API can render narratives,
    extract IoCs, and walk engagement state the same way the CLI does."""
    global _AUDIT_MODULE
    if _AUDIT_MODULE is None:
        root = Path(__file__).resolve().parent.parent.parent
        spec = importlib.util.spec_from_file_location("audit_for_api",
                                                       root / "tools" / "audit.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _AUDIT_MODULE = mod
    return _AUDIT_MODULE


_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "info": 3, "low": 4}


def _aggregate_actions(eng: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Walk per-connection logs and collect actions_taken into a flat
    list. `audit.load_engagements()` stores logs under `logs[]`, NOT
    `actions_taken` directly on the engagement."""
    out: List[Dict[str, Any]] = []
    for log in eng.get("logs") or []:
        out.extend(log.get("actions_taken") or [])
    # Allow pre-flattened engagements (unit-test convenience)
    out.extend(eng.get("actions_taken") or [])
    return out


def _aggregate_commands(eng: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for log in eng.get("logs") or []:
        out.extend(log.get("commands") or [])
    out.extend(eng.get("commands") or [])
    return out


def _summarize_engagement(eng: Dict[str, Any]) -> EngagementSummary:
    obs = eng.get("observed") or {}
    actions = _aggregate_actions(eng)
    sev_max = "info"
    sev_max_rank = 99
    for a in actions:
        rank = _SEVERITY_RANK.get(a.get("severity", "info"), 99)
        if rank < sev_max_rank:
            sev_max_rank = rank
            sev_max = a.get("severity", "info")
    return EngagementSummary(
        engagement_id=str(eng.get("engagement_id", "?")),
        claimed_user=str(eng.get("claimed_user", "?")),
        source_ip=str(eng.get("source_ip", "?")),
        persona=eng.get("persona"),
        first_seen_at=eng.get("first_seen_at"),
        last_seen_at=eng.get("last_seen_at"),
        dwell_seconds=eng.get("dwell_seconds"),
        connection_count=int(eng.get("connection_count", 1)),
        severity_max=sev_max,
        alert_count=len(actions),
        counter_ai_confidence=obs.get("attacker_llm_confidence"),
        counter_ai_proven=bool(obs.get("attacker_llm_proven_via_trap")),
    )


def _detail_engagement(eng: Dict[str, Any]) -> EngagementDetail:
    obs = eng.get("observed") or {}
    iocs: List[str] = []
    for key in ("dns_exfil_commands", "credential_files_read",
                 "decoy_targets", "tampering_commands"):
        v = obs.get(key) or []
        if isinstance(v, (list, set)):
            iocs.extend(str(x) for x in v)
    # De-dupe preserving order
    iocs = list(dict.fromkeys(iocs))
    return EngagementDetail(
        engagement_id=str(eng.get("engagement_id", "?")),
        claimed_user=str(eng.get("claimed_user", "?")),
        source_ip=str(eng.get("source_ip", "?")),
        persona=eng.get("persona"),
        first_seen_at=eng.get("first_seen_at"),
        last_seen_at=eng.get("last_seen_at"),
        dwell_seconds=eng.get("dwell_seconds"),
        connection_count=int(eng.get("connection_count", 1)),
        cwd=eng.get("cwd"),
        observed=obs,
        actions_taken=_aggregate_actions(eng),
        commands=_aggregate_commands(eng),
        iocs_extracted=iocs,
    )


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def build_app(
    cfg: Optional[Dict[str, Any]] = None,
    *,
    state_dir: Optional[Path] = None,
    logs_dir: Optional[Path] = None,
    personas_dir: Optional[Path] = None,
    auth: Optional[APIAuth] = None,
) -> FastAPI:
    """Construct the Plenith API FastAPI app.

    `cfg` is the parsed config.yaml. The other args are paths the
    handlers read state from. They default to the standard layout under
    the project root.
    """
    cfg = cfg or {}
    root = Path(__file__).resolve().parent.parent.parent
    state_dir    = state_dir    or (root / "state-docker" / "persistence")
    logs_dir     = logs_dir     or (root / "state-docker" / "logs")
    personas_dir = personas_dir or (root / "personas")

    auth_checker = auth or APIAuth.from_config(cfg)
    auth_dep = make_dependency(auth_checker)
    counters = RequestCounters()

    app = FastAPI(
        title="Plenith API",
        version=_VERSION,
        description=(
            "Inbound REST API for the Plenith deception platform. "
            "Auth via Bearer token (set PLENITH_API_TOKENS or "
            "config.api.tokens). Schema at /openapi.json, docs at /docs."
        ),
        openapi_url="/openapi.json",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # --- Middleware ----------------------------------------------------

    @app.middleware("http")
    async def _count_requests(request: Request, call_next):
        try:
            resp = await call_next(request)
            counters.hit(resp.status_code)
            return resp
        except Exception:
            counters.hit(500)
            raise

    # --- State helpers (defined inline so they close over the dirs) ----

    def _load_all_engagements() -> List[Dict[str, Any]]:
        """Walk every per-host logs subdir, aggregate engagements,
        dedupe by engagement_id (the same session can appear in
        multiple host subdirs when the attacker laterals between
        agents). When duplicates exist, merge their `logs[]` lists so
        we see actions from every host the attacker touched."""
        audit = _audit()
        if not logs_dir.exists():
            return []
        subdirs = [d for d in logs_dir.iterdir() if d.is_dir()] or [logs_dir]
        by_id: Dict[str, Dict[str, Any]] = {}
        for sub in subdirs:
            try:
                for eng in audit.load_engagements(state_dir, sub, personas_dir):
                    eid = eng.get("engagement_id")
                    if not eid:
                        continue
                    if eid in by_id:
                        # Merge logs (extend, then de-dupe by file id)
                        by_id[eid]["logs"] = (
                            (by_id[eid].get("logs") or []) + (eng.get("logs") or [])
                        )
                        # Keep newest last_seen_at
                        by_id[eid]["last_seen_at"] = max(
                            by_id[eid].get("last_seen_at") or 0,
                            eng.get("last_seen_at") or 0,
                        )
                    else:
                        by_id[eid] = eng
            except Exception:
                continue
        out = list(by_id.values())
        out.sort(key=lambda e: e.get("last_seen_at", 0) or 0, reverse=True)
        return out

    def _content_rotator():
        from ..rotation import ContentRotator
        return ContentRotator.from_config(cfg)

    # ====================================================================
    # Health / status — unauthenticated by design
    # ====================================================================

    @app.get("/health", response_model=HealthResponse, tags=["status"])
    async def health() -> HealthResponse:
        return HealthResponse(status="ok")

    @app.get("/ready", response_model=ReadyResponse, tags=["status"])
    async def ready() -> ReadyResponse:
        components = {
            "state_dir":    "ok" if state_dir.exists() else "missing",
            "logs_dir":     "ok" if logs_dir.exists() else "missing",
            "personas_dir": "ok" if personas_dir.exists() else "missing",
        }
        overall = "ready" if all(v == "ok" for v in components.values()) else "degraded"
        return ReadyResponse(status=overall, components=components)

    @app.get("/version", response_model=VersionResponse, tags=["status"])
    async def version() -> VersionResponse:
        rot = _content_rotator()
        policy_engine = (cfg.get("policy") or {}).get("engine", "heuristic")
        return VersionResponse(
            version=_VERSION,
            api_version=_API_VERSION,
            deployment_id=rot.seed.deployment_id if rot.is_enabled else None,
            content_epoch=rot.seed.epoch if rot.is_enabled else None,
            corp_name=rot.corp.corp_name if rot.is_enabled else None,
            policy_engine=policy_engine,
        )

    @app.get("/metrics", tags=["status"], response_class=PlainTextResponse)
    async def metrics():
        engagements = _load_all_engagements()
        sev_by: Dict[str, int] = {}
        action_by: Dict[str, int] = {}
        cai = 0
        cai_proven = 0
        for e in engagements:
            for a in _aggregate_actions(e):
                sev_by[a.get("severity", "info")] = sev_by.get(a.get("severity", "info"), 0) + 1
                action_by[a.get("action", "?")] = action_by.get(a.get("action", "?"), 0) + 1
            obs = e.get("observed") or {}
            if obs.get("attacker_likely_llm"):
                cai += 1
            if obs.get("attacker_llm_proven_via_trap"):
                cai_proven += 1
        snap = {
            "engagement_count":           len(engagements),
            "alerts_total_by_severity":   sev_by,
            "alerts_total_by_action":     action_by,
            "counter_ai_detections":      cai,
            "counter_ai_proven_via_trap": cai_proven,
            **counters.snapshot(),
        }
        return PlainTextResponse(render_metrics(snap), media_type="text/plain; version=0.0.4")

    # ====================================================================
    # Engagements
    # ====================================================================

    @app.get("/engagements", response_model=EngagementListResponse, tags=["engagements"])
    async def list_engagements(
        _=Depends(auth_dep),
        user:     Optional[str] = Query(None, description="Filter by claimed_user"),
        ip:       Optional[str] = Query(None, description="Filter by source_ip"),
        severity: Optional[str] = Query(None,
            description="Only return engagements whose severity_max is at LEAST this level"),
        since_seconds: Optional[float] = Query(None,
            description="Only include engagements seen in the last N seconds"),
        limit:    int = Query(100, ge=1, le=1000),
    ):
        engagements = _load_all_engagements()
        filtered = []
        # `since_seconds=0` is a valid "last 0 seconds" filter (= nothing
        # matches), so use `is not None` rather than truthiness.
        cutoff = (time.time() - since_seconds) if since_seconds is not None else None
        for e in engagements:
            if user and e.get("claimed_user") != user:
                continue
            if ip and e.get("source_ip") != ip:
                continue
            if cutoff is not None and (e.get("last_seen_at", 0) or 0) < cutoff:
                continue
            summary = _summarize_engagement(e)
            if severity:
                want = _SEVERITY_RANK.get(severity, 99)
                got  = _SEVERITY_RANK.get(summary.severity_max, 99)
                if got > want:
                    continue
            filtered.append(summary)
        return EngagementListResponse(
            engagements=filtered[:limit],
            total=len(filtered),
        )

    @app.get("/engagements/{engagement_id}", response_model=EngagementDetail,
              tags=["engagements"],
              responses={404: {"model": APIError}})
    async def get_engagement(engagement_id: str, _=Depends(auth_dep)):
        engagements = _load_all_engagements()
        match = [e for e in engagements
                 if e.get("engagement_id", "").startswith(engagement_id)]
        if not match:
            raise HTTPException(status_code=404, detail=f"no engagement '{engagement_id}'")
        if len(match) > 1:
            raise HTTPException(status_code=409,
                                 detail=f"ambiguous prefix '{engagement_id}': "
                                        f"{len(match)} matches")
        return _detail_engagement(match[0])

    @app.get("/engagements/{engagement_id}/narrative",
              response_model=NarrativeResponse, tags=["engagements"],
              responses={404: {"model": APIError}, 503: {"model": APIError}})
    async def get_narrative(engagement_id: str, _=Depends(auth_dep)):
        engagements = _load_all_engagements()
        match = [e for e in engagements
                 if e.get("engagement_id", "").startswith(engagement_id)]
        if not match:
            raise HTTPException(status_code=404,
                                 detail=f"no engagement '{engagement_id}'")
        from ..llm_client import LMStudioClient
        from ..narrate import input_from_engagement, narrate
        llm_cfg = cfg.get("llm") or {}
        if not llm_cfg.get("base_url"):
            raise HTTPException(status_code=503,
                                 detail="LLM endpoint not configured")
        try:
            llm = LMStudioClient(
                base_url=llm_cfg.get("base_url", "http://localhost:1234/v1"),
                model=llm_cfg.get("model", "qwen2.5-7b-instruct-1m"),
                api_key=llm_cfg.get("api_key", "lm-studio"),
                temperature=float(llm_cfg.get("temperature", 0.3)),
                max_tokens=int(llm_cfg.get("max_tokens", 800)),
                timeout_seconds=float(llm_cfg.get("timeout_seconds", 60)),
            )
            inp = input_from_engagement(match[0])
            text = await narrate(inp, llm)
            return NarrativeResponse(
                engagement_id=match[0]["engagement_id"],
                narrative=text.strip(),
                generated_at=datetime.now(timezone.utc),
            )
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=503,
                                 detail=f"LLM call failed: {type(e).__name__}: {e}")

    # ====================================================================
    # Alerts
    # ====================================================================

    @app.get("/alerts", response_model=AlertListResponse, tags=["alerts"])
    async def list_alerts(
        _=Depends(auth_dep),
        severity: Optional[str] = Query(None,
            description="Only return alerts at LEAST this severity"),
        action:   Optional[str] = Query(None,
            description="Filter by exact action name"),
        engagement_id: Optional[str] = Query(None,
            description="Only alerts from engagements starting with this id prefix"),
        limit: int = Query(200, ge=1, le=5000),
    ):
        engagements = _load_all_engagements()
        out: List[AlertSummary] = []
        for e in engagements:
            if engagement_id and not e.get("engagement_id", "").startswith(engagement_id):
                continue
            for a in _aggregate_actions(e):
                if action and a.get("action") != action:
                    continue
                if severity:
                    want = _SEVERITY_RANK.get(severity, 99)
                    got  = _SEVERITY_RANK.get(a.get("severity", "info"), 99)
                    if got > want:
                        continue
                out.append(AlertSummary(
                    action=a.get("action", "?"),
                    severity=a.get("severity", "info"),
                    rationale=a.get("rationale"),
                    ts_offset_s=a.get("ts_offset_s"),
                    triggered_by=a.get("triggered_by"),
                    mitre_technique=a.get("mitre_technique"),
                    mitre_tactic=a.get("mitre_tactic"),
                ))
        return AlertListResponse(alerts=out[:limit], total=len(out))

    # ====================================================================
    # Isolation
    # ====================================================================

    @app.post("/isolation/validate", response_model=IsolationProbeResult,
                tags=["actions"], responses={503: {"model": APIError}})
    async def validate_isolation(_=Depends(auth_dep)):
        validate_script = root / "linux-fork" / "isolation" / "validate.sh"
        if not validate_script.exists():
            raise HTTPException(status_code=503,
                                 detail="isolation/validate.sh not found")
        bash = shutil.which("bash") or r"C:\Program Files\Git\bin\bash.exe"
        if not Path(bash).exists():
            raise HTTPException(status_code=503,
                                 detail="bash not available")
        # Run synchronously off-thread so we don't block the event loop
        proc = await asyncio.to_thread(
            subprocess.run,
            [bash, str(validate_script)],
            capture_output=True, text=True, timeout=120,
        )
        out = proc.stdout or proc.stderr
        # Strip ANSI for clean response
        clean = re.sub(r"\x1b\[[0-9;]*m", "", out)
        # Count PASS / FAIL lines
        pass_n = clean.count(" PASS ") + clean.count("PASS  ")
        fail_n = clean.count(" FAIL ") + clean.count("FAIL  ")
        total = pass_n + fail_n
        return IsolationProbeResult(
            pass_count=pass_n,
            fail_count=fail_n,
            total=total,
            output=clean,
            succeeded=(proc.returncode == 0),
        )

    # ====================================================================
    # MFA
    # ====================================================================

    @app.post("/mfa/decisions/{ip}", response_model=MFADecisionResponse,
                tags=["actions"])
    async def write_mfa_decision(ip: str, body: MFADecisionInjection,
                                   _=Depends(auth_dep)):
        if body.decision not in ("pass", "fail"):
            raise HTTPException(status_code=400,
                                 detail="decision must be 'pass' or 'fail'")
        mfa_dir = root / "state-docker" / "mfa"
        mfa_dir.mkdir(parents=True, exist_ok=True)
        # Wipe stale decisions for this IP first (latest-wins semantics)
        for stale in mfa_dir.glob(f"{ip}.*"):
            try:
                stale.unlink()
            except OSError:
                pass
        decision_path = mfa_dir / f"{ip}.{body.decision}"
        decision_path.write_text(
            f"ip={ip}\ndecision={body.decision}\nts={int(time.time())}\n"
            + (f"reason={body.reason}\n" if body.reason else ""),
            encoding="utf-8",
        )
        return MFADecisionResponse(
            ip=ip, decision=body.decision, written=True, path=str(decision_path),
        )

    # ====================================================================
    # Policy / content
    # ====================================================================

    @app.get("/policy", response_model=PolicyInfo, tags=["status"])
    async def policy_info(_=Depends(auth_dep)):
        pol_cfg = cfg.get("policy") or {}
        from ..policy import ACTION_SPACE, OBSERVATION_FEATURES
        return PolicyInfo(
            engine=pol_cfg.get("engine", "heuristic"),
            model_path=pol_cfg.get("model_path"),
            n_actions=len(ACTION_SPACE),
            obs_features=len(OBSERVATION_FEATURES),
        )

    @app.get("/content/manifest", response_model=ContentManifest, tags=["status"])
    async def content_manifest(_=Depends(auth_dep)):
        rot = _content_rotator()
        return ContentManifest(**rot.build_manifest())

    return app
