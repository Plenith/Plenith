"""Operational runbook generators — §13 of the Engineering Blueprint.

Auditors care about CONTROLS, but operators care about RUNBOOKS. The
blueprint's §13 enumerates seven operational sections every production
deployment needs:

  1. Data retention & classification policy
  2. Incident response RACI matrix
  3. Burn-down protocol (when the attacker detects the ruse)
  4. Capacity model (concurrent sessions per server)
  5. Content rotation runbook (quarterly cadence + procedure)
  6. Disaster recovery (RTO/RPO + restoration steps)
  7. Content fingerprint defense (already shipped via content rotation)

This module generates each runbook as a Markdown document, filling in
real values from the running deployment where possible (engagement
counts, last rotation epoch, configured backup policy, etc.). When
data isn't available it falls back to documented defaults / TODO
placeholders.

The runbooks are AUDITOR-READABLE artifacts. Standard practice: drop
them into your evidence binder alongside the compliance attestation.
"""
from __future__ import annotations

import datetime
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Common context — gathered once, shared across runbook templates
# ---------------------------------------------------------------------------

@dataclass
class RunbookContext:
    """Inputs every runbook template can reference. Most fields have
    sensible defaults so missing data doesn't crash the generator."""
    deployment_id:   str = "unknown-deployment"
    corp_name:       str = "Plenith"
    current_epoch:   str = "default"
    backup_location: str = "/mnt/state-backups/"
    rto_minutes:     int = 60
    rpo_minutes:     int = 15
    max_concurrent_sessions: int = 50
    soc_tier1_oncall: str = "soc-tier1@example.invalid"
    soc_tier2_oncall: str = "soc-tier2@example.invalid"
    soc_tier3_oncall: str = "incident-response@example.invalid"
    ciso_oncall:      str = "ciso@example.invalid"
    retention_logs_days:     int = 90
    retention_iocs_days:     int = 365
    retention_engagements_days: int = 365

def _now_iso() -> str:
    return (
        datetime.datetime.now(datetime.UTC)
        .isoformat(timespec="minutes")
        .replace("+00:00", "Z")
    )

# ---------------------------------------------------------------------------
# §13.1 — Data retention & classification
# ---------------------------------------------------------------------------

def retention_runbook(ctx: RunbookContext) -> str:
    return f"""# Data Retention & Classification Runbook

_Generated {_now_iso()} for deployment `{ctx.deployment_id}`._

## Classification levels

Plenith emits and processes three classes of data. Each has its own
retention horizon and access control:

| Class | Examples | Retention | Access |
|---|---|---:|---|
| **Decoy artifacts** (low) | Planted sudoers, my.cnf, AWS-creds, MOTD — pure synthetic | Indefinite | SOC + Ops |
| **Engagement state** (medium) | Per-session command stream, observed dict, alert log | {ctx.retention_engagements_days} days | SOC tier 1+ |
| **Attacker IoCs** (high) | Source IP, exfil URLs, decoy-touched-by-IP tuples, captured payloads | {ctx.retention_iocs_days} days | SOC tier 2+ + Threat Intel |

### Why these horizons

- **Engagement state** at {ctx.retention_engagements_days} days covers the
  standard SOC 2 audit period (90-365 days) plus IR retrospectives.
- **IoCs** at {ctx.retention_iocs_days} days supports year-over-year TTP
  trend analysis. Anonymized IoCs may be exported to ISAC partners under
  the §13.7 sharing policy (see `Content Sharing & Anonymization Runbook`).

## Storage locations

| Class | Path | Backed up? |
|---|---|---|
| Decoy artifacts | content rotation manifests in `state/content/<id>__<epoch>/` | yes — version-controlled |
| Engagement state | `state-docker/persistence/*.json` (or PVC in k8s) | yes — `{ctx.backup_location}` |
| Logs (per-host) | `state-docker/logs/<hostname>/*.json` | yes |
| Audit narratives | rendered on-demand, not persisted by default | no |

## Deletion procedure

Cron-driven (`0 3 * * *`). Walks each storage dir and removes entries
older than the class's retention horizon. Implementation:

```bash
# Engagement state — {ctx.retention_engagements_days} days
find state-docker/persistence -name '*.json' \\
    -mtime +{ctx.retention_engagements_days} -delete

# Per-host logs — {ctx.retention_logs_days} days
find state-docker/logs -name '*.json' \\
    -mtime +{ctx.retention_logs_days} -delete

# IoC exports — {ctx.retention_iocs_days} days
find state-docker/logs/ot_iocs.jsonl -mtime +{ctx.retention_iocs_days} -delete
```

## Exceptions

- A legal hold pauses all deletion for the engagement(s) named in the
  hold notice. Coordinate with Legal via the IR RACI escalation path.
- A confirmed incident extends engagement-state retention to
  {ctx.retention_iocs_days} days (same as IoCs) for the duration of the
  IR cycle.
"""

# ---------------------------------------------------------------------------
# §13.2 — Incident response RACI matrix
# ---------------------------------------------------------------------------

def ir_raci_runbook(ctx: RunbookContext) -> str:
    return f"""# Incident Response RACI

_Generated {_now_iso()} for deployment `{ctx.deployment_id}`._

The Plenith-driven incident lifecycle has six phases. Each cell of
the table below assigns one of:
  - **R** Responsible (does the work)
  - **A** Accountable (final sign-off)
  - **C** Consulted
  - **I** Informed

## Phase → role matrix

| Phase | SOC Tier 1 | SOC Tier 2 | IR (Tier 3) | Identity Team | CISO | Legal |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **1. Alert triage** (any severity) | R/A | C | I | I | I | – |
| **2. Containment** (high+) | R | A | C | C (if creds touched) | I | – |
| **3. Investigation** (high+) | I | R/A | C | C | I | – |
| **4. Eradication** (high+) | – | R | A | R (if creds touched) | C | – |
| **5. Recovery** (high+) | I | R | A | C | I | – |
| **6. Lessons learned** | C | C | R/A | I | I (sign-off) | C |

## Escalation paths

| Severity | Page | Within | Next-hop |
|---|---|---|---|
| critical | `{ctx.ciso_oncall}` immediately | 5 min | – |
| high | `{ctx.soc_tier2_oncall}` page; `{ctx.soc_tier3_oncall}` on no-ack | 15 min | escalate to CISO |
| medium | `{ctx.soc_tier1_oncall}` notification | 1 hour | escalate to Tier 2 if no triage in 4h |
| info | dashboard only — no page | – | weekly digest |

## After-hours coverage

The on-call rotation MUST cover 24×7×365 for SOC Tier 1 (acknowledge
within 15 minutes of any critical/high alert). Tier 2 and IR Tier 3
follow the standard on-call schedule.

## SLA targets

| Metric | Target |
|---|---:|
| Critical alert → SOC acknowledgement | ≤ 15 min |
| High alert → SOC acknowledgement | ≤ 1 hour |
| Containment decision (high+) | ≤ 30 min after triage |
| Eradication start (confirmed compromise) | ≤ 2 hours |
| Lessons-learned retro published | ≤ 5 business days |
"""

# ---------------------------------------------------------------------------
# §13.3 — Burn-down protocol (attacker detects the ruse)
# ---------------------------------------------------------------------------

def burndown_runbook(ctx: RunbookContext) -> str:
    return f"""# Burn-Down Protocol

_Generated {_now_iso()} for deployment `{ctx.deployment_id}`._

## When the attacker detects Plenith

Signals that the attacker has realized they're in a honeypot:
- Sudden disconnect after suspicious-looking command (`cat /etc/honeypot`,
  `grep -ri honey /`).
- Burst of decoy-detection probes (looking for static markers, file
  timestamps that don't match real systems).
- Aggressive sandbox-evasion sequences (CPUID, RDTSC timing checks via
  process invocation).
- Commands referencing public honeypot project names (`cowrie`,
  `kippo`, `plenith`).

When Plenith detects these via the standard heuristics, it logs
`alert_decoy_recognized` (planned — see §13 backlog). Until that ships,
the indicator is a counter-AI-detected attacker who suddenly stops
issuing commands within 30 seconds of `cat /etc/passwd | head`.

## Standing posture

**Default: do nothing.** When the attacker stops engaging, the right
move is to:
  1. KEEP the session alive (don't close it; let them choose).
  2. LOG every byte until disconnect.
  3. PRESERVE container state for forensics.
  4. NOT respond with anything that confirms detection (no "you're in
     a honeypot" message; no behavior change).

Reasoning: a confirmed-detected adversary is more dangerous in the wild
than one who still thinks the honeypot is real prod. Don't burn the
deployment.

## Kill-switch

There IS a pre-set kill switch for the case where:
- Containment of the SESSION is paramount (e.g. active C2).
- OR the attacker is actively attempting to escape the bubble.

The kill switch is invoked via:

```bash
# Per-session: kill ONE session by source IP
docker exec plenith-proxy nginx -s reload  # not direct — see runbook below

# Per-deployment: pause ingress entirely
helm upgrade {ctx.deployment_id} plenith/ \\
    --set proxy.service.type=ClusterIP   # removes nodePort externally
```

## Communications discipline

If the attacker DETECTED us, treat the deployment as **burned**:
  - Rotate `PLENITH_DEPLOYMENT_ID` (new corp identity)
  - Bump `PLENITH_CONTENT_EPOCH` (new artifacts)
  - DO NOT publish the engagement state to public TI feeds — it could
    be used to refine attacker detection of Plenith deployments.

## Lessons-learned channel

After every burn-down, schedule a retro within 5 business days. Inputs:
  - Full session command stream
  - Counter-AI signal history (if applicable)
  - List of decoy artifacts the attacker DID touch (good IoCs)
  - List of detection signals the attacker exhibited

Outputs go into the §13.1 retention long-tail (IoCs) and feed back into
the heuristic / RL policy update cadence.
"""

# ---------------------------------------------------------------------------
# §13.4 — Capacity model
# ---------------------------------------------------------------------------

def capacity_runbook(ctx: RunbookContext) -> str:
    return f"""# Capacity Model

_Generated {_now_iso()} for deployment `{ctx.deployment_id}`._

## Resource budget per agent pod

These figures assume a Helm-deployed cluster with default
`resources.agent` limits (500m CPU, 512Mi memory). Empirical numbers
come from `tools/bench.py` runs against a representative LLM endpoint.

| Workload | CPU per session | Memory per session | Notes |
|---|---:|---:|---|
| Idle SSH (banner + prompt) | ~5m | ~6 MiB | asyncio fits dozens easily |
| Active recon (cache-hit only) | ~15m | ~12 MiB | builtin handlers (`ls`, `cat`) |
| LLM-bound command | ~10m (mostly waiting) | ~12 MiB | wall-clock dominated by LLM |
| Crown-jewel chain | ~30m | ~25 MiB | counter-AI + traps + rotation |

## Concurrent session targets

| Scale | Recommended per-agent limit | Cluster footprint |
|---|---:|---|
| Dev (1 host) | 5 concurrent | ~2.5 GiB total |
| Pilot (3 hosts) | 15 concurrent | ~7 GiB total |
| Production (≥3 hosts) | {ctx.max_concurrent_sessions} concurrent | ~25 GiB total |

## Saturation behavior

At session-count > capacity, the orchestrator continues to accept new
SSH connections but LLM-bound commands queue. Symptoms:
  - p99 command latency rises from ~2s to ~10s+
  - LLM endpoint shows queue depth alert
  - Heuristic alerts still fire on time (independent of LLM)

**This degrades gracefully**: even at 3× rated load, the session-level
deception still works — attackers see slower responses but no errors.

## Scaling levers

| Lever | When to use | Effect |
|---|---|---|
| Add agent replicas | session count > 80% capacity | linear capacity |
| Add LLM endpoint replicas | LLM queue depth > 10 | linear LLM throughput |
| Enlarge LLM cache | repeated commands across sessions | -50% LLM calls |
| Increase episode_cap | longer engagements wanted | per-session cost up |

## Monitoring

| Metric | Source | Alert on |
|---|---|---|
| concurrent sessions | dashboard `/api/state.json` | > {int(ctx.max_concurrent_sessions * 0.8)} |
| p99 command latency | bench JSON / dashboard | > 5s sustained |
| LLM endpoint queue depth | Ollama / vLLM metrics | > 10 |
| Agent pod memory | k8s metrics | > 80% of limit |

## Capacity test cadence

Run `python tools/bench.py --sessions 50 --commands 30` quarterly. Save
the JSON to `state/bench/`. Audit against this runbook to confirm the
numbers haven't drifted (e.g. an LLM swap that doubled per-call latency).
"""

# ---------------------------------------------------------------------------
# §13.5 — Content rotation runbook
# ---------------------------------------------------------------------------

def rotation_runbook(ctx: RunbookContext) -> str:
    return f"""# Content Rotation Runbook

_Generated {_now_iso()} for deployment `{ctx.deployment_id}` (current epoch: `{ctx.current_epoch}`)._

## Why rotate

Static decoy artifacts (sudoers contents, mysql passwords, hostname
patterns) become signatures that attackers and red-team aggregators
can fingerprint. Quarterly rotation defeats this — every artifact is
regenerated from `(deployment_id, epoch)`. See §8 of the Engineering
Blueprint and `plenith/rotation/`.

## Cadence

- **Quarterly** (default) — first business day of each quarter
- **Ad-hoc** — within 7 days if a previous epoch's artifact leaks into
  public IoC feeds (treat as compromise of the marker)

## Procedure

### Step 1 — Generate the new epoch

```bash
# Pick the new epoch label
NEW_EPOCH=2026Q3

# Materialize artifacts + manifest under state/content/
python tools/rotate_content.py \\
    --deployment-id {ctx.deployment_id} \\
    --epoch $NEW_EPOCH \\
    --out state/content/$NEW_EPOCH
```

### Step 2 — Diff against prior epoch

```bash
python tools/rotate_content.py \\
    --deployment-id {ctx.deployment_id} \\
    --epoch $NEW_EPOCH \\
    --diff state/content/{ctx.current_epoch}
```

Expected: **6/6 artifacts changed.** If fewer, the seed-derivation
function may be broken — investigate before deploying.

### Step 3 — Roll out

#### Helm path (production)
```bash
helm upgrade {ctx.deployment_id} plenith/ \\
    --set global.contentEpoch=$NEW_EPOCH \\
    --reuse-values
```
Rolling restart of every agent pod picks up the new epoch from the
mounted config. Existing SSH sessions keep their OLD epoch's planted
content; new sessions see the new epoch.

#### docker-compose path (dev)
```bash
# Update .env
sed -i "s/PLENITH_CONTENT_EPOCH=.*/PLENITH_CONTENT_EPOCH=$NEW_EPOCH/" linux-fork/.env
docker compose -f linux-fork/docker-compose.yml up -d --force-recreate
```

### Step 4 — Verify

```bash
# Confirm every agent advertises the new epoch
docker logs bastion-prod 2>&1 | grep "Content rotation"
docker logs db-prod-01  2>&1 | grep "Content rotation"
docker logs api-prod-03 2>&1 | grep "Content rotation"

# Drive a probe session, confirm planted sudoers references NEW corp
python tools/demo_attack.py
grep -q "$(python -c 'from plenith.rotation import *;
import sys; sys.path.insert(0, ".");
r = ContentRotator.from_seed(DeploymentSeed("{ctx.deployment_id}", "'$NEW_EPOCH'"));
print(r.corp.corp_domain)')" state/demo_attack_transcript.txt
```

### Step 5 — Document

- Append the new epoch to the compliance attestation history.
- Mention the rotation in the next quarterly SOC report.
- Anonymized IoCs from the PRIOR epoch may now be safely shared
  (the markers are burned anyway).

## Rollback

If anything fails:
```bash
helm rollback {ctx.deployment_id} 1
```
Or revert `.env`'s `PLENITH_CONTENT_EPOCH` and re-run compose.
"""

# ---------------------------------------------------------------------------
# §13.6 — Disaster recovery
# ---------------------------------------------------------------------------

def dr_runbook(ctx: RunbookContext) -> str:
    return f"""# Disaster Recovery Runbook

_Generated {_now_iso()} for deployment `{ctx.deployment_id}`._

## Targets

| Metric | Target |
|---|---:|
| RTO (recovery time objective) | {ctx.rto_minutes} minutes |
| RPO (recovery point objective) | {ctx.rpo_minutes} minutes |

## What's stateful

| Component | State | Backup | Recovery |
|---|---|---|---|
| Agent pods (orchestrator) | stateless | n/a — recreate from image | k8s self-heals; ~30s |
| Identity proxy | stateless | n/a | k8s self-heals; ~30s |
| MFA gateway | mostly stateless | enrollment.json + active decisions in shared PVC | recreate; reads PVC |
| CoreDNS | stateless (Corefile in ConfigMap) | n/a | k8s self-heals |
| **Shared state PVC** | **YES — engagements, MFA decisions, enrollment, rotation manifests** | **snapshots every {ctx.rpo_minutes}m → `{ctx.backup_location}`** | **restore from snapshot, ≤ {ctx.rto_minutes - 10}m to mount** |
| push-sim | in-memory only | not backed up | recreates empty on restart |

## Backup procedure

Cron (every {ctx.rpo_minutes} minutes) on the cluster's backup orchestrator:

```bash
# Snapshot the shared PVC's filesystem
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
kubectl exec plenith-backup-pod -- \\
    tar czf - /mnt/state \\
    > {ctx.backup_location}/state-$TIMESTAMP.tgz

# Trim old snapshots — keep last 96 (24h at 15m intervals)
ls -t {ctx.backup_location}/state-*.tgz | tail -n +97 | xargs -r rm
```

## Recovery procedure

### Scenario A — Single agent pod crash
**RTO:** ~30 seconds. No action required. k8s Deployment self-heals.

### Scenario B — Shared PVC corruption / accidental delete
**RTO:** ~{ctx.rto_minutes - 10} minutes.

1. Scale agent + MFA gateway Deployments to 0 replicas:
   ```bash
   kubectl scale deployment -l plenith-role=agent --replicas=0
   kubectl scale deployment mfa-gateway --replicas=0
   ```
2. Find latest backup:
   ```bash
   LATEST=$(ls -t {ctx.backup_location}/state-*.tgz | head -1)
   ```
3. Restore into a fresh PVC:
   ```bash
   kubectl exec plenith-restore-pod -- \\
       tar xzf - -C /mnt/state < $LATEST
   ```
4. Scale Deployments back up:
   ```bash
   kubectl scale deployment -l plenith-role=agent --replicas=1
   kubectl scale deployment mfa-gateway --replicas=1
   ```
5. Validate isolation: `bash linux-fork/isolation/validate.sh` — expect 18/18.

### Scenario C — Whole cluster loss
**RTO:** ~{ctx.rto_minutes} minutes.

1. Provision new cluster (Terraform / cluster-as-a-service).
2. Restore PVC backup as in Scenario B.
3. `helm install {ctx.deployment_id} plenith/ --set global.deploymentId={ctx.deployment_id} --set global.contentEpoch={ctx.current_epoch}`.
4. Wait for `helm status` to show all Deployments ready.
5. Run validation suite + a sentinel attack via `tools/demo_attack.py`.
6. Resume normal ops; the deployment_id + epoch stay the same so
   honeytokens remain consistent with what attackers may already have
   harvested.

## DR test cadence

| Test | Cadence | Owner |
|---|---|---|
| Scenario A (pod kill) | weekly | SRE |
| Scenario B (PVC restore) | monthly | SRE + SOC |
| Scenario C (full rebuild) | quarterly | SRE + SOC + IR |

Document each test result in the runbook log (`state/dr-test-log.jsonl`)
with the timestamp, scenario, measured RTO, and any deviations.
"""

# ---------------------------------------------------------------------------
# Public API — build context, render all runbooks
# ---------------------------------------------------------------------------

def build_context_from_config(cfg: dict[str, Any] | None) -> RunbookContext:
    """Build a context object by pulling defaults from the config tree."""
    ctx = RunbookContext()
    if not cfg:
        return ctx
    content = cfg.get("content") or {}
    if content.get("deployment_id"):
        ctx.deployment_id = content["deployment_id"]
    if content.get("epoch"):
        ctx.current_epoch = content["epoch"]
    # Allow env-var override (common for deployment_id)
    dep_env = (content.get("env_var")
                and os.environ.get(content["env_var"]))
    if dep_env:
        ctx.deployment_id = dep_env

    ops = cfg.get("operations") or {}
    if ops.get("rto_minutes"):
        ctx.rto_minutes = int(ops["rto_minutes"])
    if ops.get("rpo_minutes"):
        ctx.rpo_minutes = int(ops["rpo_minutes"])
    if ops.get("backup_location"):
        ctx.backup_location = ops["backup_location"]
    if ops.get("max_concurrent_sessions"):
        ctx.max_concurrent_sessions = int(ops["max_concurrent_sessions"])
    if ops.get("oncall"):
        oc = ops["oncall"]
        ctx.soc_tier1_oncall = oc.get("soc_tier1", ctx.soc_tier1_oncall)
        ctx.soc_tier2_oncall = oc.get("soc_tier2", ctx.soc_tier2_oncall)
        ctx.soc_tier3_oncall = oc.get("soc_tier3", ctx.soc_tier3_oncall)
        ctx.ciso_oncall      = oc.get("ciso",      ctx.ciso_oncall)
    if ops.get("retention"):
        r = ops["retention"]
        ctx.retention_logs_days        = int(r.get("logs_days", ctx.retention_logs_days))
        ctx.retention_iocs_days        = int(r.get("iocs_days", ctx.retention_iocs_days))
        ctx.retention_engagements_days = int(r.get("engagements_days",
                                                    ctx.retention_engagements_days))
    return ctx

def render_all(ctx: RunbookContext) -> dict[str, str]:
    """Render every runbook. Returns {filename: markdown_body}."""
    return {
        "01-data-retention.md":  retention_runbook(ctx),
        "02-ir-raci.md":         ir_raci_runbook(ctx),
        "03-burndown.md":        burndown_runbook(ctx),
        "04-capacity.md":        capacity_runbook(ctx),
        "05-content-rotation.md": rotation_runbook(ctx),
        "06-disaster-recovery.md": dr_runbook(ctx),
    }
