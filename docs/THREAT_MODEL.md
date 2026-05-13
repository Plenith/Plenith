# Plenith — Threat Model

**Version:** 1.0
**Last updated:** 2026-05-12
**Audience:** procurement teams, auditors, IR teams, anyone evaluating Plenith for deployment.

This document is a STRIDE-driven walk-through of Plenith's trust boundaries, the threats that cross those boundaries, and the mitigations in place. It is **not** a vulnerability disclosure (see [`SECURITY.md`](../SECURITY.md) for that) and **not** legal advice — review with counsel before deploy.

The deception platform is built to BE attacked. The threat model below distinguishes between attacks that should fail by design (an attacker escaping the bubble) and attacks that should succeed by design (an attacker reading planted decoys — that's the point).

---

## TL;DR for procurement

| Property | Status | Evidence |
|---|---|---|
| Network egress from decoys to internet | **Denied** | `linux-fork/isolation/validate.sh`, 18-probe CI gate, k8s NetworkPolicy |
| Privilege escalation from decoy to host | **Mitigated** | `cap_drop: [ALL]`, `no-new-privileges:true`, optional gVisor runtime |
| Lateral movement from decoy to real prod | **Prevented** | bubble is `internal: true`; only audited bridges egress |
| Honeypot recognition by attackers | **Mitigated** | Content rotation per deployment_id × epoch (§8 risk row) |
| API token compromise | **Detected within audit window** | Tokens hashed, rotated via config, `PLENITH_API_TOKENS` env-var rotation |
| Counter-AI: attacker uses LLM-driven tooling | **Detected & trapped** | `plenith/counter_ai.py` |
| Decoy fingerprint sharing in public IoC feeds | **Defeated quarterly** | Epoch bump regenerates everything; see `plenith/rotation/` |
| SOC 2 / ISO 27001 / NIS2 control attestation | **Available** | `python tools/compliance_report.py --framework all` |
| SBOM (CycloneDX) | **Generated on demand** | `python tools/sbom.py` |
| Audit-grade DR plan | **Documented + tested** | `plenith/compliance/runbooks.py` § DR; CI runs scenario A weekly |

---

## Trust boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│                       OPERATOR / SOC                            │  ← Trust zone 1
│                                                                 │     (full read/write)
│   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌──────────────┐    │
│   │  CLI    │   │ Grafana │   │ Dashboard│  │  REST API SDK │    │
│   └────┬────┘   └────┬────┘   └────┬────┘   └────┬─────────┘    │
└────────┼─────────────┼─────────────┼─────────────┼───────────────┘
         │             │             │             │
         ▼             ▼             ▼             ▼
   ┌──────────────────────────────────────────────────────┐
   │            Plenith REST API (Bearer auth)         │  ← Trust zone 2
   │                                                      │     (read state, trigger
   │   /engagements   /metrics   /isolation/validate      │      validated actions)
   │   /alerts        /policy    /mfa/decisions/{ip}      │
   └────┬──────────────────────────────────────┬──────────┘
        │                                      │
        ▼                                      ▼
┌───────────────────────────────┐  ┌──────────────────────────────┐
│  Orchestrator + heuristics    │  │  Connectors (outbound)       │  ← Trust zone 3
│  + rotation + policy engine   │  │  Splunk / Elastic / SOAR     │     (internal services
│                               │  │  Slack / Teams / TAXII / ... │      with their own
│                               │  │                              │      auth tokens)
└──────────────┬────────────────┘  └──────────────────────────────┘
               │
               ▼
   ┌──────────────────────────────────────────────────────┐
   │  Identity proxy (Lua risk scoring + PROXY-v1)        │
   │  listens on :22 — public attack surface              │  ← Trust zone 4 (public)
   └────┬───────────────────────┬─────────────┬───────────┘
        │                       │             │
   real-prod              MFA gateway   plenith agents
   (NOT trusted to       (TOTP / push   (decoy bubble — runs
    talk to bubble        verifier)      ATTACKER-CONTROLLED
    or vice-versa)                       commands inside)
                                        ▲
                                        │
                              ┌─────────┴───────────┐
                              │   ATTACKER (UNTRUSTED) │  ← Trust zone 5 (hostile)
                              └────────────────────────┘
```

**Critical invariant:** trust zones cross only through audited bridges. Specifically, the decoy bubble (zone 4 lower-half) MUST NOT be able to initiate connections into the orchestrator (zone 3) or out to the internet. Bidirectional connections are PROXY-protocol-prefixed by the identity proxy on the way in, and the only outbound from the bubble is the audited LLM bridge (`llm-egress` nginx with URI allow-list).

---

## STRIDE per component

### Identity proxy (`linux-fork/routing/`)

| STRIDE | Threat | Mitigation | Residual risk |
|---|---|---|---|
| **S**poofing | Attacker spoofs PROXY-v1 header to claim a privileged source IP | Proxy SETS the header from `$remote_addr` (uncontrolled by attacker) before forwarding to backends. Backends accept PROXY-v1 only on the dedicated `:2200` port, not on `:22` (the lateral-only port). | **None.** |
| **T**ampering | Attacker tampers with risk-scoring inputs | All scoring inputs come from shared dicts populated by trusted sources (geo / reputation / Tor / fail-count) which the attacker cannot write to. | **None.** |
| **R**epudiation | Attacker denies a session happened | Every routing decision logged to `[notice] [plenith] route ip=... pool=...` in nginx error log, ingested by SIEM. | **None.** |
| **I**nformation disclosure | Proxy log leaks the scoring formula | Scoring weights are visible in `score_and_route.lua` (public — repo is open-source). Source IP / time / decision can be reconstructed from a leaked log — accept this. | **Low** — operators MUST treat proxy logs as confidential. |
| **D**oS | Attacker floods :22 with handshakes | Per-IP rate limiting via `plenith_rates` shared dict + LB-side connection cap. | **Medium** — sufficient flood overwhelms; deploy CDN/WAF in front. |
| **E**oP | Lua script error escalates to RCE on proxy host | Lua runs in OpenResty's sandbox; no `os.execute`; chroot via gVisor in k8s. | **None** in default deploy. |

### MFA gateway (`linux-fork/mfa/`)

| STRIDE | Threat | Mitigation | Residual risk |
|---|---|---|---|
| **S**poofing | Attacker presents a stolen TOTP secret to bypass MFA | Per-user enrollment in JSON store; deployment-scoped derivation salt prevents cross-deployment reuse. | **Mitigated.** Detection: TOTP verifier checks ±30s window only. |
| **T**ampering | Attacker tampers with the decision file (`.pass`/`.fail`) | Decision files only writable by the gateway pod (file system perms + k8s NetworkPolicy + read-only mount for the proxy). | **None** in default deploy. |
| **R**epudiation | User denies the MFA approval | Every decision file includes a timestamp + reason; logs flow into SIEM. | **None.** |
| **I**nformation disclosure | Attacker reads other users' TOTP secrets | Enrollment file mode-0600; mounted only into mfa-gateway pod; SOC tier 3 access only. | **Low.** |
| **D**oS | Attacker fires endless MFA challenges to deny legit users | Push provider's rate-limits absorb most; gateway-side per-IP cooldown is in the V2 backlog. | **Medium.** |
| **E**oP | Attacker abuses the gateway as an unrestricted oracle | First-factor accepted as a no-op (assumed validated upstream); attacker still must produce a valid TOTP or push approval. No oracle gained. | **None.** |

### Orchestrator + agents (`plenith/`)

| STRIDE | Threat | Mitigation | Residual risk |
|---|---|---|---|
| **S**poofing | Attacker forges an engagement_id to access another session | Engagement state keyed by `(source_ip, claimed_user)` — both come from the SSH session, not from user input. | **None.** |
| **T**ampering | Attacker writes to `state/` paths from inside their session | Agent containers have `cap_drop: [ALL]` and `no-new-privileges`; the VFS is in-memory; `state/` is host-side mounted read-only to attackers via the SSH wall. | **None** in default deploy. |
| **R**epudiation | Attacker disavows the session | Per-engagement log file written at session-end; persisted across reconnects. STIX bundles include `last_observed`. | **None.** |
| **I**nformation disclosure | Attacker discovers Plenith via fingerprinted decoy content | Content rotation per `(deployment_id, epoch)` — see §8 risk row. Quarterly bump procedure documented in DR runbook. | **Low; managed by rotation cadence.** |
| **D**oS | Attacker spams commands to exhaust orchestrator CPU | Async event loop + LLM-call timeout + per-session command cap (200 default) + LLM cache absorbs cache-hit traffic. | **Medium** under sustained DoS. |
| **E**oP | Attacker escapes asyncssh / orchestrator → host RCE | Defense-in-depth: container runs as non-root after init; `cap_drop ALL`; optional gVisor (`linux-fork/docker-compose.gvisor.yml`); k8s NetworkPolicy denies outbound except to audited bridge. | **Low** with gVisor + NetworkPolicy. |

### Network isolation (`linux-fork/isolation/`)

| STRIDE | Threat | Mitigation | Residual risk |
|---|---|---|---|
| **S**poofing | Attacker spoofs the LLM bridge's auth to call the real LLM | Bridge nginx accepts only `/v1/{models,chat/completions,...}` — locked URI list. Attacker traffic IS the proxied request shape; no spoof to detect. | **None.** |
| **T**ampering | Attacker tampers with the CoreDNS Corefile to enable recursion | Corefile mounted read-only into the dns pod from a ConfigMap; operator-only edits via Helm upgrade. | **None.** |
| **R**epudiation | Attacker denies attempting external DNS exfil | Every query logged by CoreDNS, including NXDOMAIN/SERVFAIL — visible in dashboard + Prometheus. | **None.** |
| **I**nformation disclosure | Attacker exfils via DNS query name (subdomain encoding) | The CoreDNS log IS the detector — every external lookup is captured and flagged in SIEM. | **By design — converted to detection.** |
| **D**oS | Attacker floods DNS with queries to exhaust CoreDNS | CoreDNS cache + standard NXDOMAIN response is cheap; queries-per-second cap configurable. | **Low.** |
| **E**oP | Attacker escapes the bubble's networking namespace | `internal: true` Docker network has no NAT and no host gateway. Even with full container root, no route to outside exists. | **None** without kernel-level exploit. |

### REST API (`plenith/api/`)

| STRIDE | Threat | Mitigation | Residual risk |
|---|---|---|---|
| **S**poofing | Attacker forges a Bearer token | Tokens compared via `hmac.compare_digest`; multiple tokens supported so rotation is non-disruptive. | **None** with sufficient token entropy. |
| **T**ampering | Attacker writes a `.pass` MFA decision via `/mfa/decisions/{ip}` to escalate | Endpoint requires Bearer auth (SOC tier 2+). Every write logged. The path is documented as override-only — production deployments should additionally gate it behind a SOAR approval. | **Medium — token holder can override MFA. Audit logs are the detection.** |
| **R**epudiation | API client denies the call | All requests logged by uvicorn + counted in `/metrics` (Prometheus). | **None.** |
| **I**nformation disclosure | API leaks engagement state to unauthenticated callers | `/engagements`, `/alerts`, `/mfa/...` all auth-gated when `api.tokens` is configured. Operator MUST configure in production — `/health`, `/ready`, `/metrics` remain open by design. | **Low** when correctly configured. |
| **D**oS | Attacker hammers `/engagements/{id}/narrative` to burn LLM tokens | LLM call has timeout; SOAR can rate-limit by token. | **Medium** without external rate limit. |
| **E**oP | API consumer escalates from read to admin | Single-tier token model — every authenticated caller has full access. **For per-tenant RBAC see backlog item 11.** | **High** in multi-tenant scenarios — single-tenant only for v1. |

### RL policy + counter-AI (`plenith/training/`, `plenith/counter_ai.py`)

| STRIDE | Threat | Mitigation | Residual risk |
|---|---|---|---|
| **T**ampering | Attacker poisons the RL policy by feeding crafted command streams | RL training is offline (against a hand-curated `AttackerSim` + corpus fixtures); attacker traffic never feeds back into the trained model without operator review. | **None.** |
| **I**nformation disclosure | Attacker learns to evade counter-AI traps by recognizing the marker format | Trap marker is per-engagement (SHA-256 derived) — different every session. Marker format itself is in the public code; rotation is the defense. | **Mitigated** by per-engagement freshness. |
| **E**oP | Attacker controls the LLM that the LLM bridge fronts | LLM endpoint is operator-controlled (self-hosted Ollama / vLLM). Attacker cannot reach the LLM endpoint directly — it's behind the audited bridge. | **None.** |

---

## High-impact attack scenarios

### Scenario 1: stolen credentials → real-prod compromise

**Goal:** attacker obtains a legitimate user's credentials and reaches real prod, bypassing Plenith.

**Attack chain:**
1. Phish jdoe's credentials.
2. SSH to corporate jumphost (`ssh -p 22 jdoe@corp.example.com`).
3. Identity proxy scores the connection. Geo, reputation, time-of-day all match jdoe's baseline → score < 3 → routed to **real-prod**.
4. Attacker accesses real systems as jdoe.

**Defense layered:** identity-proxy score isn't the only gate. If `jdoe` enrolled in MFA, even a low-score routing path should require it. The default config does NOT enforce this (score < 3 → real-prod with no MFA challenge); this is the intentional tradeoff for legit-user UX. To enforce MFA on every connection regardless of score, configure `mfa.enforce_on_low_risk: true` (not yet implemented — backlog).

**Acceptance criteria:** every customer's IR plan documents how MFA-required-everywhere is enforced upstream of Plenith.

### Scenario 2: attacker recognizes the honeypot

**Goal:** attacker realizes they're in Plenith and breaks contact, denying intel.

**Attack chain:**
1. Attacker reads `/etc/sudoers.d/zzz_compat` and recognizes the static content from a previous deployment they hit.
2. They issue `cat /etc/honeypot` or `grep -r Plenith /` looking for confirmation.
3. They `exit` immediately.

**Defenses:**
- **Content rotation per deployment** (`plenith/rotation/`) — two deployments with different `deployment_id` produce different sudoers/mysql/banner content. Static fingerprints don't carry between sites.
- **Quarterly epoch rotation** — even within one deployment, quarterly bumps invalidate any pattern published by red-team aggregators.
- **Counter-AI detection** — LLM-driven attackers that probe for honeypot markers trigger `alert_attacker_llm_detected` (high), giving the SOC visibility even when the attacker bails.

### Scenario 3: bubble escape

**Goal:** attacker escapes the decoy network and reaches real infrastructure.

**Attack chain:**
1. Attacker lands in bastion-prod with full shell (the orchestrator gave them one, that's the point).
2. Attempts:
   - `curl https://attacker.example.com/` → DNS blocked by CoreDNS
   - `curl http://10.0.0.5/` → no route to 10.0.0.5 (RFC1918 outside bubble)
   - `ssh user@10.0.0.5` → no route
   - `python3 -c 'socket.connect(("8.8.8.8",53))'` → no route
3. Each attempt fails fast (no outbound NAT).
4. Attacker tries kernel-level evasion (privilege escalation via local exploit). Without gVisor, succeeds. With gVisor (default in production Helm), defeated by syscall filter.

**Detection:** every blocked attempt fires the relevant heuristic (`alert_dns_exfil`, etc.) AND lights up the CoreDNS query log AND fails the next `validate.sh` cron run (raising a `validate.sh did not pass 18/18` SIEM alert).

### Scenario 4: API token leak

**Goal:** attacker leaks an admin token (e.g. from a misconfigured CI variable) and writes a fake `.pass` decision to bypass MFA.

**Attack chain:**
1. CI logs leak `PLENITH_API_TOKEN=secret123`.
2. Attacker exfiltrates the token.
3. Attacker hits `POST /mfa/decisions/192.0.2.99 {decision:"pass"}` from their own IP.
4. Connects with stolen creds; proxy sees the `.pass` decision, routes to real-prod, bypasses MFA.

**Mitigations:**
- Token rotation: support for **multiple valid tokens simultaneously** means operators can rotate on a schedule without service interruption (`PLENITH_API_TOKENS=new,old`).
- Audit log: every API call writes to uvicorn's access log + counted in `/metrics`. SOC tier 2 detects the unusual call.
- The `mfa.decisions/{ip}` endpoint should additionally be gated behind a separate "admin-tier" token in production — see backlog item 11 (per-tenant RBAC) and ADR 008.

### Scenario 5: supply-chain compromise of a dependency

**Goal:** malicious version of asyncssh / fastapi / pydantic gets pulled in via `pip install`.

**Mitigations:**
- All Python deps pinned in `requirements.txt` with explicit version ranges.
- CycloneDX SBOM (`python tools/sbom.py`) generated on every build; auditable against CVE databases.
- Dependabot / Renovate config (backlog item 15) opens PRs on dep updates; each goes through CI.
- Container images use `FROM ubuntu:22.04` — pinned base, vulnerability-scanned on push.

---

## What we explicitly do NOT defend against

These are out of scope; document them so customers understand the boundary:

1. **Kernel-level exploits on the host without gVisor.** If the operator declines gVisor and the attacker has a working LPE in the host kernel, Plenith cannot prevent host compromise. Recommendation: enable gVisor in the Helm chart (`runtime.runtimeClassName: runsc`).
2. **Compromised operator workstation.** If the operator's machine that holds the API token / Helm values is compromised, the attacker has full control. Out of scope.
3. **Compromised upstream LLM endpoint.** If the operator's Ollama / vLLM cluster is compromised, the LLM responses Plenith serves to attackers become attacker-controlled. Recommendation: run LLM inside the same trust boundary as the orchestrator.
4. **Side-channel attacks on TOTP secrets.** Plenith uses constant-time compare for tokens, but a sufficiently-resourced attacker with local code execution on the gateway can recover secrets.
5. **Legal / regulatory liability of "attracting" attackers.** Plenith is a tool. Customers MUST consult counsel for jurisdictions where running a honeypot may create entrapment / wiretap / data-protection obligations.

---

## Update cadence

This document is reviewed:
- On every major release (anything that touches `plenith/policy.py`, `plenith/api/`, `linux-fork/isolation/`, `linux-fork/mfa/`, or the connector wire formats).
- At least annually regardless.
- After every confirmed compromise of a customer deployment.

Suggest changes via PR. Material changes require sign-off from the security lead.
