# Deployment Guide

How Plenith actually gets deployed, by whom, and what each user
sees. This is the canonical answer to "what does the user
experience look like?" — covering the three distinct users
(operator, SOC analyst, attacker) and the three deployment tiers
(single-host MVP, docker-compose multi-host, production
Kubernetes).

If you're evaluating Plenith for procurement: read sections 1–2.
If you're deploying it: read section 3 onward.

---

## 1. The three users

Plenith has three audiences. They use different interfaces and
should be considered separately when planning a deployment.

### 1.1 The Operator

**Who**: the SOC engineer or platform engineer who installs,
configures, and operates Plenith.

**What they see**:
- CLI tools (`run.py`, the entire `tools/` directory)
- Config files (`config.yaml`, `linux-fork/.env`, Helm
  `values.yaml`)
- The Plenith REST API (programmable interface for automation)
- The dashboard at `:8765` (for live monitoring)

**Why prompt-based**: SOCs run real infrastructure via code
(Terraform, Helm, GitOps, Ansible). A click-to-deploy GUI would
be hostile to their existing operational practice. Also, a web
installer on a security tool is itself an attack surface.

### 1.2 The SOC Analyst

**Who**: the human who triages alerts, investigates engagements,
and decides response actions during an active attack.

**What they see**:
- **The Plenith dashboard** at `http://<host>:8765/` — an
  auto-refreshing web UI showing live engagements, container
  status, DNS query log, and severity-ranked alerts. Pushed via
  SSE; no manual polling.
- **Their existing SIEM** — Splunk / Wazuh / Sentinel / Elastic.
  Plenith ships CEF-formatted alerts here via the SIEM connector;
  the analyst stays in the tool they already use.
- **Slack / Teams / their ChatOps channel** — high-severity
  alerts route here via the ChatOps connector.

**Why graphical**: live monitoring is a graphical-UI problem. The
dashboard is purpose-built for this; integrations with the
analyst's existing graphical tools are first-class.

### 1.3 The Attacker

**Who**: a malicious actor who's hit the SSH proxy port (`:22000`
by default).

**What they see**:
- A login prompt that looks like a real SSH server
- After authentication, a realistic Linux shell prompt
- LLM-generated responses to commands they type
- Planted credentials, decoys, and synthetic data that look real

**Why prompt-based**: the whole product is "make this look like a
real Linux server so the attacker stays engaged." A GUI would
break the deception.

---

## 2. Architecture topology

```
                ┌─────────────────────────────────────────────────────┐
                │           OPERATOR'S NETWORK (your SOC)             │
                │                                                     │
   ┌────────┐   │   ┌─────────────────┐    ┌─────────────────────┐  │
   │ SOC    │HTTPS┤Plenith dashboard │    │ Existing SIEM       │  │
   │ analyst│───┼──►│ :8765 (browser) │    │ (Splunk/Wazuh/etc.) │  │
   │ (you)  │   │   └─────────────────┘    └─────────────────────┘  │
   └────────┘   │            ▲                    ▲                  │
                │            │ SSE push           │ CEF alerts        │
   ┌────────┐   │            │                    │                  │
   │ Ops    │CLI│   ┌────────┴────────────────────┴──────────────┐  │
   │ (you)  │───┼──►│  Plenith orchestrator                       │  │
   └────────┘   │   │   - REST API (FastAPI :8000)                │  │
                │   │   - SSH proxy (:22000)  ◄──── attacker      │  │
   ┌────────┐   │   │   - Heuristics + policy + LLM client        │  │
   │SOAR/   │REST   │   - Connectors (SIEM/SOAR/MFA/STIX)         │  │
   │CI/CD   │───┼──►│   - Audit chain + retention                 │  │
   └────────┘   │   └─────────────────────┬────────────────────────┘  │
                │                          │                          │
                │                          │ controls                  │
                │                ┌─────────▼──────────────────┐       │
                │                │ Decoy Bubble (containers)   │       │
                │                │ ┌──────┐ ┌──────┐ ┌──────┐ │       │
                │                │ │bastion│ │ db-  │ │ api- │ │       │
                │                │ │-prod  │ │prod  │ │prod  │ │       │
                │                │ └──────┘ └──────┘ └──────┘ │       │
                │                │   + plenith-dns + MFA      │       │
                │                └─────────────────────────────┘       │
                └─────────────────────────────────────────────────────┘
                                          ▲
                              attacker SSH│ (port 22000)
                                          │
                                ┌─────────┴──────────┐
                                │ ATTACKER (internet)│
                                │ sees a fake shell  │
                                └────────────────────┘
```

Key points:

- **Three network zones**: the operator's network (your SOC
  perimeter), the decoy bubble (isolated container network), and
  the attacker's source (the internet or the customer's
  semi-trusted internal network).
- **Default-DROP egress** from the decoy bubble to anywhere except
  the documented allowlist endpoints (LLM, SIEM, MFA, NTP, DNS).
  Enforced by `deploy/network/decoy-bubble-egress.nft`.
- **One-way data flow** to your SIEM. Plenith pushes alerts; your
  SIEM doesn't reach back into the bubble.
- **Reverse proxy in front of the API + dashboard** for any
  production deployment. Plenith ships bearer-token auth as the
  second line of defense; the proxy is the first.

---

## 3. Deployment Tier 1 — Single-host MVP

**Use case**: laptop, dev VM, evaluation, small-scale
proof-of-concept. ~5 minutes from `git clone` to first
engagement.

### Prerequisites

- Python ≥ 3.11
- An OpenAI-compatible LLM endpoint:
  - **Local** (recommended for evaluation): LM Studio or Ollama
    running on the same machine. The `qwen2.5-7b-instruct-1m`
    model is a good starting point.
  - **Cloud**: any OpenAI-compatible API. Note that prompts +
    response context will leave your network — review
    `docs/DATA_HANDLING.md` § D5 first.
- Docker (optional, only needed for the decoy bubble in Tier 2+).

### Steps

```bash
# 1. Clone
git clone https://github.com/Plenith/Plenith
cd plenith

# 2. Python environment
python -m venv .venv
source .venv/bin/activate           # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 3. Configure
cp config.yaml.example config.yaml
$EDITOR config.yaml                 # set LLM endpoint, paths, etc.

# 4. Start the three processes (separate terminals or systemd units)
python run.py                        # Terminal 1 — SSH proxy :22000
python tools/api_server.py           # Terminal 2 — REST API :8000
python tools/dashboard.py            # Terminal 3 — Dashboard :8765

# 5. Open the dashboard
# (Linux)   xdg-open http://127.0.0.1:8765/
# (Mac)     open http://127.0.0.1:8765/
# (Windows) start http://127.0.0.1:8765/
```

### Verification — make sure it works

In a fourth terminal, drive a test attack:

```bash
ssh -p 22000 jdoe@127.0.0.1
# Try commands a real attacker would type:
> ls -la
> cat /etc/passwd
> find / -name "*.aws*" 2>/dev/null
> sudo -l
```

Each command should:
- Return realistic output (cache, LLM, or simulation bot)
- Appear in the dashboard within a second or two
- Trigger a heuristic alert if the command matches one of the 14
  rules

If you see all three: deployment is healthy.

### What you have at the end of Tier 1

- Orchestrator running on `127.0.0.1`
- Dashboard viewable in browser
- REST API responding at `:8000` (try `curl http://127.0.0.1:8000/health`)
- All state under `state/` and `state-docker/persistence/`

What you do NOT have:
- The decoy containers (db-prod-01, api-prod-03, etc.) — those
  need Tier 2
- TLS, real auth, retention enforcement, alert routing — those
  need Tier 3 hardening

---

## 4. Deployment Tier 2 — Multi-host docker-compose (dev fabric)

**Use case**: red team exercises, demo environments, full-stack
integration testing. The full multi-host bubble runs locally.

### Prerequisites

- Tier 1 prerequisites, plus
- Docker Engine + docker-compose v2
- ~4GB free RAM (each agent container is ~256MB)

### Steps

```bash
cd linux-fork/
cp .env.example .env
$EDITOR .env
# At minimum, set:
#   PLENITH_DEPLOYMENT_ID=<your-uuid>
#   PLENITH_LLM_ENDPOINT=http://host.docker.internal:1234/v1
#   PLENITH_SIEM_URL=http://<your-siem>:8088   (optional)

docker compose up -d
docker compose ps    # should show 7-8 containers Up
```

The fabric brings up:

| Container | Purpose |
| :--- | :--- |
| `bastion-prod` | The decoy "bastion host" (SSH entry point) |
| `db-prod-01` | Decoy database server |
| `api-prod-03` | Decoy API server |
| `real-prod-jumphost` | Decoy "real production" jumphost (the attacker's prize) |
| `plenith-dns` | Dedicated DNS resolver for the bubble |
| `plenith-llm-egress` | Egress proxy for LLM calls |
| `mfa-gateway` | MFA bridge (Duo / Okta simulation) |
| `push-sim` | MFA push notification simulator |

The dashboard (running on the host, not in a container)
auto-discovers all of them and shows a unified view.

### Verification

From outside the bubble:

```bash
# Attacker entry point
ssh -p 22000 jdoe@<host>

# Each decoy host has its own SSH personality
ssh -p 22000 -o ProxyJump=jdoe@<host>:22000 agarcia@db-prod-01
```

The 18-probe network-isolation test (in `tests/test_isolation.py`)
verifies the bubble cannot reach anything outside its allowlist.

### What you have at the end of Tier 2

- A working multi-host deception fabric
- Persistent state across container restarts (volumes mounted)
- Realistic lateral-movement targets for red-team exercises

What you do NOT have (still):
- Production-grade TLS / auth / retention
- Real SIEM integration (just a placeholder URL)
- Multi-tenant separation

Those need Tier 3.

---

## 5. Deployment Tier 3 — Production Kubernetes

**Use case**: real SOC deployment, customer-facing, multi-tenant.

### Prerequisites

- Kubernetes cluster (1.27+)
- Helm 3.x
- Ingress controller (nginx-ingress or equivalent)
- TLS certificates (Let's Encrypt + cert-manager, or your CA)
- A real LLM endpoint reachable from the cluster
- A real SIEM that accepts CEF over syslog / Splunk HEC / etc.
- Persistent storage class (for engagement state, logs, audit chain)

### Steps

```bash
# 1. Add the Helm repository (when published)
helm repo add plenith https://Plenith.github.io/plenith-helm
helm repo update

# 2. Inspect default values
helm show values plenith/plenith > my-values.yaml
$EDITOR my-values.yaml

# 3. Install
helm install plenith plenith/plenith \
  --namespace plenith \
  --create-namespace \
  --values my-values.yaml

# 4. Verify
kubectl get pods -n plenith
kubectl logs -n plenith deployment/plenith-orchestrator
```

### Hardening (NOT optional in production)

After the basic install, follow `docs/HARDENING.md`:

1. **Network**: apply `deploy/network/decoy-bubble-egress.nft` at
   the host level (the Helm chart can't do this — it's a
   node-level firewall change).
2. **Container runtime**: enforce seccomp + AppArmor profiles
   (`deploy/security/`). The Helm chart supports
   `securityContext` overrides for each Pod.
3. **TLS termination**: deploy nginx-ingress with cert-manager;
   point a hostname at the ingress; require TLS on the dashboard
   and API.
4. **Auth**: configure bearer tokens via the secrets resolver
   (`docs/SECRETS.md` patterns). Don't store tokens in
   `values.yaml` plain-text.
5. **Audit chain verification**: schedule
   `tools/verify_chain.py` as a CronJob.
6. **Retention enforcement**: schedule `tools/retention_purge.py`
   as a CronJob.
7. **Alerting**: ship the alert rules in
   `deploy/prometheus/alerts.yml` to your Alertmanager.

### What you have at the end of Tier 3

A production-grade deployment that:
- Survives node failures (replicas, pod disruption budgets)
- TLS-protected throughout
- Audited continuously (chain verification + retention)
- Integrated with your existing Prometheus / Grafana / SIEM stack
- Multi-tenant if you configured tenant tokens

What you should now ALSO have running (separate from the cluster):
- Your own Plenith deployment on a public IP for a real attack
  surface (recommended: run for ≥30 days before public launch to
  prove out the operational story — see
  `docs/PRE_LAUNCH_CHECKLIST.md` Part E).

---

## 6. Day-to-day operations

### For the SOC analyst

Open the dashboard in a browser tab. It auto-refreshes via SSE.
When an alert fires:

1. **Critical alert** (reverse shell, SSH persistence, proven
   counter-AI hit) → page to the on-call via your Alertmanager;
   the matching runbook in `docs/runbooks/` has the playbook.
2. **High / Medium alert** → ticket via your SIEM's standard
   workflow.
3. **Info** → archived for trending analysis.

The dashboard is for *live* observation; the SIEM is for
*historical* triage. They're complementary.

### For the operator

CLI tools cover the operational tasks:

| Task | Tool |
| :--- | :--- |
| Replay an engagement log | `tools/audit.py` + `tools/replay.py` |
| Backup state | `tools/backup.py` |
| Verify audit chain integrity | `tools/verify_chain.py` |
| Purge old data per retention policy | `tools/retention_purge.py` |
| Generate after-action narrative | `tools/after_action.py` |
| Rotate decoy content (defeat fingerprinting) | `tools/rotate_content.py` |
| Generate SBOM | `tools/sbom.py` |
| Run benchmark + compare to baseline | `tools/bench.py --compare` |
| Generate compliance evidence | `tools/compliance_report.py` |
| Verify secret references resolve | `tools/secrets_check.py` |

All CLIs support `--json` output where it makes sense, so they
slot into existing automation.

### For the integrator (SOAR / CI)

The REST API at `:8000` is the integration surface. OpenAPI spec
at `/openapi.json`; Swagger UI at `/docs`. Common patterns:

- Query active engagements: `GET /api/v1/engagements?status=open`
- Fetch one engagement: `GET /api/v1/engagements/<id>`
- List recent alerts: `GET /api/v1/alerts?since=...`
- Issue a tenant token (admin only):
  `POST /api/v1/tenants/<id>/tokens`

See `docs/PLUGINS.md` for adding custom plugins (detectors,
responders, connectors, policies) when the built-ins don't fit.

---

## 7. What about a hosted SaaS option?

Plenith does NOT offer a hosted multi-tenant SaaS dashboard today.
The architecture is self-hosted by design:

- Engagement data includes attacker source IPs, credential
  fingerprints, and command streams — material most enterprises
  refuse to send to a third party
- Self-hosting matches the buyer expectation (Acalvio, Illusive,
  CounterCraft are all self-hosted)
- The Apache 2.0 license + the open-source-forever promise mean
  any vendor can stand up a hosted Plenith — including the
  maintainer organization, when revenue justifies it

A hosted dashboard tier is on the v2.x roadmap (`ROADMAP.md` §
"Considering — v2.x"). When it ships, it will be a **service
layer over the OSS engine**, not a replacement for self-hosting.

---

## 8. Common deployment gotchas

| Symptom | Likely cause |
| :--- | :--- |
| Dashboard shows no engagements after attack | LLM endpoint unreachable from orchestrator; check `python run.py` stderr for connection errors |
| Containers up but attacker SSH connection drops | nftables blocking — verify `iif "$BUBBLE_IFACE" tcp dport 22000 accept` rule loaded |
| Alerts not appearing in Splunk | SIEM connector credential mismatch; check `tools/secrets_check.py --resolve` |
| `tools/verify_chain.py` reports legacy logs | Engagement logs written before v1.0; expected during rollout, see audit-chain rollout doc |
| Heartbeat alerts firing immediately | `mirrorcore_agent_heartbeat_timestamp_seconds` metric not exposed yet — see `docs/HARDENING.md` § 4.2 for the textfile-collector setup |
| Dashboard reachable but engagements not refreshing | SSE blocked by intermediate proxy; check that your reverse proxy has `proxy_buffering off` for `/api/stream` |

For anything not covered here, open a GitHub Discussion or check
the runbook for the specific alert that fired
(`docs/runbooks/`).

---

## 9. What this doc does NOT cover

- **The threat model** — see `docs/THREAT_MODEL.md`
- **Hardening details** — see `docs/HARDENING.md`
- **Compliance evidence** — see `docs/COMPLIANCE_MAPPING.md` and
  `docs/DPIA.md`
- **Secret management** — see `docs/SECRETS.md`
- **Plugin authorship** — see `docs/PLUGINS.md`
- **Release verification** — see `docs/VERIFY_RELEASES.md`
- **Backup / disaster recovery** — see `tools/backup.py` and
  `tools/restore.py` headers

This deployment guide is the on-ramp; those are the details once
you're moving.

---

*Last updated: 2026-05-12.*
*Companion to [QUICKSTART.md](QUICKSTART.md), [HARDENING.md](HARDENING.md),
[THREAT_MODEL.md](THREAT_MODEL.md).*
