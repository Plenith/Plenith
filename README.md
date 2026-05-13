# Plenith

**Self-hosted, AI-driven SSH deception platform.** Routes attackers into a sealed deception fabric, learns from them with reinforcement learning, detects when the adversary is an LLM agent and feeds it prompt-injection bait, and emits MITRE-tagged events into every major SIEM / SOAR / TI platform.

```
ssh attacker@your.org
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│  Identity proxy (Lua risk-scoring + PROXY-v1 forwarding)    │
│        │              │              │                       │
│   low risk      borderline       high risk                   │
│        ▼              ▼              ▼                       │
│  real-prod     MFA gateway     plenith agents             │
│                (Duo/Okta/      (decoy fabric)                │
│                 Twilio/TOTP)    │                            │
│                                 │  lateral SSH allowed       │
│                                 ▼  inside the bubble only    │
│             ┌─────────────────────────────────────────┐      │
│             │ bastion-prod  db-prod-01  api-prod-03   │      │
│             │  + counter-AI detector                  │      │
│             │  + content rotation per deployment      │      │
│             │  + OT decoys (Modbus/S7/DNP3)           │      │
│             └─────────────────────────────────────────┘      │
│                          │                                   │
│   network isolation:  ◀──┘  CoreDNS sealed against external  │
│   default-DROP egress       recursion, all queries logged    │
│   LLM bridge audited        for covert-channel detection     │
└─────────────────────────────────────────────────────────────┘
        │
        ▼
  Alerts → Splunk HEC, Elastic, syslog (CEF/LEEF/RFC-5424),
            Slack, Teams, PagerDuty, Cortex XSOAR, Splunk SOAR
  IoCs   → STIX 2.1 bundles auto-published to MISP / OpenCTI
            / ISAC TAXII servers
  Reports → SOC 2 / ISO 27001 / NIS2 attestations, on demand
  API    → FastAPI + OpenAPI 3.1 + Python SDK
```

---

## Why this exists

The commercial deception market (Acalvio, Illusive, Attivo SentinelOne, Splunk DECEIVE) charges $50k+/year per endpoint and ships closed-source. Plenith matches their feature parity on the integration surface that matters, **plus** ships features none of them have (counter-AI deception, adversarial RL co-evolution, content rotation per deployment, OT/ICS protocol decoys, LLM-narrated incident reports), under the MIT license with **zero per-endpoint cost**.

The Engineering Blueprint at `../Plenith.md` is the design spec. This repo is the realization.

---

## Feature matrix

|  | Plenith | Acalvio | Illusive | Attivo | Splunk DECEIVE |
|---|:---:|:---:|:---:|:---:|:---:|
| SSH-layer deception | ✓ | ✓ | ✓ | ✓ | ✓ |
| Identity-proxy risk routing | ✓ | ✓ | ✓ | ✓ | — |
| MFA step-up (Duo/Okta/Twilio) | ✓ | ✓ | ✓ | ✓ | — |
| Push approval flow | ✓ | ✓ | ✓ | ✓ | — |
| Content rotation (per deployment) | ✓ | partial | partial | — | — |
| RL-trained policy | ✓ | — | — | — | ✓ |
| **Counter-AI / LLM-attacker detection** | **✓** | — | — | — | ✓ |
| **Adversarial RL co-evolution** | **✓** | — | — | — | — |
| **OT/ICS decoys (Modbus/S7/DNP3)** | **✓** | partial | — | partial | — |
| **LLM-narrated incident reports** | **✓** | — | — | — | partial |
| MITRE ATT&CK tagging | ✓ | ✓ | ✓ | ✓ | ✓ |
| Splunk HEC / Elastic / Syslog | ✓ | ✓ | ✓ | ✓ | ✓ (native) |
| STIX 2.1 + TAXII 2.1 publish | ✓ | ✓ | ✓ | ✓ | — |
| Cortex XSOAR + Splunk SOAR | ✓ | ✓ | ✓ | ✓ | partial |
| Helm chart / k8s native | ✓ | ✓ | ✓ | ✓ | ✓ |
| OpenAPI REST + Python SDK | ✓ | ✓ | ✓ | ✓ | partial |
| **Open source / self-hostable** | **✓** | — | — | — | ✓ |

---

## 60-second quickstart

```bash
# Single-host MVP
git clone https://github.com/example/plenith.git
cd plenith
pip install -r requirements.txt

# Start LM Studio with qwen2.5-7b-instruct on http://localhost:1234
python run.py
# Honeypot listening on 127.0.0.1:2222

# In another terminal — attack it
ssh -p 2222 jdoe@127.0.0.1
```

Full multi-host fabric is 5 minutes:

```bash
cd linux-fork
cp .env.example .env       # set PLENITH_DEPLOYMENT_ID
docker compose up -d
ssh -p 22000 jdoe@127.0.0.1   # routed by the identity proxy
```

Production k8s deploy:

```bash
helm install plenith deploy/helm/plenith/ \
    --set global.deploymentId=$(uuidgen) \
    --set connectors.splunkHec.url=https://splunk.example.com:8088 \
    --set connectors.splunkHec.token=$SPLUNK_HEC_TOKEN \
    --set mfa.provider=duo \
    --set mfa.duo.host=api-XXX.duosecurity.com \
    --set chatops.slack.url=https://hooks.slack.com/...
```

Detailed walkthrough: **[`docs/QUICKSTART.md`](docs/QUICKSTART.md)**.

---

## What's in the box

### Core platform

| Module | What it does |
|---|---|
| `plenith/orchestrator.py` | Per-session command dispatch + heuristic loop |
| `plenith/session.py` | Engagement state, observation, cross-connection persistence |
| `plenith/heuristics.py` | 14 rules + counter-AI detection — fires alerts based on observed attacker behavior |
| `plenith/vfs.py` | Canonical-POSIX virtual filesystem (read/write/append/rm/...) |
| `plenith/synthetic.py` | Deterministic honeytoken generation (AWS / SSH / git / bash_history) |
| `plenith/sim_bot.py` | Synthetic fleet (`who` / `w` / `last` / `/etc/passwd` consistency) |
| `plenith/ssh_server.py` | asyncssh-based listener + dual-port PROXY-v1 stripping |
| `plenith/state_store.py` | Cross-session persistence keyed by (source_ip, claimed_user) |
| `plenith/persona.py` | YAML personas (`jdoe` SWE, `agarcia` SRE, `mwilson` IR/DE) |

### Adaptive deception

| Module | What it does |
|---|---|
| `plenith/policy.py` | V1/V2 policy interface; `HeuristicPolicy`, `RLPolicyStub`, `TrainedRLPolicy` |
| `plenith/training/` | REINFORCE RL pipeline — env, attacker sim, reward, policy_net, train, evaluate |
| `plenith/training/adversary.py` + `coevolve.py` | Adversarial RL co-evolution (defender vs adversary with Elo tracking) |
| `plenith/counter_ai.py` | Detects LLM-driven attackers (timing rhythm + lexical purity + injection probes) and embeds prompt-injection traps |
| `plenith/rotation/` | Deployment-scoped content rotation — quarterly epoch bumps regenerate every decoy artifact |
| `plenith/narrate.py` | LLM-generated exec-readable incident summaries |

### Multi-host fabric (`linux-fork/`)

| Path | What it does |
|---|---|
| `linux-fork/docker-compose.yml` | 9-service fabric: 5 agents + proxy + DNS + LLM bridge + push-sim + MFA gateway |
| `linux-fork/isolation/` | §4.2 — internal-only DNS (CoreDNS), audited LLM egress (nginx), 18-probe breakout validation |
| `linux-fork/routing/` | OpenResty stream + Lua risk-scoring + PROXY-v1 forwarding |
| `linux-fork/mfa/` | TOTP gateway + push-sim + decision-file handoff to Lua |
| `linux-fork/tools/ot_decoys.py` | Modbus / S7 / DNP3 protocol speakers (with function-code parsing) |
| `linux-fork/agent/` | Per-host agent Dockerfile + entrypoint |
| `linux-fork/tools/fake_service.py` | MySQL / HTTP fake listeners + OT decoys |

### Connectors (`plenith/connectors/`)

| Module | Wire format / endpoint |
|---|---|
| `formats.py` | CEF (ArcSight), LEEF (QRadar), RFC 5424 syslog, JSON event |
| `siem.py` | Splunk HEC, Elasticsearch bulk, syslog UDP/TCP, generic webhook, FanOut |
| `chatops.py` | Slack, Teams (MessageCard), PagerDuty Events API v2 |
| `mitre.py` | ATT&CK technique mapping + Sigma tag rendering |
| `mfa_providers.py` | Duo Auth API v2, Okta Factors API, Twilio Verify, PushSim |
| `stix.py` | STIX 2.1 Bundle export (indicators + attack-patterns) |
| `taxii.py` | TAXII 2.1 publish-fan-out (MISP / OpenCTI / FreeTAXII / ISAC) |
| `soar.py` | Cortex XSOAR incident + Splunk SOAR container/artifact + 8 playbook hints |

### Inbound REST API (`plenith/api/`)

| Endpoint | Purpose |
|---|---|
| `GET /engagements` (+ filters) | List attacker sessions with severity/user/IP/time filters |
| `GET /engagements/{id}` | Full session detail (command stream, alerts, IoCs) |
| `GET /engagements/{id}/narrative` | LLM-generated exec summary |
| `GET /alerts` (+ filters) | All fired alerts |
| `POST /isolation/validate` | Trigger 18-probe breakout test |
| `POST /mfa/decisions/{ip}` | Manual MFA decision override |
| `GET /metrics` | Prometheus exposition |
| `GET /openapi.json` + `/docs` + `/redoc` | Schema + Swagger UI + ReDoc |

CLI client: `python tools/api_client.py engagements --severity high`.
Python SDK: `PlenithClient` (async, in `plenith.api`).

### Compliance + operations (`plenith/compliance/`)

| Module | What it does |
|---|---|
| `controls.py` | Maps every Plenith action to SOC 2 (8 controls), ISO 27001 (8 controls), NIS2 (10 article 21 measures) |
| `evidence.py` | Harvests real evidence from engagement state, logs, MFA decisions, rotation manifests |
| `report.py` | Renders attestation as Markdown / HTML / JSON for auditors and GRC platforms |
| `runbooks.py` | Generates 6 §13 operational runbooks: data retention, IR RACI, burn-down protocol, capacity model, content rotation, disaster recovery |

### CLIs (`tools/`)

| Command | What it does |
|---|---|
| `tools/audit.py` | Engagement narrative + IoC export + Sigma rules + HTML reports |
| `tools/connectors.py` | Render alert through every format + publish STIX via TAXII + export SOAR playbooks |
| `tools/compliance_report.py` | Generate SOC 2 / ISO 27001 / NIS2 attestation |
| `tools/runbook.py` | Render any of the 6 operational runbooks |
| `tools/narrate.py` | LLM exec summary of one engagement |
| `tools/rotate_content.py` | Bump content-rotation epoch and inspect/diff manifests |
| `tools/mfa_enroll.py` | Enroll users in the MFA store (with ASCII QR codes) |
| `tools/train_rl.py` | Train the RL policy network |
| `tools/coevolve_rl.py` | Run adversarial RL co-evolution |
| `tools/dashboard.py` | Live SOC dashboard (auto-refresh HTML) |
| `tools/after_action.py` | Post-engagement quick report |
| `tools/demo_attack.py` | Scripted attacker run-through (E2E demo) |
| `tools/api_server.py` | Run the FastAPI REST API |
| `tools/api_client.py` | CLI for the REST API |
| `tools/bench.py` | Concurrency benchmark |
| `tools/backup.py`, `tools/restore.py` | DR-runbook implementation |
| `tools/sbom.py` | CycloneDX SBOM generator |
| `tools/replay.py` | Replay a captured engagement log |
| `tools/sweep.py` | Multi-persona end-to-end exercise |
| `tools/connect.py` | Quick interactive SSH client |

---

## Running the tests

```bash
pip install -r requirements-dev.txt
pytest                                   # full suite, ~30s
pytest --ignore=tests/test_isolation.py  # skip Docker E2E
pytest -k counter_ai                     # one module
```

The CI matrix runs on Python 3.11, 3.12, 3.13, 3.14 across Ubuntu + Windows. Docker-dependent tests (isolation probes + live MFA gateway E2E) run on Ubuntu only via `docker compose`.

Current count: **571 tests, ~30 second suite, coverage ratchet at 70%**.

---

## Engineering Blueprint cross-reference

The repo maps 1:1 to sections of `Plenith.md`:

| Blueprint section | Where in this repo |
|---|---|
| §3 Core concept + differentiators | This README, `docs/THREAT_MODEL.md` |
| §4.1 Architecture diagram | `linux-fork/docker-compose.yml` |
| §4.2 Isolation Design | `linux-fork/isolation/` |
| §4.3 Credential-Compromised Attack Flow (MFA step-up) | `linux-fork/mfa/`, `linux-fork/routing/` |
| §5.1 Smart Identity Proxy | `linux-fork/routing/ROUTING_SPEC.md` |
| §5.2 Deception Orchestrator V1 | `plenith/orchestrator.py` |
| §5.3 Self-Hosted LLM | `plenith/llm_client.py` + LM Studio / Ollama |
| §5.4 Decoy Factory | `plenith/rotation/`, `plenith/responses.py` |
| §5.5 Synthetic user simulation | `plenith/sim_bot.py` |
| §5.6 Monitoring | `plenith/connectors/`, `tools/audit.py` |
| §6.1 Hardware BoM | `Plenith.md` (RTX 3090, 64GB) |
| §8 Risk table → "synthetic data fingerprinting" | `plenith/rotation/` (corp identity per deployment) |
| §9 Legal/Compliance | `plenith/compliance/`, `docs/THREAT_MODEL.md` |
| §10 KPIs | `plenith/api/metrics.py`, `tools/dashboard.py` |
| §11 V2 RL Policy | `plenith/training/`, `plenith/policy.py` (`TrainedRLPolicy`) |
| §11 V3 Adversarial RL | `plenith/training/adversary.py` + `coevolve.py` |
| §13 Operational sections | `plenith/compliance/runbooks.py` (6 generated docs) |

---

## Documentation

### Getting started

- **[`docs/QUICKSTART.md`](docs/QUICKSTART.md)** — 60s install / 5min first deploy / 10min first alert
- **[`docs/DEPLOYMENT_GUIDE.md`](docs/DEPLOYMENT_GUIDE.md)** — three deployment tiers (laptop → docker-compose → Kubernetes), UX matrix, topology diagram
- **[`docs/FAQ.md`](docs/FAQ.md)** — common questions on licensing, mission, architecture, operations

### Architecture + security

- **[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)** — STRIDE walk-through for procurement
- **[`docs/HARDENING.md`](docs/HARDENING.md)** — five-layer production hardening (network → runtime → TLS → audit → retention)
- **[`docs/VERIFY_RELEASES.md`](docs/VERIFY_RELEASES.md)** — cosign + SLSA verification of signed releases
- **[`docs/SECRETS.md`](docs/SECRETS.md)** — env / file / Vault / AWS Secrets Manager integration
- **[`docs/PLUGINS.md`](docs/PLUGINS.md)** — third-party detectors / responders / connectors / policies
- **[`docs/adr/`](docs/adr/)** — 14 architecture decision records

### Compliance + privacy

- **[`docs/DPIA.md`](docs/DPIA.md)** — GDPR Art. 35 Data Protection Impact Assessment
- **[`docs/DATA_HANDLING.md`](docs/DATA_HANDLING.md)** — per-category data lifecycle + DSR workflow
- **[`docs/COMPLIANCE_MAPPING.md`](docs/COMPLIANCE_MAPPING.md)** — SOC 2 + ISO 27001 control mapping
- **[`docs/runbooks/`](docs/runbooks/)** — one operator runbook per Prometheus alert

### Project + governance

- **[`MISSION.md`](MISSION.md)** — open-source-forever promise + 30% commercial-revenue pledge to children's-development initiatives
- **[`GOVERNANCE.md`](GOVERNANCE.md)** — maintainer structure, Mission Steward role, succession planning
- **[`MAINTAINERS.md`](MAINTAINERS.md)** — current maintainers + path to joining
- **[`ROADMAP.md`](ROADMAP.md)** — v1.x done / v1.1 / v1.2 / v2.x / out-of-scope
- **[`TRADEMARK.md`](TRADEMARK.md)** — brand-marks policy + fork-naming convention
- **[`COMMERCIAL.md`](COMMERCIAL.md)** — what's free forever vs. what's commercially offered
- **[`SECURITY.md`](SECURITY.md)** — vulnerability disclosure policy
- **[`CONTRIBUTING.md`](CONTRIBUTING.md)** — dev setup + PR workflow
- **[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)** — Contributor Covenant 2.1

### Multi-host fabric

- **[`linux-fork/README.md`](linux-fork/README.md)** — multi-host fabric overview
- **[`linux-fork/isolation/README.md`](linux-fork/isolation/README.md)** — §4.2 four pillars + probe playbook
- **[`linux-fork/routing/ROUTING_SPEC.md`](linux-fork/routing/ROUTING_SPEC.md)** — proxy + MFA step-up

After `python tools/api_server.py`:

- `http://localhost:8080/docs` — Swagger UI (try-it-now interactive)
- `http://localhost:8080/redoc` — ReDoc reference browser
- `http://localhost:8080/openapi.json` — schema (feed into any code-gen tool)

---

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

The source code is free forever under that license. The name **Plenith** and the Plenith logo are separately reserved trademarks — see [TRADEMARK.md](TRADEMARK.md) for permitted uses. The commercial offering boundary (what's OSS engine vs. what's paid services + content) is documented in [COMMERCIAL.md](COMMERCIAL.md). The 30% pledge of net commercial revenue to children's-development initiatives is binding per [MISSION.md](MISSION.md).
