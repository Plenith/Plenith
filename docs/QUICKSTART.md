# Plenith Quickstart

**Goal:** install Plenith in <60 seconds, deploy your first decoy in <5 minutes, see your first alert in <10 minutes.

Three deployment shapes. Pick the one that matches what you want today; you can graduate from one to the next without re-installing.

| Shape | Time | What you get |
|---|---|---|
| **(A) Single-host MVP** | 60s | One Python process. Honeypot on `127.0.0.1:2222`. Perfect for "what does this thing do?" |
| **(B) Multi-host fabric** | 5min | 9-container Docker Compose. Identity proxy, MFA gateway, isolated decoy network, content rotation, full SIEM connectors. |
| **(C) Production (Helm)** | 30min | k8s deploy with NetworkPolicy, NodePort ingress, real MFA provider (Duo/Okta), Splunk / Slack / PagerDuty wired. |

---

## Prerequisites

| Shape | Python | Docker | k8s | LLM |
|---|---|---|---|---|
| A | 3.11+ | — | — | LM Studio or Ollama on localhost |
| B | 3.11+ | 20.10+ + `docker compose` v2 | — | LM Studio or Ollama on host (reached via the audited bridge) |
| C | 3.11+ | — | 1.28+ | Ollama deployment (separate Helm chart or sidecar) |

All shapes assume Linux / macOS / Windows 11 with WSL2 (the multi-host fabric runs in Docker Desktop's WSL2 backend just fine).

---

## (A) Single-host MVP — 60 seconds

```bash
git clone https://github.com/example/plenith.git
cd plenith

# One-shot bootstrap — creates a venv, installs deps, prints next steps
./bootstrap.sh

# Start the honeypot
.venv/bin/python run.py
# Listening on 127.0.0.1:2222
```

In another terminal:

```bash
ssh -p 2222 -o StrictHostKeyChecking=no jdoe@127.0.0.1
# (any password — Plenith accepts the first auth attempt)

# Try the deception
jdoe@bastion-prod:~$ whoami
jdoe
jdoe@bastion-prod:~$ sudo -l
User jdoe may run the following commands:
    (ALL) NOPASSWD: /usr/bin/apt-get
jdoe@bastion-prod:~$ cat /etc/sudoers.d/zzz_compat       # ← decoy
[planted sudoers content]
jdoe@bastion-prod:~$ cat ~/.aws/credentials              # ← honeytoken
[default]
aws_access_key_id = AKIAEFXU7OA4DPKTWRHC
...
jdoe@bastion-prod:~$ exit
```

Now see what fired:

```bash
.venv/bin/python tools/audit.py
# Lists every engagement with severity badge + alert count

.venv/bin/python tools/audit.py <8-char-engagement-id>
# Full incident detail — every command, every alert, every IoC
```

That's it. You've run an SSH honeypot, captured an attacker, and reviewed the engagement.

---

## (B) Multi-host fabric — 5 minutes

The Docker Compose fabric adds: identity proxy with risk scoring, MFA step-up gateway, sealed decoy network with default-DROP egress, content rotation per deployment, OT/ICS decoys (Modbus/S7/DNP3).

```bash
cd linux-fork

# 1. Configure the deployment
cp .env.example .env
# Edit .env:
#   PLENITH_DEPLOYMENT_ID=$(uuidgen)  # pick one, keep it forever
#   PLENITH_CONTENT_EPOCH=2026Q2      # bump quarterly

# 2. Build the images
docker build -f agent/Dockerfile         -t plenith/agent:0.1       ..
docker build -f mfa/Dockerfile           -t plenith/mfa-gateway:0.1 ..
docker build -f mfa/push-sim.Dockerfile  -t plenith/push-sim:0.1    ..

# 3. Bring up the fabric
docker compose up -d

# 4. Confirm isolation
bash isolation/validate.sh
# Expect: ALL PROBES PASSED — 18/18

# 5. Attack it
ssh -p 22000 -o StrictHostKeyChecking=no jdoe@127.0.0.1
# (routed through the identity proxy — risk-scored, MFA-gated if borderline)
```

Watch alerts come in via:

```bash
# Live dashboard at http://127.0.0.1:8765/
python tools/dashboard.py

# Or query the REST API
python tools/api_server.py --port 8080 &
python tools/api_client.py engagements
```

The full end-to-end demo (every alert tier, both rotated decoys planted and swallowed, isolation maintained):

```bash
python linux-fork/tools/demo_attack.py
```

---

## (C) Production (Helm) — 30 minutes

```bash
helm install plenith deploy/helm/plenith/ \
    --set global.deploymentId=$(uuidgen) \
    --set global.contentEpoch=2026Q2 \
    --set proxy.service.type=NodePort \
    --set proxy.service.nodePort=30022 \
    --set mfa.provider=duo \
    --set mfa.duo.host=api-XXXXXXXX.duosecurity.com \
    --set mfa.duo.integrationKey=$DUO_IKEY \
    --set mfa.duo.secretKey=$DUO_SKEY \
    --set connectors.splunkHec.url=https://splunk.example.com:8088 \
    --set connectors.splunkHec.token=$SPLUNK_HEC_TOKEN \
    --set chatops.slack.url=$SLACK_WEBHOOK_URL \
    --set chatops.pagerduty.routingKey=$PAGERDUTY_KEY \
    --set isolation.validateBreakouts.enabled=true \
    --set runtime.runtimeClassName=runsc
```

Helm will print the access URL + the per-cluster setup instructions. The CronJob runs `validate.sh` every 15 minutes, fails the deployment readiness if any of the 18 probes regresses.

---

## Sanity checks (any shape)

```bash
# Tests pass
pytest --ignore=tests/test_isolation.py    # 30s

# CycloneDX SBOM for the audit binder
python tools/sbom.py --validate --out sbom.json

# Compliance attestation
python tools/compliance_report.py --framework soc2 --html attestation.html

# §13 runbooks (data retention, RACI, burndown, DR, capacity, rotation)
python tools/runbook.py all --out docs/runbooks/

# Backup + restore
python tools/backup.py --out /backups/
python tools/restore.py --list
```

---

## Wiring an alert into your existing SIEM

The single most-asked integration question. The answer is the same for any SIEM:

```bash
# 1. Render one alert through every wire format — pick the one your SIEM speaks
python tools/connectors.py demo

# 2. Wire the connector in config.yaml
cat >> config.yaml <<EOF
connectors:
  splunk_hec:
    url:    https://splunk.example.com:8088
    token:  <your-HEC-token>
    index:  plenith
  syslog_udp:
    host:   syslog.example.com
    port:   514
    body_format: cef          # cef | leef | plain
EOF

# 3. Trigger one synthetic alert to confirm
echo '{"action":"alert_credential_exfil","severity":"high","rationale":"test"}' > /tmp/a.json
python tools/connectors.py send /tmp/a.json
```

Same wiring works for Elastic, Datadog, Sumo, Devo, ArcSight, QRadar, LogRhythm.

---

## What to read next

- **`README.md`** — feature matrix vs commercial competitors, project layout
- **`docs/THREAT_MODEL.md`** — STRIDE analysis for procurement / audit teams
- **`docs/adr/`** — the 10 ADRs explaining the big design choices
- **`linux-fork/README.md`** — multi-host fabric overview
- **`Plenith.md`** (parent dir) — Engineering Blueprint v1.1
- **After `python tools/api_server.py`** → `http://localhost:8080/docs` for the live Swagger UI

If something doesn't work as documented, file an issue. The `571-test`-passing suite + the `validate.sh` probe catch regressions before they ship, but the integration with YOUR specific Splunk/Okta/Slack instance is something only you can validate end-to-end on your side.
