# Production hardening guide

The defaults in this repo are tuned for "developer can run it on their
laptop." This guide walks you from that baseline to a deployment you
can defend in a procurement review.

Five layers, in the order you should apply them:

1. **Network**: nftables ruleset isolating the decoy bubble.
2. **Container runtime**: seccomp + AppArmor for the agent.
3. **TLS termination + reverse proxy**: real auth in front of the REST API.
4. **Audit-log integrity**: nightly chain verification cron.
5. **Retention enforcement**: daily purge cron.

Order matters — layer 1 contains the blast radius if anything goes
wrong with the others.

---

## 1. Network isolation (decoy bubble)

The bubble is the set of containers an attacker reaches via the SSH
honeypot. Everything inside it is treated as untrusted; the host
running the orchestrator MUST be one network hop away.

### 1.1 Apply the nftables ruleset

```bash
# Edit deploy/network/decoy-bubble-egress.nft FIRST — set:
#   BUBBLE_IFACE, BUBBLE_NET, LLM_HOST/PORT, SIEM_HOST/PORT,
#   MFA_HOST/PORT, NTP_HOST, DNS_RESOLVER, SSH_PROXY_PORT
# to your deployment's values.

sudo nft -f deploy/network/decoy-bubble-egress.nft
sudo nft list ruleset > /etc/nftables.conf       # persist across reboot
sudo systemctl enable nftables
```

### 1.2 Verify isolation

From **inside** the bubble (e.g. exec into a decoy container):

```bash
# Should FAIL — internet is unreachable
curl --max-time 3 -sS https://1.1.1.1 || echo "(blocked — correct)"

# Should FAIL — production LAN is unreachable
curl --max-time 3 -sS http://prod-db.internal:5432 || echo "(blocked — correct)"

# Should SUCCEED — only the LLM endpoint
curl --max-time 5 -sS http://<LLM_HOST>:<LLM_PORT>/v1/models
```

If any allowed flow fails, check the variables at the top of the
`.nft` file. If any disallowed flow succeeds, do NOT proceed —
something is wrong with the ruleset application.

### 1.3 Capture denied flows for the SOC

The rules log dropped packets at `level warn` rate-limited to 10/min.
Forward to your SIEM:

```bash
sudo journalctl -k -f | grep plenith-egress-deny
```

Surges in this log are interesting — they're an attacker actively
trying to escape the bubble.

---

## 2. Container runtime profiles (seccomp + AppArmor)

### 2.1 Seccomp

The seccomp profile (`deploy/security/seccomp-agent.json`) restricts
which syscalls the agent's Python process can make. Even if an
attacker achieves RCE inside the agent, kernel-level escalation paths
(`kexec_load`, `init_module`, `ptrace`, `clone` to a user namespace,
etc.) are blocked.

Apply per container:

```yaml
# docker-compose.yml
services:
  agent:
    security_opt:
      - seccomp=./deploy/security/seccomp-agent.json
      - no-new-privileges:true
```

Or per `docker run`:

```bash
docker run \
  --security-opt seccomp=$(pwd)/deploy/security/seccomp-agent.json \
  --security-opt no-new-privileges:true \
  plenith-agent:latest
```

### 2.2 AppArmor

The AppArmor profile (`deploy/security/apparmor-agent.profile`) adds
path-level mandatory access controls. The agent can read its own code
read-only and write only to `state-docker/`, `state/`, `caches/`,
`logs/`, `/tmp/`. Writes outside those paths are denied — including
to `/etc/passwd`, `/etc/sudoers`, `/root/`, `/home/`.

On Debian / Ubuntu hosts:

```bash
sudo cp deploy/security/apparmor-agent.profile /etc/apparmor.d/plenith-agent
sudo apparmor_parser -r /etc/apparmor.d/plenith-agent
sudo aa-status | grep plenith-agent     # confirm loaded in enforce mode
```

Apply per container:

```yaml
services:
  agent:
    security_opt:
      - apparmor=plenith-agent
```

### 2.3 Verify profiles are active

```bash
# Inside a container with both profiles applied:
docker exec <agent-container> sh -c 'cat /proc/self/attr/current'
# Expected output: something like
#   plenith-agent (enforce)

# Verify seccomp is enabled:
docker exec <agent-container> sh -c 'grep Seccomp /proc/self/status'
# Expected: "Seccomp: 2" (filter mode)
```

### 2.4 Diagnosing denials in production

AppArmor logs to the kernel ring buffer + journal:

```bash
sudo dmesg | grep DENIED
sudo journalctl -k | grep apparmor=DENIED
```

If you see legitimate operations being denied, **don't disable the
profile**. Either:

- Add the path to the profile (`deploy/security/apparmor-agent.profile`),
  re-load, ship a PR with a justification, OR
- Refactor the agent to not need that path.

The right answer is almost always the former. Profile drift is the
fastest path to "everyone disables it after one incident."

---

## 3. TLS termination + reverse proxy

The REST API (`plenith/api/server.py`) ships with bearer-token auth
but no TLS. In production it MUST run behind a reverse proxy that:

- Terminates TLS with a real (non-self-signed) certificate.
- Adds rate limits (`limit_req` in nginx, `rate_limit` in Caddy).
- IP-whitelists trusted consumers (your SIEM, SOAR, dashboards).
- Logs every request to your standard access-log pipeline.

### 3.1 Sample nginx config

```nginx
# /etc/nginx/sites-available/plenith
upstream plenith_api {
    server 127.0.0.1:8000;
    keepalive 32;
}

limit_req_zone $binary_remote_addr zone=plenith_api:10m rate=20r/s;

server {
    listen 443 ssl http2;
    server_name plenith-api.internal;

    ssl_certificate     /etc/ssl/certs/plenith.pem;
    ssl_certificate_key /etc/ssl/private/plenith.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    # Restrict to your trusted consumers (SIEM, SOAR, dashboards).
    allow 10.10.0.0/24;
    deny  all;

    location / {
        limit_req zone=plenith_api burst=40 nodelay;

        proxy_pass http://plenith_api;
        proxy_set_header Host             $host;
        proxy_set_header X-Real-IP        $remote_addr;
        proxy_set_header X-Forwarded-For  $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Don't buffer SSE / streaming responses
        proxy_buffering off;
        proxy_read_timeout 86400;
    }

    # /metrics is for Prometheus only — separate ACL
    location = /metrics {
        allow 10.10.0.20;     # your Prometheus host
        deny  all;
        proxy_pass http://plenith_api;
    }
}
```

Reload nginx after the cert is in place:

```bash
sudo nginx -t && sudo systemctl reload nginx
```

### 3.2 Caddy alternative

```caddy
plenith-api.internal {
    @trusted remote_ip 10.10.0.0/24
    reverse_proxy @trusted 127.0.0.1:8000

    rate_limit {
        zone plenith { window 1m events 1200 }
    }

    handle @trusted {
        respond "forbidden" 403
    }
}
```

Caddy handles cert provisioning automatically if your DNS supports it.

---

## 4. Audit-log integrity (chain verification)

The audit chain (`plenith/audit_chain.py`) makes on-disk tampering
detectable. The verifier is `tools/verify_chain.py`. To convert
"detectable" into "detected", run it on a cron.

### 4.1 Daily verification cron

```cron
# /etc/cron.d/plenith-verify-chain
SHELL=/bin/bash
PATH=/usr/bin:/bin

0 4 * * * plenith /opt/plenith/.venv/bin/python \
          /opt/plenith/tools/verify_chain.py \
          --json \
          /opt/plenith/state-docker/logs/ \
          > /var/log/plenith/chain-status.json 2>&1
```

### 4.2 Surface to Prometheus

The alert `PlenithAuditChainBroken` (in
`deploy/prometheus/alerts.yml`) fires on
`plenith_audit_chain_ok == 0`. Expose this gauge via the textfile
collector:

```bash
# Helper at /usr/local/bin/plenith-chain-textfile
#!/bin/bash
set -euo pipefail
RESULT=$(/opt/plenith/.venv/bin/python \
         /opt/plenith/tools/verify_chain.py --json \
         /opt/plenith/state-docker/logs/ 2>/dev/null || echo '{"broken":1}')

BROKEN=$(echo "$RESULT" | python -c 'import json,sys; print(json.load(sys.stdin)["broken"])')
OK_VALUE=1
[ "$BROKEN" -gt 0 ] && OK_VALUE=0

cat <<EOF > /var/lib/node_exporter/textfile/plenith_audit.prom
# HELP plenith_audit_chain_ok Chain verification status (1=ok, 0=broken).
# TYPE plenith_audit_chain_ok gauge
plenith_audit_chain_ok ${OK_VALUE}
EOF
```

Run it on the same cron interval as the verifier. The alert fires
within Prometheus's next evaluation window.

### 4.3 Once the rollout is complete

After every running agent has been on a chain-aware version for 90+
days, no legacy logs should remain in the working window. Tighten the
cron to refuse legacy logs:

```cron
0 4 * * * plenith /opt/plenith/.venv/bin/python \
          /opt/plenith/tools/verify_chain.py --no-allow-legacy ...
```

---

## 5. Retention enforcement

The retention policy in `docs/DATA_HANDLING.md` is just a document
until something deletes data. That something is
`tools/retention_purge.py`.

### 5.1 Daily purge cron

```cron
# /etc/cron.d/plenith-retention
SHELL=/bin/bash
PATH=/usr/bin:/bin

15 4 * * * plenith /opt/plenith/.venv/bin/python \
          /opt/plenith/tools/retention_purge.py \
          --apply --json \
          > /var/log/plenith/retention-$(date +\%Y-\%m-\%d).log 2>&1
```

### 5.2 Verify it's working

After a week, you should see files at the retention boundary getting
deleted. Spot-check:

```bash
# Anything older than the policy window should be gone.
find /opt/plenith/state-docker/logs -mtime +90 -type f | head
# Expected: empty.
```

### 5.3 Subject access request fulfillment

If you receive a DSR / erasure request for a specific identifier:

```bash
# First, dry-run — see what would be deleted.
python tools/retention_purge.py \
  --filter source_ip=<IP> --json

# Then apply with the safety interlock.
python tools/retention_purge.py \
  --apply --confirm --filter source_ip=<IP>
```

The `--confirm` flag is required when combining `--apply` with
`--filter` — see `tools/retention_purge.py` for the rationale.

---

## Verification checklist

After hardening, walk through this list before declaring production-
ready:

- [ ] `sudo nft list table inet plenith` shows the bubble ruleset
      loaded.
- [ ] From inside a bubble container, you can reach the LLM/SIEM/MFA
      hosts and **nothing else**.
- [ ] `docker inspect <agent-container> | grep -i seccomp` shows
      `seccomp-agent.json` applied.
- [ ] `sudo aa-status` lists `plenith-agent` in enforce mode.
- [ ] The REST API answers on the reverse-proxy URL (HTTPS); direct
      hits on `127.0.0.1:8000` are not reachable from non-loopback.
- [ ] `tools/verify_chain.py` reports `0 BROKEN` against the engagement
      log directory.
- [ ] After 24h, `plenith_audit_chain_ok` is in Prometheus and
      `PlenithAuditChainBroken` does not fire.
- [ ] After 7d, `find state-docker/logs -mtime +<retention_days>` is
      empty.
- [ ] `gh attestation verify <release.tar.gz>` succeeds against the
      release tag you've deployed.

---

## What's NOT in this guide

These are deployment-specific or hold-the-line items that this repo
can't generalize for you:

- **Egress to the LLM provider**, if you use a cloud LLM. Treat it as
  a sub-processor under your DPA.
- **Host-level antivirus** / EDR — your standard host stack.
- **Backup encryption** — `tools/backup.py` produces tarballs;
  encrypt them at rest with your existing tooling.
- **Vault / SOPS / AWS Secrets Manager integration for `config.yaml`** —
  not built in. The config file is plain YAML; if you want secrets
  pulled from a manager, write a small wrapper that templates
  `config.yaml` from your secrets backend.
- **24×7 SOC integration** — out of scope for this doc.

For anything not covered: file an issue describing the gap, and we'll
either document the recommended pattern or add the missing piece.
