# Plenith agent spec

The single-host Windows MVP becomes a per-decoy-host **agent** by adding a thin layer of env-driven configuration and a shared StateStore volume. The orchestrator core is unchanged.

## What changes from the MVP

| Concern | MVP | Agent |
|---|---|---|
| `config.yaml` | committed to repo | rendered at startup from env vars (`PLENITH_*`) |
| `personas_dir` | local `personas/` | bind-mounted `/opt/plenith/personas` (one persona per agent role) |
| `state_dir` | local `state/persistence/` | **shared volume** mounted at `/mnt/state`, written-to by every agent in the topology |
| `llm.base_url` | `http://localhost:1234/v1` (LM Studio) | `http://llm-gw:11434/v1` (Ollama on the GPU node) |
| `ssh.host` | `127.0.0.1` | `0.0.0.0` (container network only — outer firewall still drops external) |
| Honeytokens | per-engagement RNG seeded by `engagement_id` | **same** — and because state is shared, an attacker who reads `~/.aws/credentials` on `bastion-prod` sees the **identical** body if they `ssh db-prod-01` and re-read it |

## The shared-state insight

The single most important property of the agent design: **engagement state is keyed by `(source_ip, claimed_user)`, NOT by hostname**. So when an attacker SSHs into `bastion-prod` as `agarcia`, fingers a credential, and then `ssh db-prod-01`, the `db-prod-01` agent — which sees the inbound connection from `bastion-prod`'s internal IP — uses `(bastion-prod-internal-ip, jdoe)` (or whatever claimed_user they used) as its key.

This means **the attacker's apparent "lateral movement" is recorded as a NEW engagement on `db-prod-01`**, not a continuation of the bastion-prod engagement. That's actually what we want for the audit story — the operator sees one engagement per hop. To correlate them, the audit tool's `--export-ioc` mode emits the source IP, and the operator joins on `source_ip` across engagements.

For the simpler use case (true single-attacker, multi-host), the spec to add later is a "campaign ID" — derived from JA3 + claimed-user — that ties engagements across hosts. That's a v2 fork-of-the-fork.

## Entrypoint script (sketch)

```bash
#!/bin/bash
set -e

# Render config.yaml from env vars.
cat > /opt/plenith/config.yaml <<EOF
ssh:
  host: 0.0.0.0
  port: 2222
  banner: "Ubuntu 22.04.4 LTS"
  host_key_path: /mnt/state/ssh_host_key_${PLENITH_HOSTNAME}

llm:
  base_url: ${PLENITH_LLM_URL}
  model: llama3.1:8b
  api_key: ollama
  temperature: 0.3
  max_tokens: 512
  timeout_seconds: 60

paths:
  personas_dir: /opt/plenith/personas
  cache_file:   /opt/plenith/caches/default_responses.yaml
  logs_dir:     /mnt/state/logs/${PLENITH_HOSTNAME}
  state_dir:    /mnt/state/persistence

session:
  prompt: "{user}@${PLENITH_HOSTNAME}:{cwd}\$ "
EOF

# If the agent has fake services to expose alongside SSH (mysqld, https):
# kick off a sidecar for each. These are NOT real services; they're tiny
# Python listeners that respond with the planted /etc/mysql/my.cnf banner
# etc. Their lifecycle is independent of the orchestrator.
if [ -n "$PLENITH_FAKE_SERVICES" ]; then
  python3 /opt/plenith/tools/fake_service.py "$PLENITH_FAKE_SERVICES" &
fi

# Run the orchestrator in the foreground; container stops when it stops.
exec python3 /opt/plenith/run.py
```

(The above is a sketch — `tools/fake_service.py` would be a small TCP-binding wrapper that's NOT in this MVP but is the next piece to add for the Linux fork.)

## Per-agent persona selection

The agent picks its persona from `PLENITH_PERSONA` env var. The persona's `hostname` field should be left blank in the YAML and filled in at runtime from `PLENITH_HOSTNAME`.

For the topology in `../containerlab/topology.yaml`:

| Container | Persona | Hostname | Role |
|---|---|---|---|
| `bastion-prod` | `agarcia` | `bastion-prod` | SRE jumphost |
| `db-prod-01` | `jdoe` | `db-prod-01` | Application DB |
| `api-prod-03` | `jdoe` | `api-prod-03` | Application server |

A 4th container could host `mwilson` on a fake `siem-prod` for an SecOps decoy — useful for catching attackers who pivot toward detection infrastructure to disable it.

## What does NOT need to change in the orchestrator

- `plenith/vfs.py` — canonical paths, same.
- `plenith/heuristics.py` — same 14 rules.
- `plenith/responses.py` — same plant executors.
- `plenith/synthetic.py` — same generators.
- `plenith/sim_bot.py` — same; each agent boots its own bot from the persona list, which produces consistent `who`/`w` across all containers because the seed is deterministic.
- `plenith/state_store.py` — same atomic file model. Since multiple agent processes share the volume, atomic-rename gives us last-writer-wins semantics, which is fine because each engagement is keyed by `(ip, user)` and only one agent at a time talks to a given pair.

## Open questions for a real deployment

1. **JA3 fingerprint as part of the engagement key** — would tie multi-host hops by the same attacker. Adds value, requires asyncssh extension to expose the TLS fingerprint (it's an SSH protocol so JA3 doesn't quite apply; you'd use SSH banner + KEX algorithm prefs as a proxy).

2. **Agent-to-agent gossip** — when an alert fires on bastion-prod, should db-prod-01 pre-elevate its attacker-state block in anticipation? For most setups: no, the per-engagement state is enough.

3. **GPU contention** — three agents hitting one Ollama at the same time means three concurrent inference requests. `llama3.1:8b` Q4 on a 3090 handles ~2 concurrent comfortably, ~3 with latency growth. For >3 hosts, batch or scale the LLM tier.
