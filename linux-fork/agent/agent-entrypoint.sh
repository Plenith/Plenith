#!/bin/bash
#
# Plenith per-host agent entrypoint.
#
# Reads env vars passed by Containerlab / docker run:
#   PLENITH_PERSONA       (required: jdoe / agarcia / mwilson)
#   PLENITH_HOSTNAME      (required: db-prod-01 / bastion-prod / etc.)
#   PLENITH_LLM_URL       (default: http://llm-gw:11434/v1)
#   PLENITH_LLM_MODEL     (default: llama3.1:8b)
#   PLENITH_SHARED_STATE  (default: /mnt/state)
#   PLENITH_SSH_PORT      (default: 2222)
#   PLENITH_FAKE_SERVICES (optional, comma-separated: mysql:3306,http:80)
#
# Renders config.yaml from these, optionally starts fake-service listeners
# as background processes, then execs the orchestrator in the foreground.

set -e

# Mandatory env vars
: "${PLENITH_PERSONA:?PLENITH_PERSONA must be set (jdoe / agarcia / mwilson)}"
: "${PLENITH_HOSTNAME:?PLENITH_HOSTNAME must be set (e.g. db-prod-01)}"

# Defaults
: "${PLENITH_LLM_URL:=http://llm-gw:11434/v1}"
: "${PLENITH_LLM_MODEL:=llama3.1:8b}"
: "${PLENITH_SHARED_STATE:=/mnt/state}"
: "${PLENITH_SSH_PORT:=2222}"
: "${PLENITH_LLM_TIMEOUT:=60}"
: "${PLENITH_LLM_TEMPERATURE:=0.3}"
# When the identity proxy enables `proxy_protocol on;` (it does), each
# inbound connection prepends a PROXY-v1 header naming the real client
# IP. We listen on a SEPARATE port for those — plain SSH on $PLENITH_SSH_PORT
# continues to work for lateral movement inside the bubble. The proxy
# targets this port on every backend.
: "${PLENITH_PROXY_PROTOCOL_PORT:=2200}"
export PLENITH_PROXY_PROTOCOL_PORT

# Content rotation: when PLENITH_DEPLOYMENT_ID is set, every agent on
# this fabric shares one corp identity (so prod-db-01 and prod-api-03
# advertise the same fake "Acme Corp" / db creds / etc.). Bump
# PLENITH_CONTENT_EPOCH quarterly to rotate every artifact at once.
: "${PLENITH_DEPLOYMENT_ID:=}"
: "${PLENITH_CONTENT_EPOCH:=default}"

# Wait for the shared state dir to exist (Containerlab sometimes brings
# containers up before the bind mount stabilizes).
for i in 1 2 3 4 5; do
  if [ -d "${PLENITH_SHARED_STATE}" ]; then break; fi
  echo "waiting for shared state dir ${PLENITH_SHARED_STATE}..."
  sleep 1
done
mkdir -p "${PLENITH_SHARED_STATE}/persistence"
mkdir -p "${PLENITH_SHARED_STATE}/logs/${PLENITH_HOSTNAME}"

# Render config.yaml in-place. We use a heredoc with `EOF` (no expansion
# control) so the shell variables interpolate.
cat > /opt/plenith/config.yaml <<EOF
ssh:
  host: 0.0.0.0
  port: ${PLENITH_SSH_PORT}
  banner: "Ubuntu 22.04.4 LTS"
  host_key_path: ${PLENITH_SHARED_STATE}/ssh_host_key_${PLENITH_HOSTNAME}

llm:
  base_url: ${PLENITH_LLM_URL}
  model: ${PLENITH_LLM_MODEL}
  api_key: ollama
  temperature: ${PLENITH_LLM_TEMPERATURE}
  max_tokens: 512
  timeout_seconds: ${PLENITH_LLM_TIMEOUT}

paths:
  personas_dir: /opt/plenith/personas
  cache_file:   /opt/plenith/caches/default_responses.yaml
  logs_dir:     ${PLENITH_SHARED_STATE}/logs/${PLENITH_HOSTNAME}
  state_dir:    ${PLENITH_SHARED_STATE}/persistence

session:
  prompt: "{user}@${PLENITH_HOSTNAME}:{cwd}\$ "
  default_cwd: /home/{user}
  max_commands_per_session: 500

content:
  deployment_id: "${PLENITH_DEPLOYMENT_ID}"
  epoch: "${PLENITH_CONTENT_EPOCH}"
EOF

echo "=== Plenith agent ${PLENITH_HOSTNAME} (persona=${PLENITH_PERSONA}) ==="
echo "    LLM:         ${PLENITH_LLM_URL}  (${PLENITH_LLM_MODEL})"
echo "    State dir:   ${PLENITH_SHARED_STATE}"
echo "    SSH port:    ${PLENITH_SSH_PORT}"
if [ -n "${PLENITH_DEPLOYMENT_ID}" ]; then
  echo "    Rotation:    deployment=${PLENITH_DEPLOYMENT_ID} epoch=${PLENITH_CONTENT_EPOCH}"
else
  echo "    Rotation:    DISABLED (set PLENITH_DEPLOYMENT_ID to enable)"
fi

# Optional: fake-service sidecars for non-SSH protocols. These bind extra
# ports inside the container and respond with the planted banners/configs.
# Format: comma-separated PROTO:PORT entries.
if [ -n "${PLENITH_FAKE_SERVICES}" ]; then
  echo "    Fake services: ${PLENITH_FAKE_SERVICES}"
  python3 /opt/plenith/linux-fork/tools/fake_service.py \
    --hostname "${PLENITH_HOSTNAME}" \
    --state-dir "${PLENITH_SHARED_STATE}" \
    "${PLENITH_FAKE_SERVICES}" &
  FAKE_SVC_PID=$!
  trap "kill ${FAKE_SVC_PID} 2>/dev/null || true" EXIT INT TERM
fi

# Make the chosen persona the only one visible to the orchestrator. We
# rename other persona YAMLs out of the way so auto-discovery only picks up
# this agent's role.
PERSONA_KEEP="/opt/plenith/personas/${PLENITH_PERSONA}.yaml"
if [ ! -f "${PERSONA_KEEP}" ]; then
  echo "ERROR: persona file not found at ${PERSONA_KEEP}" >&2
  ls -la /opt/plenith/personas/ >&2
  exit 1
fi

# (Optional refinement: instead of hiding, we could KEEP the other personas
# so `who`/`/etc/passwd`/sim_bot still reflect the multi-user fleet. That's
# the production setup. For per-host single-persona simplicity right now
# we keep all of them and the orchestrator routes new sessions to whatever
# username the attacker claimed.)

# Hand off to the orchestrator. SIGTERM-able.
cd /opt/plenith
exec python3 run.py
