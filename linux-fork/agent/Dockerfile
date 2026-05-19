# Plenith per-host decoy agent.
#
# Build from the plenith-mvp ROOT (one level above linux-fork/):
#     cd plenith-mvp
#     docker build -f linux-fork/agent/Dockerfile -t plenith/agent:0.1 .
#
# Build context = the entire plenith-mvp directory. The .dockerignore at
# the root excludes .venv, state/, logs/, __pycache__, tests/, etc. so the
# build doesn't pull in dev artifacts.

# ubuntu:24.04 ships Python 3.12. ubuntu:22.04 ships 3.10, which is
# BELOW this project's own supported floor (README CI matrix: Python
# 3.11-3.14) — the codebase uses 3.11+ APIs (e.g. datetime.UTC in
# sim_bot/orchestrator/connectors), so a 22.04 build crash-loops at
# runtime. Aligned to the supported floor; all apt packages below
# exist on 24.04 and the venv flow is unchanged.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Layer 1: OS-level tools the agent presents to attackers. They are real
# binaries inside the container so timing on `nmap`/`curl`/`ssh` matches
# real Linux (covers the latency-fingerprint constraint from blueprint §5.3.1).
# `binutils` brings `strings`. `ca-certificates` for curl to TLS endpoints.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-venv python3-pip \
        openssh-server openssh-client \
        iproute2 net-tools dnsutils \
        curl wget vim less procps psmisc \
        file binutils openssl jq tcpdump \
        ca-certificates tini \
    && rm -rf /var/lib/apt/lists/*

# Layer 2: python deps inside a venv. Ubuntu 22.04 PEP 668-marks the system
# python as "externally managed"; the venv sidesteps that cleanly and is
# tidier than `--break-system-packages`.
ENV VIRTUAL_ENV=/opt/plenith-venv \
    PATH="/opt/plenith-venv/bin:$PATH"
RUN python3 -m venv "$VIRTUAL_ENV" \
    && pip install --upgrade pip \
    && pip install \
        asyncssh==2.18.0 \
        httpx==0.27.2 \
        pyyaml==6.0.2

# Layer 3: copy the orchestrator. Paths are relative to the build context
# (plenith-mvp/), NOT to the Dockerfile.
COPY plenith/      /opt/plenith/plenith/
COPY caches/          /opt/plenith/caches/
COPY personas/        /opt/plenith/personas/
COPY run.py           /opt/plenith/run.py
COPY linux-fork/tools/fake_service.py  /opt/plenith/linux-fork/tools/fake_service.py

# Entrypoint. Normalize CRLF in case it was edited on Windows, and make
# it executable.
COPY linux-fork/agent/agent-entrypoint.sh  /usr/local/bin/agent-entrypoint
RUN sed -i 's/\r$//' /usr/local/bin/agent-entrypoint \
    && chmod +x /usr/local/bin/agent-entrypoint

WORKDIR /opt/plenith

# Each agent binds 2222 inside the container. Containerlab's bridge handles
# routing — the identity proxy in front maps external SSH connections to
# the appropriate agent's 2222.
EXPOSE 2222

# Use tini as PID 1 so signal handling / zombie reaping is correct, and so
# Ctrl-C against the foreground agent process propagates cleanly.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/agent-entrypoint"]
