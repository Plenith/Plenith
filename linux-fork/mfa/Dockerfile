# MFA gateway container — minimal asyncssh server for §4.3 step-up.
#
# Same Python + asyncssh layer as the agent image, but with no
# orchestrator code shipped. The gateway is intentionally tiny so it can
# be audited end-to-end as a single file (mfa_gateway.py).

FROM ubuntu:22.04

# Avoid the apt frontend tzdata prompts.
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-venv python3-pip ca-certificates tini \
    && rm -rf /var/lib/apt/lists/*

# PEP 668 — venv inside the container so pip can install freely.
RUN python3 -m venv /opt/mfa-venv \
    && /opt/mfa-venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/mfa-venv/bin/pip install --no-cache-dir asyncssh

ENV PATH="/opt/mfa-venv/bin:${PATH}"

# Ship the gateway sources. proxy_protocol.py is the canonical copy
# from plenith/, duplicated here so the MFA container doesn't need
# the full plenith package on its PYTHONPATH.
WORKDIR /opt/mfa
COPY linux-fork/mfa/totp.py            /opt/mfa/totp.py
COPY linux-fork/mfa/proxy_protocol.py  /opt/mfa/proxy_protocol.py
COPY linux-fork/mfa/enrollment.py      /opt/mfa/enrollment.py
COPY linux-fork/mfa/mfa_gateway.py     /opt/mfa/mfa_gateway.py

# 22  = plain SSH (intra-bubble test path)
# 2200 = PROXY-v1 prefixed traffic from the identity proxy
EXPOSE 22 2200

# tini as PID 1 so signals reap cleanly
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python3", "/opt/mfa/mfa_gateway.py"]
