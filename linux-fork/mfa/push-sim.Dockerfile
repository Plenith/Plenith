# Push-notification simulator — tiny stdlib HTTP service.
# Pure Python; no third-party deps; ~250 lines total.

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 ca-certificates tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/push-sim
COPY linux-fork/mfa/push_sim.py /opt/push-sim/push_sim.py

EXPOSE 8080

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python3", "/opt/push-sim/push_sim.py"]
