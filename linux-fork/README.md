# Linux fork — multi-host decoy network (preview, not runnable)

This directory is the **architecture scaffold** for the next phase of Plenith: a multi-host deception network running on Linux + Docker + Containerlab. Nothing here is runnable on the Windows MVP host. It's the blueprint and templates for the team that picks up §4.2 + §5.4 of the Engineering Blueprint.

The single-host Windows MVP (one Python process, one persona at a time) is the **reference implementation** of the orchestrator core. This fork shows how to scale it horizontally onto a fake VLAN.

---

## What "the Linux fork" adds vs. the MVP

| Aspect | Windows MVP | Linux fork |
|---|---|---|
| Hosts | 1 (Python process) | N (Containerlab topology, one container per decoy host) |
| Isolation | None (host process) | VLAN, default-DROP egress, DNS isolation, gVisor or Firecracker microVM — see `isolation/README.md` for the four pillars implemented |
| Front-end | None — direct SSH to honeypot | Identity proxy (Nginx + Lua) routes by risk score |
| Personas | 1 per connection | 1 per decoy host; routing by claimed username |
| LLM | LM Studio on the dev machine | Ollama on a GPU-attached node, shared by all agents |
| Monitoring | `tools/audit.py` against local JSON | Wazuh + T-Pot, IoCs shipped to real SIEM via unidirectional gateway |
| Persistence | `state/persistence/*.json` | Same file format, on a shared volume mounted by every agent |
| Action execution | VFS writes only | VFS writes + per-host service spawning (e.g. spawn a real fake MySQL in a sibling container) |

The single-host MVP is correct for proving the loop. The Linux fork is what you build to put it in front of real attackers.

---

## Directory layout

```
linux-fork/
├── README.md                          # this file
├── docker-compose.yml                 # 6-service isolated fabric (default)
├── docker-compose.gvisor.yml          # runtime override → runsc / gVisor (production-Linux only)
├── containerlab/
│   └── topology.yaml                  # legacy 3-host decoy network spec
├── agent/
│   ├── Dockerfile                     # containerizes the orchestrator
│   ├── agent-entrypoint.sh
│   └── AGENT_SPEC.md
├── isolation/                         # §4.2 Isolation Design — see README inside
│   ├── README.md                      # ← four-pillar overview, debug playbook
│   ├── Corefile                       # CoreDNS: synthetic decoy zone, no external recursion
│   ├── llm-egress.conf                # nginx: only audited egress path from the bubble
│   └── validate.sh                    # 18-probe continuous breakout test
├── mfa/                               # §4.3 MFA step-up — interactive TOTP challenger
│   ├── Dockerfile                     # tiny Python + asyncssh container
│   ├── mfa_gateway.py                 # asyncssh server, decision-file handoff
│   └── totp.py                        # RFC 6238 (stdlib only)
├── routing/
│   ├── ROUTING_SPEC.md                # front-end risk engine + identity proxy spec
│   ├── nginx.conf                     # OpenResty stream + Lua hook
│   ├── init.lua                       # geo/rep seed data
│   └── score_and_route.lua            # risk-scoring + .pass/.fail consumption + pool selection
└── tools/
    ├── fake_service.py                # sidecar fake-mysql + fake-http listeners
    ├── demo_attack.py                 # full attacker run-through the proxy
    └── demo_mfa.py                    # three-tier routing demo (real-prod / MFA / plenith)
```

---

## Reading order

1. **`containerlab/topology.yaml`** — the lab topology. Three "production" hosts the attacker can move between, plus a bastion as the entry point.
2. **`agent/AGENT_SPEC.md`** — how the existing Python orchestrator is wrapped into a per-host agent. Spoiler: the orchestrator stays mostly as-is; the persona file becomes per-container, and the StateStore mounts a shared volume.
3. **`routing/ROUTING_SPEC.md`** — the identity proxy that decides which host an inbound session lands on. This is the §5.1 piece of the blueprint, not present in the MVP at all.

---

## What's deliberately NOT here

- **No actual Dockerfile** beyond a stub — the production Dockerfile depends on the Linux base image (Ubuntu 22.04 LTS) and the Ollama endpoint config, which are environment-specific.
- **No real Nginx + Lua proxy code.** The routing spec describes the decision logic; the actual Lua module is a separate sub-project (~200 lines).
- **No T-Pot / Wazuh integration.** That's a deployment-time task, not a code-time task — you bring up T-Pot per its own runbook and point our session-log writer at the T-Pot Elasticsearch endpoint via a new `cfg["telemetry"]` config block.

---

## Prerequisites for actually running this

- Linux host (Ubuntu 22.04+ recommended) — see "WSL2 caveat" below before you try this on Docker Desktop
- Docker 20.10+ with `docker compose` v2
- [Containerlab](https://containerlab.dev) 0.50+
- A GPU node running [Ollama](https://ollama.com) with `llama3.1:8b` (or compatible)
- Optional: T-Pot stack for monitoring, Wazuh for IoC export
- Optional: separate VLAN or VRF for the decoy bubble (avoids egress to real infra)

A reasonable host: 1× server with 16+ CPU cores, 64 GB RAM, RTX 3090 (24 GB VRAM) for Ollama, 1 TB NVMe. Budget ~$2k as the blueprint's §6.1 BoM specifies.

### WSL2 caveat (developer convenience deploy)

Running this stack on a **Windows host via WSL2 + Docker Desktop** works partially:

- ✅ The agent image builds cleanly.
- ✅ `docker compose up` from `linux-fork/docker-compose.yml` brings up the 3-host fabric + Nginx-Lua proxy. Cross-agent lateral SSH works. The proxy routes by risk score correctly.
- ❌ `containerlab deploy -t containerlab/topology.yaml` does NOT work end-to-end. Containerlab uses netlink to manage Linux bridges; under Docker Desktop's WSL2 backend, the Docker daemon runs in a separate distro from where Containerlab runs, and the netlink primitives don't cross that boundary cleanly. Containers either fail to attach to their network namespace, or exit before clab can manage them.

**Recommendation for dev work**: use `docker compose` on WSL2. The functional behavior is the same as what Containerlab would give you for a 3-host all-Docker topology. Containerlab's real value-add (vrnetlab integration, complex L2 topologies, per-link VLAN tagging) only matters once you're modeling network-layer attacks too.

**Recommendation for production**: run on a native Linux host. Containerlab works as documented there.

---

## How this maps back to the Engineering Blueprint

| Blueprint section | Where in linux-fork |
|---|---|
| §4.1 Architecture diagram | `containerlab/topology.yaml` is the realized version |
| §4.2 Isolation Design | **`isolation/README.md`** — four pillars implemented end-to-end with a continuous-validation probe (18/18 green) |
| §4.3 Credential-Compromised Attack Flow + MFA step-up | `mfa/mfa_gateway.py` + `routing/score_and_route.lua` (see "MFA step-up" section of `routing/ROUTING_SPEC.md`) |
| §5.1 Smart Identity Proxy | `routing/ROUTING_SPEC.md` |
| §5.2 Deception Orchestrator V1 | Existing MVP, containerized per `agent/AGENT_SPEC.md` |
| §5.3 Self-Hosted LLM | Ollama node; agents point at it via `cfg["llm"]["base_url"]` |
| §5.4 Decoy Factory | `containerlab/topology.yaml` |
| §5.5 Synthetic user simulation | Existing MVP `sim_bot.py`; shared state across containers |
| §5.6 Monitoring | T-Pot / Wazuh sidecar, IoC export via `tools/audit.py --export-ioc` |

The bulk of the orchestrator code does NOT change. The fork is mostly infrastructure plumbing around the existing platform.
