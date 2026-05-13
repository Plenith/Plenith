# Isolation Design — §4.2 Implementation

This directory holds the concrete realization of **Engineering Blueprint §4.2 (Isolation Design)** for the dev fork. The blueprint specifies five pillars; this fork implements four directly and substitutes the fifth.

| Pillar | Blueprint says | Dev fork implements | File |
| :--- | :--- | :--- | :--- |
| Network | Separate VLAN/VRF/ns; default-DROP egress; allowlist proxy ingress only | Docker `internal: true` bridge + DMZ for audited bridges | `../docker-compose.yml` |
| DNS | Dedicated resolver; block external recursion; log queries (covert channel) | CoreDNS with `hosts` plugin + no `forward`; structured query log | `Corefile` |
| Time | Internal NTP only; never query real NTP | Inherits container kernel clock; external NTP unreachable via the network lockdown | (no service needed) |
| Compute | Firecracker / Kata microVM for high-risk decoys | gVisor (`runsc`) — userspace kernel; same threat surface story | `../docker-compose.gvisor.yml` |
| Continuous validation | Automated breakout tests on every deploy | `validate.sh` runs 18 probes from each agent | `validate.sh` |

The egress bridge to LM Studio is the one and only audited path out of the bubble.

```
                   Windows host (LM Studio :1234)
                              │
                       host.docker.internal
                              │
       ┌──────────────────────┴──────────────────────┐
       │            bridge_net (NAT, route)          │
       │   ┌──────────────────┐   ┌──────────────┐   │
       │   │ plenith-proxy │   │ llm-egress   │   │
       │   │ (OpenResty stream)   │ (nginx       │   │
       │   │ Lua risk scoring)│   │ allow-list)  │   │
       │   └──────┬───────────┘   └────┬─────────┘   │
       └──────────┼─────────────────────┼────────────┘
                  │                     │
       ┌──────────┼─────────────────────┼────────────┐
       │     decoy_net (internal:true)  │            │
       │          │                     │            │
       │   ┌──────▼──────┐    ┌─────────▼──────┐     │
       │   │ bastion     │    │ llm.internal   │     │
       │   │ db-prod-01  │◄───┤ (alias of      │     │
       │   │ api-prod-03 │    │  llm-egress)   │     │
       │   │ real-prod   │    └────────────────┘     │
       │   │ mfa         │                           │
       │   │             │    ┌────────────────┐     │
       │   │             │◄───┤ dns.internal   │     │
       │   │             │    │ (CoreDNS,      │     │
       │   │             │    │  no forward)   │     │
       │   └─────────────┘    └────────────────┘     │
       └─────────────────────────────────────────────┘
```

---

## How to verify it's working

```bash
docker compose up -d
bash isolation/validate.sh
# … expect: ALL PROBES PASSED — 18/18
```

The probe set runs from each of the three real agents:

| # | Probe | Expected |
| :--- | :--- | :--- |
| 1 | `curl https://www.google.com` | Connect fails (no host route, no DNS) |
| 2 | `dig @8.8.8.8 google.com` | Times out (8.8.8.8 unreachable) |
| 3 | `nslookup google.com 172.30.0.40` | NXDOMAIN or SERVFAIL (no forward plugin) |
| 4 | `python3 socket.connect((8.8.8.8, 53))` | Raises (no route to host) |
| 5 | `nslookup db-prod-01 172.30.0.40` | Returns 172.30.0.11 (synthetic A-record) |
| 6 | `curl http://llm.internal:1234/v1/models` | Returns HTTP/1.1 200 OK (LLM relay alive) |

Probe 5 must always succeed because **lateral movement inside the bubble is the engagement** — the attacker SSHing from bastion to db-prod-01 has to *actually reach* db-prod-01 for the deception to feel real. Isolation is at the bubble's edge, not between containers.

---

## What the DNS log catches

Tail the CoreDNS log while running attacker traffic:

```bash
docker logs -f plenith-dns
```

You'll see lines like:

```
[INFO] 172.30.0.10 A db-prod-01.        -> NOERROR    # legit lateral lookup
[INFO] 172.30.0.10 A google.com.        -> NXDOMAIN   # external attempt
[INFO] 172.30.0.10 A data.x.oast.live.  -> NXDOMAIN   # ★ covert DNS exfil ★
[INFO] 172.30.0.10 A AAAA-base64-blob.  -> NXDOMAIN   # ★ very likely exfil ★
```

Anything that returns `-> NXDOMAIN` and looks structured (long subdomain, base64-like chars, repeated TLD `.oast.live`/`.burpcollaborator.net`/`.interactsh.com`) is a covert exfiltration channel. The orchestrator's `alert_dns_exfil` heuristic already catches the obvious `curl host/$(cat …)` form at the shell level; this log catches the cases where the attacker uses `dig` or `nslookup` directly to encode data in query names — which the shell-level heuristic can't see.

---

## What's NOT here vs. the blueprint

- **Real VLAN tagging.** `internal: true` is logical-only on a single host. To get real L2 isolation you need a managed switch and an actual VRF, which is a deployment-time concern handled by network-engineering, not by this repo.
- **Egress firewall on `bridge_net`.** In production, lock down `bridge_net` at the host iptables level: allow only outbound to the Ollama/LLM endpoint, deny everything else. The dev fork relies on Docker's default bridge behavior plus the nginx URI allow-list inside `llm-egress`.
- **microVM for real.** gVisor is a substitute for Firecracker/Kata. Same threat-model intent (intercept syscalls before the host kernel sees them), different mechanism (userspace kernel vs. KVM microVM). Use `docker-compose.gvisor.yml` on production Linux for the real thing.
- **Internal NTP server.** The bubble's `internal: true` setting already blocks outbound 123/udp. Containers inherit the host kernel clock; no agent code reads the wall clock for security purposes. We could add a chrony container in stratum-orphan mode for full pillar-completeness, but it adds no real defense for this workload.

---

## Failure modes & how to debug

| Symptom | Likely cause | Fix |
| :--- | :--- | :--- |
| `validate.sh` says all egress unblocked | Agents are still on the old bridge | `docker compose down && docker compose up -d` |
| Internal nslookup returns NXDOMAIN | CoreDNS Corefile or container is stale | `docker compose restart dns` then re-check `docker exec bastion-prod cat /etc/resolv.conf` — should show `172.30.0.40` |
| `llm.internal /v1/models` returns 502 | LM Studio not running on host or `host.docker.internal` resolution broke | `curl http://localhost:1234/v1/models` from Windows; confirm LM Studio server is up |
| Agents can't reach each other | The new compose has fixed IPs; if you previously had a `plenith_decoy_net` with different IPAM, recreate the network: `docker network rm plenith_decoy_net && docker compose up -d` |

---

## How this maps back to the blueprint

| §4.2 sub-clause | Where in this fork |
| :--- | :--- |
| "separate VLAN/VRF/namespace" | `decoy_net` is a separate Docker bridge with no NAT |
| "default-DROP egress" | `internal: true` on `decoy_net` = no MASQUERADE rule installed |
| "allowlist only the proxy ingress path" | Only `plenith-proxy` has `ports:` mapped from the host |
| "dedicated resolver for the decoy bubble" | `dns` service, alias `dns.internal` |
| "block external DNS" | No `forward` plugin in `Corefile` — there is no recursion path |
| "log all queries (covert exfil channel)" | `log . "{remote} {type} {name} -> {rcode}"` in `Corefile` |
| "internal NTP only" | Outbound 123/udp blocked by `internal: true`; containers use host clock |
| "microVM for high-risk decoys" | `docker-compose.gvisor.yml` swaps runtime to `runsc` |
| "Docker only acceptable for low-fidelity HTTP decoys" | The agents are HTTP/SSH decoys; gVisor adds the kernel-isolation layer the blueprint requires |
| "Continuous validation: automated breakout tests" | `validate.sh` — 18 probes, machine-readable pass/fail |
