# ADR 004: Dual-port (22 + 2200) for PROXY-protocol forwarding

**Status:** Accepted
**Date:** 2026-05

## Context

The identity proxy enables `proxy_protocol on;` on its outbound, which
prepends a CRLF-terminated PROXY-v1 header to every connection to the
backends. Without that, the backends see the proxy's IP, not the real
client IP — which breaks engagement state keying, MFA decision keying,
geo-scoring on lateral, and audit-log attribution.

But agents inside the bubble do plain SSH (lateral movement: bastion →
db-prod). That traffic has NO PROXY header. The backend can't reliably
sniff the first bytes for "PROXY ", because asyncssh hands off the
socket immediately and reading bytes outside asyncssh requires careful
push-back.

## Decision

**Each backend dual-listens.** Port 22 = plain SSH (intra-bubble
lateral). Port 2200 = PROXY-v1-prefixed (proxy ingress). Proxy
`upstream` blocks target `:2200` on every backend.

## Considered alternatives

- **First-byte sniff on a single port** — read the first 6 bytes, look
  for "PROXY ", parse if found, push back if not. Requires custom
  asyncssh protocol class to push bytes back after sniff — fragile
  across asyncssh versions.
- **PROXY-v2 binary** — same dual-port issue; v2 is harder to detect
  by sniff (binary signature is `0x0d0a0d0a000d0a51` and easier to
  unambiguously detect, but still requires push-back).
- **All ports require PROXY**, lateral SSH wraps with `socat` shim —
  adds an in-bubble component just for PROXY framing.
- **Disable PROXY-v1, key MFA decisions on (proxy IP + username)** —
  fails when multiple clients share the proxy's NAT, all decisions
  collide.

## Why dual-port wins

1. **Crisp protocol boundary.** A connection to port 22 IS plain SSH.
   A connection to port 2200 IS PROXY-prefixed. No sniff, no push-back.
2. **Standard pattern.** AWS ALB uses port 80/443 vs 8080/8443 for
   the same reason — different protocols on different ports.
3. **Lateral SSH still works** — bastion → `db-prod-01:22` is the
   default port. Nothing in `~/.ssh/config` changes.
4. **PROXY-stripping listener is small** — `~50 lines` in
   `plenith/ssh_server.py::_proxy_strip_and_forward`. Reads PROXY
   header, opens a loopback connection to an internal asyncssh
   listener on `2200 + 10000 = 12200`, forwards bytes both ways,
   tracks the real client IP in a per-port dict.

## Consequences

- **Two listening ports per backend** (3 if you count the loopback
  internal). Trivial memory cost. NetworkPolicy ingress rules name
  both.
- **The proxy ingress nginx must `proxy_protocol on;`** — set in the
  Helm chart's templated `nginx.conf` ConfigMap.
- **In-bubble services (push-sim, dns, llm-egress) don't dual-listen**
  — they're never reached via the proxy.

## File pointers

- `plenith/ssh_server.py::_proxy_strip_and_forward`
- `plenith/api/auth.py` (auth lookups key on real_ip)
- `linux-fork/routing/nginx.conf::proxy_protocol on;`
- `linux-fork/docker-compose.yml` — both port mappings per agent
