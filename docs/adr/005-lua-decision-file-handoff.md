# ADR 005: Lua decision-file handoff over PROXY-v2 TLVs for MFA

**Status:** Accepted
**Date:** 2026-05

## Context

§4.3 MFA step-up needs the proxy to know "did this IP pass MFA?". Two
shapes are possible:

1. **Decision-file pattern.** Gateway writes `/mnt/state/mfa/<ip>.pass`
   when MFA succeeds. Proxy's Lua scorer reads the file on the next
   connection from that IP and routes accordingly.
2. **Inline state in the connection itself** — embed an "MFA OK" claim
   in a PROXY-v2 TLV custom field. Gateway-side service sets it;
   proxy-side scorer reads it.

## Decision

**File-based handoff.**

## Why

1. **Time-decoupled.** The user passes MFA, gets disconnected, then
   reconnects 30 seconds later. Decision file persists; PROXY-v2 TLV
   needs a continuous connection.
2. **Auditable.** Every decision file is a forensic artifact with a
   timestamp + reason. SOC pulls them, ships to SIEM, retains per the
   §13 retention policy. PROXY-v2 TLV vanishes when the connection
   closes.
3. **Simpler.** Lua + `io.open` reads a tiny key=value file. PROXY-v2
   TLV requires custom v2 framing on the proxy side AND custom TLV
   parsing on the gateway side.
4. **Survives proxy restart.** A `.pass` file written 10 minutes ago
   still routes correctly after the proxy is restarted. PROXY-v2 TLV
   state lives in the connection.

## Considered alternatives

- **Shared Redis** — better for high-throughput, but adds Redis as a
  hard dependency. Out of scope for the single-host MVP and Helm chart
  default.
- **Database table** — same Redis-style argument; we're not at the
  scale where this matters.
- **Lua shared dict in nginx** — proxy-side only. Gateway can't write
  to nginx's shared dict from a different container.

## Consequences

- **TTL enforcement is Lua's responsibility.** `MFA_TTL_SECONDS=300` in
  `score_and_route.lua`. Files older than that are removed on read.
- **Single-use semantics.** Decision file is `os.remove`'d on
  consumption — one decision authorizes exactly one inbound session.
- **NFS-style consistency** if the state mount is on networked storage
  — newly-written files may take a few ms to appear. The 1-2 second
  network round-trip between the user's reconnect and the file lookup
  is enough margin in practice.

## File pointers

- `linux-fork/routing/score_and_route.lua` — `check_mfa_decision()`
- `linux-fork/mfa/mfa_gateway.py` — `_write_decision()`
