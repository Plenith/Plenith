# Architecture Decision Records

Each ADR documents one significant design choice in Plenith — what
we picked, what we considered, why the picked option won, and what
that costs us. The goal is so that 18 months from now, someone asking
"why isn't this using X?" can find the answer in <60 seconds.

Format: lightly modified Michael Nygard / Joel Parker Henderson style.

## Index

| # | Title | Status |
|---|---|---|
| 001 | REINFORCE over PPO for the V2 policy | Accepted |
| 002 | FastAPI over aiohttp / Starlette for the inbound REST | Accepted |
| 003 | CEF as the primary SIEM wire format (over LEEF, syslog-plain) | Accepted |
| 004 | Dual-port (22 + 2200) for PROXY-protocol forwarding | Accepted |
| 005 | Lua decision-file handoff over PROXY-v2 TLVs for MFA | Accepted |
| 006 | Synchronous httpx in Duo / Okta clients (vs. async-native SDKs) | Accepted |
| 007 | gVisor as the dev-fabric microVM substitute (over Firecracker) | Accepted |
| 008 | Single-tier API tokens for v1 (per-tenant RBAC deferred to v2) | Accepted |
| 009 | numpy-only RL training (no torch / jax) | Accepted |
| 010 | Stdlib http.server for the dashboard + push-sim (no Flask/FastAPI) | Accepted |
| 011 | Plugin system — four base classes + two discovery paths | Accepted |
| 012 | Secrets resolver — opt-in URI references with lazy backend deps | Accepted |
| 013 | Renamed from MirrorCore to Caltrop | Superseded by 014 |
| 014 | Renamed from Caltrop to Plenith | Accepted |

Add new ADRs as `NNN-short-name.md`, increment the number, link from
this index, never delete or renumber an existing ADR.
