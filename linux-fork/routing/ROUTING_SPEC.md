# Identity proxy + risk-engine routing spec

This is the **§5.1** piece of the Engineering Blueprint, absent from the single-host MVP. In the Linux fork, an Nginx + OpenResty/Lua front-end intercepts inbound SSH and decides:

- **Low risk** → forward to real production. (Out of scope for the deception platform — that's just your normal SSH server.)
- **Borderline** → step-up MFA challenge. Pass-through to real prod on success, route to bastion-prod on fail.
- **High risk** → route directly to the Plenith decoy network at `bastion-prod:2222`.

This file is the spec. The actual Lua module is a separate sub-project of ~200 lines.

---

## Signal inputs to the risk engine

| Signal | Source | Weight (illustrative) |
|---|---|---|
| Source IP geo | MaxMind GeoIP2 free DB | +1 if outside expected work region |
| Device fingerprint | JA3/JA4 of TLS hello (for HTTPS); SSH banner + KEX prefs (for SSH) | +2 if novel for this user |
| Time-of-day deviation | Per-user baseline learned over 30 days | +1 if 3σ outside |
| Credential breach status | HaveIBeenPwned API (optional) | +3 if known-breached |
| Source IP reputation | AbuseIPDB free tier | +3 if confidence ≥ 75% |
| Tor / VPN egress | Public Tor exit-node list + IP2Location LITE | +2 if Tor, +1 if commercial VPN |
| Concurrent active session for same user | Local DB | +1 if existing session from different geo |
| Rate of recent failed auths | Local cache | +1 per failure beyond threshold |

Weights are tuned for an organization's risk tolerance. Total score:
- `< 3` → real prod
- `3 ≤ score < 6` → step-up MFA
- `≥ 6` → decoy

---

## Decision flow

```
                inbound TCP SYN to port 22
                          │
                          v
                ┌──────────────────────┐
                │ Nginx stream listener │
                │   (proxy, port 22)    │
                └────────────┬─────────┘
                             │
                             v
                ┌────────────────────────┐
                │ Lua: compute risk score │
                │  (signals above)        │
                └────────────┬───────────┘
                             │
        ┌────────────────────┼────────────────────┐
        v                    v                    v
     score < 3          3 ≤ score < 6           score ≥ 6
        │                    │                    │
        v                    v                    v
  real-prod:22       step-up MFA portal     bastion-prod:2222
                     (out-of-band)          (Plenith decoy)
                            │
                            v
                  pass → real-prod:22
                  fail → bastion-prod:2222
```

---

## Where this lives in the Nginx config

The relevant directive is the `stream` block (not `http`), because SSH is a TCP protocol:

```nginx
stream {
    lua_package_path "/etc/nginx/lua/?.lua;;";
    init_by_lua_file /etc/nginx/lua/init.lua;

    upstream real_prod    { server 10.10.5.10:22; }
    upstream mfa_relay    { server 10.10.5.11:22; }
    upstream plenith   { server 10.10.99.10:2222; }   # bastion-prod

    server {
        listen 22;
        preread_by_lua_file /etc/nginx/lua/score_and_route.lua;
        proxy_pass $upstream_pool;       # set in the preread Lua
    }
}
```

The Lua `score_and_route.lua` does:
1. `ngx.var.remote_addr` for source IP.
2. Cache lookup (Redis or shared dict) for geo + breach + reputation.
3. Read the SSH banner from `ngx.req.get_uri_args()` — actually `ngx_stream_ssl_preread_module` exposes the SSH version string.
4. Compute total score.
5. Set `ngx.var.upstream_pool` to one of the three upstreams.

---

## What this gives the Plenith platform

The single biggest property: **the attacker never knows they're not on the real network.** They typed `ssh prod.acme.corp`, the DNS resolved normally, the TCP handshake succeeded, the SSH banner looked right, they authed (with whatever credential they had), and they landed in a corporate-shaped shell. The decision to route them to a decoy happened transparently at the proxy.

Compare with the MVP, where the attacker has to type `ssh -p 2222 jdoe@127.0.0.1` knowing it's a honeypot. The Linux fork removes that — production-grade deception requires the attacker not to know.

---

## Failure modes

| Failure | Behavior |
|---|---|
| Risk engine down (Lua exception, Redis unreachable) | **Fail-safe MFA**: route to step-up MFA. Never silent-route to decoy on failure. |
| Decoy network unreachable | Drop the connection. Better than a confusing "Connection refused" that hints at platform state. |
| Real prod unreachable | Standard error returned to the legit user, who retries through other channels. |
| Risk engine timeout | Default to MFA after 200 ms (real prod takes priority if the user is provably legit, but we'd rather be slow-and-safe than fast-and-misrouted). |

---

## What's deliberately NOT here

- **No identity database.** Use your existing AD/LDAP/Auth0. The risk engine reads from that; nothing is duplicated.

---

## MFA step-up — implementation (`linux-fork/mfa/`)

This section is **no longer aspirational**. The borderline-risk tier is implemented as a dedicated TCP service inside the bubble. See `linux-fork/mfa/mfa_gateway.py` and `linux-fork/mfa/totp.py`.

### Decision flow

```
   borderline-risk SSH (Lua score 3-6)
                    │
                    v
     ┌──────────────────────────────┐
     │  mfa-gateway (asyncssh)      │
     │  hostname: mfa-relay         │
     │  IP: 172.30.0.21             │
     ├──────────────────────────────┤
     │  1. accept any first-factor  │   ← real corp MFA assumes the
     │     credential               │     credential was already
     │  2. print corp banner +      │     verified upstream
     │     "push sent to your       │
     │     device"                  │
     │  3. wait briefly, "push      │
     │     denied" (location        │
     │     policy)                  │
     │  4. prompt for TOTP          │
     │  5. validate (RFC 6238,      │
     │     ±30s window)             │
     │  6. write decision file:     │
     │       /mnt/state/mfa/        │
     │         <ip>.{pass,fail}     │
     │  7. disconnect with "please  │
     │     reconnect"               │
     └──────────────────────────────┘
                    │
       user reconnects to the proxy
                    │
                    v
     ┌──────────────────────────────┐
     │  score_and_route.lua main()  │
     │  step 0: check_mfa_decision  │
     │   - .pass → real_prod        │
     │   - .fail → plenith       │
     │     (silent — attacker is    │
     │      shown the bastion       │
     │      banner as if they       │
     │      reached prod)           │
     │  decision file consumed on   │
     │  read (single-use grant)     │
     │  step 1: normal scoring      │
     │  (only if no decision file)  │
     └──────────────────────────────┘
```

### TOTP secret source

For the dev fabric, secrets are derived deterministically from `(deployment_id, username)` via SHA-256 — so the gateway logs the current valid code on each prompt (helpful when test-driving the demo) and you don't need a real enrollment service. In production, swap `mfa.totp.secret_for(username)` for a call into your enrollment store (Duo, Okta admin API, etc.).

### Decision file format

Small key-value text file. Lua parses with `string.match`; no JSON dep needed.

```
ip=192.0.2.99
decision=pass
ts=1778589315
```

`ts` is checked against `MFA_TTL_SECONDS` (default 300s). Expired files are deleted on read; valid files are renamed-to-consumed on use so a single MFA grant authorizes exactly one inbound session.

### Production caveat: PROXY protocol

In production the proxy MUST forward PROXY-protocol v1 to mfa-gateway so the gateway sees the original client IP, not the proxy's loopback. The dev fabric on Docker Desktop NAT collapses all host connections to a single bridge-gateway IP (172.18.0.1), which masks this issue — but `linux-fork/tools/demo_mfa.py` demonstrates each wire (`.pass`/`.fail` injection, gateway protocol) separately so you can verify each piece independently.

Configuration on the nginx side:

```nginx
upstream mfa_relay_pool {
    server mfa-gateway:22;
}

server {
    listen 22;
    preread_by_lua_file /etc/nginx/lua/score_and_route.lua;
    proxy_pass $resolved_upstream;
    proxy_protocol on;   # ← required in production
}
```

The gateway (asyncssh) then needs to read 56-108 bytes of PROXY-v1 header before letting asyncssh own the socket. Not yet implemented; see [issue 1234] when filed.

---

## Why this matters for the deception model

Reading the [Engineering Blueprint §4.3 "Credential-Compromised Attack Flow"](../../Plenith.md) again with this routing in place:

1. Attacker connects with stolen `jdoe / Spring2024!`.
2. Risk engine sees: anomalous geo (+1), novel JA3 (+2), HIBP says password is breached (+3). Score = 6. → **Decoy.**
3. The proxy forwards the SSH session to `bastion-prod:2222`. The bastion-prod agent accepts the (any) password, the Plenith orchestrator builds a session as `agarcia`, the attacker lands at `agarcia@bastion-prod:~$`.
4. The attacker now thinks they have agarcia's bastion access. From their perspective, everything looks normal.
5. They `ssh db-prod-01`. The proxy sees inbound SSH from `bastion-prod` (an internal IP, low risk because it's a trusted bastion) and routes it through the internal decoy switch fabric. They land at `jdoe@db-prod-01:~$` (the db-prod-01 agent's default persona).
6. Multi-host engagement begins. Every command on either host fires alerts back into the shared StateStore. Audit tool joins them.

This is the production deception story. The MVP proves the orchestrator can do step 3-6 correctly. The Linux fork proves it can do step 1-2.
