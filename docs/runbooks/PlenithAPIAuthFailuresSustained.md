# PlenithAPIAuthFailuresSustained

**Severity:** ticket · **Component:** api

## What fired

`rate(plenith_api_errors_total{status=~"401|403"}[5m]) > 0.5` for 10m.

Auth failures on the REST API at >0.5/s for 10 minutes. That's more
than a typo or a misconfigured client retrying.

## Why we care

The REST API tokens are an authn-only secret. If an attacker gets one,
they can read engagement intelligence — the planted credentials,
attacker IPs, what we know. That's exactly the kind of "second-order"
data a competitor or sophisticated adversary would want.

A brute-force pattern against the API is also a tell that the
attacker has discovered the API exists (it's not advertised — it's
not internet-exposed by default). Investigate **how they knew**.

## First 5 minutes

1. **Is this internal or external?**
   The API should be behind your reverse proxy. The proxy's access log
   will show the source. If the source is internal, it's almost
   certainly a misconfigured consumer; if external, treat as
   adversarial.
   ```bash
   ssh <proxy-host> "tail -200 /var/log/nginx/plenith.access.log | \\
     awk '/401|403/ {print $1}' | sort | uniq -c | sort -rn | head"
   ```
2. **Is the rate climbing or steady?**
   Steady → script with fixed delay (probably a broken consumer). Climbing
   → a brute force ramping up.
3. **Is the API supposed to be reachable from where the traffic is
   coming from?**
   Per `docs/THREAT_MODEL.md`, the API surface should be tightly scoped.
   If the source IP shouldn't even see the port, you have a network ACL
   bug as well as an auth attack.

## Likely causes

| Source | Cause | Mitigation |
| :--- | :--- | :--- |
| Internal CI/CD with old credentials | Token rotation forgotten on that CI job | Re-issue and update; revoke the old token. |
| Internal SOAR with bad routing | The playbook's auth config is stale | Same fix. |
| External, low rate, single IP | Reconnaissance | Block the IP at the proxy; the platform has nothing of value to expose if they can't auth. |
| External, high rate, distributed | Distributed brute force | Engage your DDoS / WAF tier. The API can't outrun a botnet on its own. |
| External, but they're hitting valid token formats | Token exfiltrated from somewhere. Treat as active credential compromise. | Rotate ALL API tokens (`plenith/api/auth.py:rotate_all_tokens`); audit recent successful logins; investigate how the token leaked. |

## Mitigation

1. If internal: identify the consumer (see step 1), update its token.
2. If external: add a deny rule at the reverse proxy for the source(s).
   Don't try to fix this in Plenith — the proxy is the right layer
   for IP-based blocking.
3. If you suspect token leak: **rotate everything**, audit the access
   log for successful 200s from that source, and treat as an incident.

## Post-incident

- If you found a leaked token, run the leak-source analysis: was it in
  a commit? CI logs? A screenshot? Update your secrets-handling
  guidance.
- Consider whether the API should be on a separate network from the
  decoy bubble (it should — `docs/THREAT_MODEL.md` flags this).
- If brute force is a recurring shape, ticket up "add rate-limiting +
  IP-block-list to API" as a feature request.
