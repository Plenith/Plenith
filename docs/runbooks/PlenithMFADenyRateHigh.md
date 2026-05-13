# PlenithMFADenyRateHigh

**Severity:** ticket · **Component:** mfa

## What fired

`(deny / total)` for MFA decisions > 50% over 10 minutes.

More than half of MFA decisions in the last 10 minutes were denies.

## Why we care

The MFA bridge sits between attempted authentications and the
decoy-vs-real routing decision (`docs/THREAT_MODEL.md` § Credential
flow). When denies dominate, one of two things is happening:

- **An attacker is grinding stolen credentials** against the bridge.
  Most credentials are denied because the user hasn't approved a push
  on their phone.
- **The upstream MFA provider is degraded** (Duo / Okta API timeouts,
  rate-limited, etc.) and the bridge is failing closed (correctly).

Both are tickets — neither is "the platform is broken" — but they're
diagnostically different and the fix is different.

## First 5 minutes

1. **Is the upstream MFA provider healthy?**
   ```bash
   # Test the Duo / Okta endpoint from the bridge host
   ssh <mfa-host> "curl -sS -o /dev/null -w '%{http_code} %{time_total}s\n' \\
     https://api-XXXXXXXX.duosecurity.com/auth/v2/ping"
   ```
   - HTTP 200 in <1s → upstream is fine. Skip to step 2.
   - Slow / 5xx / timeout → upstream is degraded; the denies are
     legitimate fail-closed decisions. Wait for upstream to recover or
     fall through to your manual approval procedure.
2. **What's the source distribution of the denies?**
   The bridge logs the source IP on every decision. If denies are
   concentrated on one or a few IPs:
   ```bash
   ssh <mfa-host> "jq -r '.source_ip' /var/log/plenith/mfa.log | \\
     sort | uniq -c | sort -rn | head"
   ```
   - One IP, many denies → blocked credential-stuffing attempt; the
     platform is doing exactly what it should. Block at the firewall
     and close the ticket.
   - Many IPs, evenly distributed → either distributed brute force OR
     a usability regression (e.g. the push notification stopped
     reaching phones). Check step 3.
3. **Is the push channel working?**
   Try an approval push to a known-good test account. If the push
   never arrives, the provider's push channel is broken — denies are
   really user-can't-approve.

## Likely causes

| Pattern | Cause | Mitigation |
| :--- | :--- | :--- |
| Concentrated denies from one IP | Credential stuffing | Block at firewall. Notify the affected user's IT lead. |
| Distributed denies, upstream healthy | Either coordinated attack OR push delivery broken | Test a known-good push; if broken, file with the MFA provider. |
| Concentrated allow→deny pattern (alternating) | One stolen credential under brute force, real user denying | Force-rotate the credential; alert the user. |
| Sudden 100% deny | Upstream provider outage | Wait. The bridge is failing closed correctly. Consider manual procedure if the outage is long. |

## Mitigation

1. If credential stuffing: block the source at the upstream firewall
   (NOT in Plenith — the platform doesn't deliver IP-level blocking
   on its own).
2. If push delivery is broken: file with the MFA provider; the bridge
   has nothing to fix. Communicate to users that they may need to
   approve via the provider's app directly.
3. If the upstream provider is degraded: the bridge is correctly
   failing closed. Wait or escalate.

## Post-incident

- If credential stuffing was confirmed, file the source IPs as
  threat-intel via the STIX connector.
- If the cause was a push-delivery regression, log the duration; this
  feeds your MFA-provider SLA review.
- If denies are sustained at >20% even after fix, consider whether
  the bridge's timeout is too short — fail-closed should be the
  fallback, not the default.
