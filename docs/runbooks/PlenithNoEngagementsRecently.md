# PlenithNoEngagementsRecently

**Severity:** ticket · **Component:** orchestrator

## What fired

`increase(plenith_engagements_total[6h]) == 0` for 15m.

No new engagement was recorded in the last 6 hours.

## Why we care

On the public internet, 6 hours of zero SSH probes is **unusual** —
indiscriminate scanning floors out around tens of probes per hour even
on low-value IP space. Zero engagements typically means the deception
fabric is no longer reachable, which means you're paying compute cost
to do nothing.

On a deliberately isolated deployment (internal pentest range, lab
network), this alert will fire by design — silence it or tune up.

## First 5 minutes

1. **Is the SSH proxy port open externally?**
   ```bash
   # From outside the deployment's network
   nc -zv <public-ip> 22000
   # Or, if you have a remote test runner:
   ssh -o ConnectTimeout=5 -p 22000 testuser@<public-ip> false
   ```
   - `Connection refused` or `timeout` → ingress broken.
   - Connection accepted → ingress is fine, problem is internal.
2. **Was the orchestrator restarted recently?**
   ```bash
   curl -sS http://<api-host>:8000/metrics | grep plenith_process_uptime_seconds
   ```
   A low uptime (<6h) plus zero engagements can simply mean nothing
   has happened since restart. False positive.
3. **Has the public IP changed?**
   Hosting providers occasionally re-assign IPs. If yours moved,
   nothing else discovers the new one until search engines re-crawl.
   Check your DNS A record vs. the actual outbound IP.
4. **Is there a NAT / firewall change?**
   ```bash
   ssh <agent-host> "iptables -t nat -L -n -v | grep 22000"
   ssh <agent-host> "ss -tlnp | grep 22000"
   ```

## Likely causes

| Signal | Cause | Mitigation |
| :--- | :--- | :--- |
| Port unreachable from outside | Firewall / security group change | Restore the ingress rule. Verify with `nc -zv` from outside. |
| Port reachable but no engagements logged | SSH proxy accepting but not handing off to orchestrator | Check the proxy's logs; restart it. |
| IP changed | Provider re-assigned | Update DNS, wait for re-discovery (24h–72h). |
| Recent deploy zeroed counters | False positive | Wait 6h then re-evaluate. Consider tuning the alert. |

## Mitigation

1. Restore reachability if the cause was a network change.
2. If the orchestrator is healthy but no traffic is arriving, you have
   nothing to fix — wait. Consider adding a synthetic-probe service
   that periodically logs an engagement so the alert distinguishes
   "platform broken" from "internet quiet."

## Post-incident

- If the cause was an ingress change, identify whose change it was and
  add Plenith to their change-review list.
- If the cause was IP re-assignment, consider pinning a static IP or
  using a stable hostname for discovery.
- If this alert fires often, tune the threshold or rewrite the alert
  to compare against historical norm for this deployment.
