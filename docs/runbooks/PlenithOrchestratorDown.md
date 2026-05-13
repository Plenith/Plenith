# PlenithOrchestratorDown

**Severity:** page · **Component:** orchestrator

## What fired

`up{job="plenith"} == 0` for >1 minute.

Prometheus could not scrape `/metrics` on the orchestrator instance.

## Why we care

The orchestrator is the only component that records attacker behavior.
While it's down, the SSH gateway may still answer connections (if it's
a separate process) but **no actions, no alerts, no audit logs are
being written.** Attackers who connect now are unmonitored — the worst
operational state this system can be in.

## First 5 minutes

In this order. Stop as soon as you find the cause.

1. **Is the process alive?**
   ```bash
   ssh <agent-host> "systemctl status plenith"   # or:
   ssh <agent-host> "docker ps --filter name=plenith --format '{{.Names}} {{.Status}}'"
   ```
   - `inactive (dead)` → restart and skip to step 4.
   - `active (running)` but Prometheus can't scrape → step 2.
2. **Is the metrics endpoint reachable from the Prometheus host?**
   ```bash
   curl -sS -o /dev/null -w '%{http_code}\n' http://<agent-host>:8000/metrics
   ```
   - `000` → network / firewall change. Check `iptables -S` and
     security-group rules.
   - `401` / `403` → auth misconfig on Prometheus's side; check the
     scrape config's `authorization:` block.
   - `200` but Prometheus still says down → Prometheus storage / WAL
     issue, restart Prometheus.
3. **Logs.**
   ```bash
   ssh <agent-host> "journalctl -u plenith -n 200 --no-pager"
   ```
   Look for the last successful log line; what happened immediately
   after is usually the cause (OOM, exception, signal).

## Likely causes

| Signal | Cause | Mitigation |
| :--- | :--- | :--- |
| Process not in `ps`, no obvious crash | OOM-killed | Check `dmesg | grep -i kill`. Increase memory or reduce concurrent engagements via config. |
| Stuck in `Up <hours>` but unresponsive | Asyncio deadlock | `kill -SIGUSR1` to dump tracebacks (we install a signal handler that writes to `state-docker/diag/`); restart. |
| Started recently, exits within seconds | Bad config or missing dep | `python run.py` interactively; the traceback is the answer. |
| Started, then exits when first SSH connect arrives | Persona file invalid YAML or LLM endpoint unreachable | Same: run interactively. |

## Mitigation

1. **Restart** if there's no evidence of compromise:
   ```bash
   ssh <agent-host> "systemctl restart plenith"
   ```
2. If the orchestrator is part of a deployment with hot standby, fail
   over and investigate the failed instance offline.
3. If the metrics endpoint stays unreachable after restart, escalate
   to networking — the alert is real and you can't see it from your
   workstation either.

## Post-incident

- Capture `journalctl -u plenith --since "1 hour ago"` and attach
  to the ticket.
- If the cause was OOM, file an issue with the memory profile from
  `state-docker/diag/` so we can fix the leak.
- Update the deployment's monitoring playbook with the time-to-detect
  and time-to-mitigate for this incident.
