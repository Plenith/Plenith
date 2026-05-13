# PlenithCriticalAlertSurge

**Severity:** page · **Component:** detection

## What fired

`increase(plenith_alerts_total{severity="critical"}[5m]) > 5` for 1m.

More than 5 critical-severity alerts fired in the last 5 minutes.

## Why we care

Critical alerts in Plenith are reserved for the highest-confidence
signals: reverse shells, SSH persistence, confirmed counter-AI hits
via proof-by-trap. Five-plus in five minutes either means:

- **An active, multi-stage compromise.** Pay attention — this is what
  the platform is for.
- **A heuristic firing spuriously after a rule change.** Same volume,
  different cause. The dashboard will show whether the alerts are
  evenly spread across engagements (alarm shape) or concentrated on
  one (real attack).

Either way: someone needs to look NOW.

## First 5 minutes

1. **Open the SOC dashboard.**
   `http://<dashboard-host>:8765/` — the SSE feed will show the live
   engagement view. Look at the engagement list, sorted by severity.
2. **Is the surge in one engagement, or many?**
   - **One engagement, many alerts** → almost certainly a real attack,
     mid-flight. Continue to step 3.
   - **Many engagements, one alert each** → either a noisy heuristic
     OR a coordinated campaign. Continue to step 4.
3. **Inspect the engagement:**
   ```bash
   ssh <agent-host> "cat /opt/plenith/state-docker/persistence/*.json | \\
     jq 'select(.engagement_id==\"<ID>\")'"
   ```
   The `actions_taken` array tells you the attack sequence. The order
   alone is usually diagnostic.
4. **Did anyone deploy a rule change recently?**
   ```bash
   cd /opt/plenith && git log --since="6 hours ago" -- plenith/heuristics.py plenith/responses.py
   ```
   If yes, this is the prime suspect. Roll back the change first; confirm
   alerts return to baseline; then re-investigate the rule.

## Likely causes

| Pattern | Cause | Mitigation |
| :--- | :--- | :--- |
| One engagement firing `alert_reverse_shell`, `alert_ssh_persistence`, `alert_credential_exfil` in sequence | Real, full-chain attack | This is the success state. Capture the engagement log; alert the SOC tier-2 lead per your IR playbook. |
| One engagement firing the same alert N times | Bug: `alerted_*` flag isn't sticking | File an issue; the heuristic's idempotency check is broken. |
| Many engagements firing one alert each | Coordinated scan / red team | Capture all engagements; correlate source IPs / patterns. |
| Many engagements firing because of recent rule change | Heuristic over-firing | Roll back the change; re-introduce with stricter thresholds. |

## Mitigation

- **Do not silence the alert** while you're investigating. The whole
  point is for someone to see it.
- If it's a real attack: follow your IR playbook. The Plenith docs
  recommend: preserve the decoy container, do NOT kill the session
  (deception value is being maximized), force-rotate the real-world
  equivalent credentials for any planted files the attacker read.
- If it's a rule bug: revert; reproduce in a unit test; ship the fix.

## Post-incident

- If real: produce an after-action with `tools/after_action.py` for
  this engagement. The narrative output is what you'll send to the
  business stakeholder.
- If false-positive: add a test case under `tests/test_heuristics.py`
  exercising the scenario that triggered the spurious fire so the next
  similar rule change doesn't regress.
- Either way: the engagement IDs go into the monthly KPI rollup.
