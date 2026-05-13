# PlenithAPIErrorRateHigh

**Severity:** ticket · **Component:** api

## What fired

`rate(plenith_api_errors_total[5m]) / rate(plenith_api_requests_total[5m]) > 0.05` for 5m.

More than 5% of inbound REST API calls are failing.

## Why we care

The REST API is what downstream integrations (SOAR playbooks, SIEM
queries, dashboards, the operator CLI) use to read engagement state.
A sustained error rate above noise means somebody's integration is
broken — possibly silently dropping alerts on the consumer side.

This is a ticket (not a page) because the orchestrator itself is
unaffected. Investigate during business hours unless paired with
another alert.

## First 5 minutes

1. **What's the dominant status code?**
   ```promql
   topk(5, sum by (status) (rate(plenith_api_errors_total[15m])))
   ```
   - All `5xx` → it's our fault; check orchestrator logs.
   - All `4xx` → it's the caller's fault; check who's calling.
   - `401`/`403` dominant → likely related; see
     `PlenithAPIAuthFailuresSustained`.
2. **Which endpoint?**
   If labels include `path`, group by it. A spike on `/api/engagements`
   but not `/api/health` usually means a specific consumer broke; a
   uniform spike across endpoints means the API process is unhappy.
3. **Recent deploy?**
   ```bash
   ssh <api-host> "docker logs plenith-api 2>&1 | head -1"
   ```
   The "Uvicorn started" line gives you the start time. If it's recent,
   the previous deploy is the prime suspect — roll back first, debug
   second.

## Likely causes

| Status pattern | Cause | Mitigation |
| :--- | :--- | :--- |
| 502 / 503 spike | Upstream dependency timing out (LLM, SIEM connector). API surfaces those as 5xx by design. | Look at the matching dependency alert; fix upstream. |
| 422 spike | A new consumer is sending malformed payloads. Schema change? | `grep -i 'validation' /var/log/plenith/api.log` — Pydantic errors are explicit. |
| 401/403 surge | Token revoked or expired. | See `PlenithAPIAuthFailuresSustained`. |
| 500 uniform | Bug introduced by recent change | Roll back the deployment; file the traceback as an issue. |

## Mitigation

1. If the cause is a recent deploy, **roll back immediately.**
2. If the cause is an upstream dependency, the API is correctly
   reporting it — don't suppress the alert, fix upstream.
3. If the cause is a noisy consumer, identify them via the reverse
   proxy's access logs (the API itself doesn't log request bodies by
   design) and contact them.

## Post-incident

- If 5xx, attach the traceback to the issue.
- If consumer-caused, document the contract violation in
  `docs/API_GUIDE.md` so the next consumer doesn't hit it.
- Consider whether rate-limiting on the offending endpoint would
  short-circuit future occurrences.
