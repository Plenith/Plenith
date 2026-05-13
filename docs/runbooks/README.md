# Operator runbooks

One file per Prometheus alert (`deploy/prometheus/alerts.yml`). The
alert's `runbook_url` annotation points here. Convention for each
runbook:

1. **What fired** — the alert expression, in one line.
2. **Why we care** — the threat or operational risk.
3. **First 5 minutes** — what to check, in priority order.
4. **Likely causes** — common diagnoses with their telltale signals.
5. **Mitigation** — the action to take.
6. **Post-incident** — what to capture, who to tell.

Runbooks are tested: `tests/test_alerts_config.py` asserts every
alert has a runbook AND every runbook references a known alert.

## Index

| Alert | Severity | Runbook |
| :--- | :--- | :--- |
| `PlenithOrchestratorDown` | page | [PlenithOrchestratorDown.md](PlenithOrchestratorDown.md) |
| `PlenithAgentHeartbeatStale` | page | [PlenithAgentHeartbeatStale.md](PlenithAgentHeartbeatStale.md) |
| `PlenithAPIErrorRateHigh` | ticket | [PlenithAPIErrorRateHigh.md](PlenithAPIErrorRateHigh.md) |
| `PlenithAPIAuthFailuresSustained` | ticket | [PlenithAPIAuthFailuresSustained.md](PlenithAPIAuthFailuresSustained.md) |
| `PlenithNoEngagementsRecently` | ticket | [PlenithNoEngagementsRecently.md](PlenithNoEngagementsRecently.md) |
| `PlenithCriticalAlertSurge` | page | [PlenithCriticalAlertSurge.md](PlenithCriticalAlertSurge.md) |
| `PlenithCounterAIProvenSpike` | page | [PlenithCounterAIProvenSpike.md](PlenithCounterAIProvenSpike.md) |
| `PlenithMFADenyRateHigh` | ticket | [PlenithMFADenyRateHigh.md](PlenithMFADenyRateHigh.md) |
| `PlenithAuditChainBroken` | page | [PlenithAuditChainBroken.md](PlenithAuditChainBroken.md) |
