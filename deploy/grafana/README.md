# Grafana dashboards for Plenith

Importable JSON dashboards that consume the metrics exposed at
`http://<api-host>:8080/metrics`. Two dashboards:

| File | What it shows |
|---|---|
| `plenith-soc-overview.json` | SOC-eyes dashboard: engagement count, alerts by severity, ATT&CK tactic coverage, MFA decisions, counter-AI detections |
| `plenith-platform-health.json` | Operator dashboard: API request rate, error rate, process uptime, per-action alert rates |

## Prerequisites

You need a Prometheus instance scraping Plenith. Add this to your
`prometheus.yml`:

```yaml
scrape_configs:
  - job_name: plenith
    metrics_path: /metrics
    scheme: http
    bearer_token: ""            # /metrics is open by design (no auth)
    static_configs:
      - targets:
          - plenith-api:8080
```

## Importing

```
Grafana → Dashboards → New → Import → paste the JSON or upload the file.
```

The dashboards declare a `prometheus` datasource by name; if yours is
named differently, edit the variable when prompted.

## What the panels show

### `plenith-soc-overview.json`

- **Active engagements (counter)** — `plenith_engagements_total`
- **Alerts by severity (stacked area)** — `plenith_alerts_total{severity=...}` over time
- **Top 10 alert actions (table)** — `topk(10, plenith_alerts_by_action_total)`
- **Counter-AI detections (counter)** — `plenith_counter_ai_detections_total`
- **Counter-AI proven via trap (counter)** — `plenith_counter_ai_proven_total`
- **MFA decisions (pass/fail) (gauge)** — `plenith_mfa_decisions_total{decision="pass"|"fail"}`

### `plenith-platform-health.json`

- **API requests / sec (line)** — `rate(plenith_api_requests_total[5m])`
- **API error rate (line)** — `rate(plenith_api_errors_total[5m])`
- **API error ratio (single-stat)** — `... / (errors + requests)`
- **Process uptime (single-stat)** — `plenith_process_uptime_seconds`

## Customizing

Both dashboards declare a `$deployment_id` variable so you can filter
to one tenant in multi-tenancy mode. In single-tenant mode the
variable is hidden and matches everything.
