# Changelog

All notable changes to this project will be documented in this file.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) with semver-
flavored versioning. We treat the orchestrator + REST API + connector
surface as the public API. Plugin and configuration interfaces follow
semver discipline; internal-only modules may change without notice.

## [Unreleased]

### Changed
- **Project renamed from MirrorCore to Plenith.** The prior name was
  unavailable in the security namespace. See ADR 013 for the
  rationale and metaphor fit. All identifiers updated: Python package
  (`plenith/`), Prometheus metric prefix (`plenith_*`), environment
  variable prefix (`PLENITH_*`), Docker image namespaces, GitHub URL
  placeholders, runbook filenames (`Plenith*.md`), Grafana dashboard
  filenames, and Helm chart path. No deprecation shim — there are no
  external deployments yet to break.

## [1.0.0] - 2026-05-12

First stable release. This is the baseline against which subsequent
changes will be tracked.

### Added

#### Core platform
- **Orchestrator** — async SSH proxy + per-engagement state machine
  with persona-driven response generation
  (`plenith/orchestrator.py`).
- **LLM client** — LM Studio / Ollama / OpenAI-compatible inference
  (`plenith/llm_client.py`).
- **Heuristic + policy engine** — 14-rule heuristic ladder + V2 RL
  policy scaffold (`plenith/heuristics.py`, `plenith/policy.py`).
- **Response cache** — pre-cached deterministic outputs to reduce
  LLM hits on common commands (`plenith/response_cache.py`).
- **Simulation bot** — non-LLM fallback for trivial commands
  (`plenith/sim_bot.py`).
- **Persona system** — YAML-defined synthetic personas driving the
  decoy environment (`plenith/persona.py`).
- **Content rotation** — deployment-keyed regeneration of decoy
  artifacts to defeat cross-deployment fingerprinting
  (`plenith/rotation.py`).
- **Counter-AI module** — timing + lexical + injection-probe
  detection of LLM-driven attackers with proof-by-trap escalation
  (`plenith/counter_ai.py`).
- **Multi-tenancy** — per-tenant tokens, RBAC, deployment-id
  namespacing (`plenith/multitenancy.py`).
- **Plugin system** — four plugin base classes (detector / policy /
  responder / connector), entry-point + directory discovery
  (`plenith/plugins.py`, `docs/PLUGINS.md`, ADR 011).

#### Reliability + observability
- **REST API** — FastAPI surface with bearer-token auth, OpenAPI
  spec, per-tenant filtering (`plenith/api/`).
- **Prometheus metrics** — `/metrics` endpoint exposing engagement,
  alert, MFA, API, and counter-AI counters
  (`plenith/api/metrics.py`).
- **Grafana dashboards** — pre-built SOC overview and platform health
  dashboards (`deploy/grafana/`).
- **Prometheus alert rules** — 9 named alerts across liveness, API,
  detection, MFA, and audit-integrity groups, each linked to an
  operator runbook (`deploy/prometheus/alerts.yml`, `docs/runbooks/`).
- **OpenTelemetry shim** — engagement / command / LLM-call /
  connector-emit spans; no-op when OTel not installed
  (`plenith/tracing.py`, ADR — none yet, see file header).
- **Agent heartbeats** — back-channel for active liveness rather
  than docker-ps inference (`plenith/heartbeat.py`).
- **Performance baseline + regression gate** — captured baseline +
  `bench.py --compare` (`state/bench/baseline.json`, `tools/bench.py`).

#### Security + integrity
- **Hash-chained audit log** — tamper-evident on-disk engagement
  logs with verifier CLI (`plenith/audit_chain.py`,
  `tools/verify_chain.py`).
- **Backup + restore** — atomic tar + SHA-256 manifest with cross-
  deployment protection (`tools/backup.py`, `tools/restore.py`).
- **CycloneDX SBOM** — `tools/sbom.py` produces a 1.5-schema-
  conformant SBOM consumed by the release workflow.
- **Signed releases** — cosign keyless signing + SLSA build
  provenance via `.github/workflows/release.yml`; verification
  documented in `docs/VERIFY_RELEASES.md`.
- **Secrets resolver** — opt-in `<scheme>://...` references for
  config values (env / file / Vault / AWS Secrets Manager), lazy
  imports, fail-loud on miss (`plenith/secrets.py`,
  `tools/secrets_check.py`, ADR 012, `docs/SECRETS.md`).
- **Retention enforcement** — daily-cron purge per documented policy
  with subject-access-request scoping
  (`plenith/retention.py`, `tools/retention_purge.py`).
- **Container runtime profiles** — seccomp + AppArmor for the agent
  container (`deploy/security/`).
- **Network isolation** — default-DROP nftables ruleset for the
  decoy bubble (`deploy/network/decoy-bubble-egress.nft`).

#### Integration surface
- **SIEM connectors** — Splunk HEC, Elasticsearch bulk, syslog
  TCP/UDP, generic webhook (`plenith/connectors/siem.py`).
- **SOAR connectors** — generic SOAR webhook with retry
  (`plenith/connectors/soar.py`).
- **MITRE ATT&CK mapping** — heuristic → technique-ID lookup
  (`plenith/connectors/mitre.py`).
- **STIX 2.1 / TAXII 2.1** — outbound IoC publishing
  (`plenith/connectors/stix.py`, `taxii.py`).
- **ChatOps** — Slack / Teams / generic webhook notifiers
  (`plenith/connectors/chatops.py`).
- **MFA bridge** — Duo + Okta verification with fail-closed defaults
  (`plenith/connectors/mfa_providers.py`).

#### Documentation
- **README** — operator-facing platform overview with comparison
  matrix vs. Acalvio / Illusive / Attivo / Splunk DECEIVE.
- **QUICKSTART** — 60-second install + 5-minute deploy
  (`docs/QUICKSTART.md`, `bootstrap.sh`).
- **Threat model** — STRIDE walk-through, 5 documented attack
  scenarios (`docs/THREAT_MODEL.md`).
- **DPIA** — GDPR Art. 35 Data Protection Impact Assessment with
  DPO sign-off block (`docs/DPIA.md`).
- **Data-handling reference** — per-category lifecycle, retention,
  DSR workflow (`docs/DATA_HANDLING.md`).
- **Hardening guide** — five-layer production walkthrough
  (`docs/HARDENING.md`).
- **Architecture Decision Records** — 12 ADRs covering the
  significant design decisions (`docs/adr/`).
- **Plugin guide** — how to write a third-party detector / policy /
  responder / connector (`docs/PLUGINS.md`).
- **Operator runbooks** — one per Prometheus alert
  (`docs/runbooks/`).

#### Project hygiene
- **CI matrix** — Python 3.11 / 3.12 / 3.13 / 3.14 on Ubuntu and
  Windows with Docker-dependent tests separated into their own job
  (`.github/workflows/ci.yml`).
- **Release workflow** — tag-triggered build → SBOM → cosign keyless
  signing → SLSA attestation → GitHub Release
  (`.github/workflows/release.yml`).
- **Dependabot** — weekly grouped PRs for pip / GitHub Actions /
  Docker bases (`.github/dependabot.yml`).
- **Security policy** — disclosure process, supported versions,
  safe-harbour (`SECURITY.md`).
- **Mission statement** — open-source-forever promise + 30% of net
  commercial proceeds committed to children's-development
  initiatives (`MISSION.md`).

### Tests

872 tests passing across 1100+ assertions. Categories:

| Area | Tests |
| :--- | :--- |
| Orchestrator + heuristics + policy | ~140 |
| Session + persona + persistence | ~80 |
| Connectors + formats + MITRE + STIX | ~130 |
| API + auth + multitenancy | ~80 |
| Audit + audit-chain | ~70 |
| Secrets resolver | 52 |
| Plugin system | 26 |
| Retention | 23 |
| Backup / restore | 17 |
| SBOM | 20 |
| Tracing | 12 |
| Heartbeat | 14 |
| Dashboard SSE | 11 |
| Bench compare | 14 |
| Alert config + runbook coverage | 16 |
| Dependabot config | 10 |
| Audit-chain CLI + integration | 33 |
| Security artifacts (seccomp / AppArmor / nft) | 32 |
| Other (counter-AI, rotation, narrate, ot-decoys, training, mfa, etc.) | balance |

### Known limitations (open work)

These are documented openly rather than hidden — the project ships
1.0 with these caveats:

- **V2 RL policy is scaffolded but not trained**. `TrainedRLPolicy`
  loads checkpoints but no production-grade checkpoint ships with
  1.0. Default policy remains the heuristic ladder.
- **Vertical persona libraries are placeholder-shallow.** The
  default personas are generic developer / DBA archetypes; banking-
  / healthcare- / OT-specific personas are on the commercial roadmap.
- **No real-world deployment proof published yet.** A case study
  is part of the 1.1 roadmap.
- **Hosted SaaS layer not built.** Operators run the platform on
  their own infrastructure. A multi-tenant managed offering is a
  longer-term option.

---

## Versioning

We use [Semantic Versioning](https://semver.org). The public API
surface for versioning purposes is:

- The REST API (paths, request/response shapes).
- The plugin interfaces (`PluginBase` subclass methods).
- The connector configuration shape.
- The `plenith.policy.Policy` interface.
- The `plenith.audit_chain` external functions.
- The on-disk engagement-log JSON shape (additive changes minor;
  field renames / removals major).

Internal modules — heuristics rules, persona schema, response
cache shape, training internals — may change without a major bump
provided behavior is unchanged.

## Pre-1.0 history

Prior to 1.0, Plenith was an MVP iterated on a developer
workstation. There are no tagged pre-1.0 releases.

---

[Unreleased]: https://github.com/Plenith/Plenith/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Plenith/Plenith/releases/tag/v1.0.0
