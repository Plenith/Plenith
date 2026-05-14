# Changelog

All notable changes to this project will be documented in this file.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) with semver-
flavored versioning. We treat the orchestrator + REST API + connector
surface as the public API. Plugin and configuration interfaces follow
semver discipline; internal-only modules may change without notice.

## [Unreleased]

### Security
- **C-1 (critical):** validate the `ip` path parameter in
  `POST /mfa/decisions/{ip}` via `ipaddress.ip_address()` before any
  filesystem operation. Pre-fix, an unauth attacker (default
  open-mode config) could send a traversal pattern and write a
  controlled `.pass`/`.fail` file at an arbitrary location with a
  controlled body. (`plenith/api/server.py`)
- **C-2 (critical):** add `_safe()` sanitizer to `tools/audit.py`
  that strips ANSI escape sequences and C0/C1 control bytes from
  every attacker-controlled field (claimed_user, command, cwd,
  triggered_by, decoy_targets, etc.) before printing to the
  operator's terminal. Pre-fix, an attacker who typed an escape
  sequence in their SSH username or commands could clear the
  analyst's screen, hide alerts, or smuggle OSC-8 paste-on-click
  hyperlinks.
- **C-3 (critical):** harden CSV IoC export against formula
  injection. `_csv_safe()` prefixes attacker-controlled cell
  values beginning with `=+-@\t` with a single quote, and the
  export now uses `csv.writer` for proper RFC-4180 quoting. Pre-fix
  an attacker-controlled exfil domain starting with `-` would
  execute as a formula when the analyst opened the CSV in Excel.
  (`tools/audit.py`)
- **H-1:** STIX 2.1 domain-name pattern now uses `json.dumps()` for
  quoting, matching the URL-indicator path. Pre-fix, a single quote
  in an attacker-controlled subdomain could break out of the STIX
  pattern expression. (`plenith/connectors/stix.py`)
- **H-2:** `MFA_DEMO_LOG_CODE` default flipped from `"1"` (on) to
  `"0"` (off). Previously every deployment that didn't explicitly
  opt out was logging valid TOTP codes to stderr every 30 seconds —
  anyone with log read access could bypass MFA for the demo users.
  (`linux-fork/mfa/mfa_gateway.py`,
  `linux-fork/docker-compose.yml`)
- **H-3:** SSH password logging hashed via BLAKE2b-64 instead of
  cleartext `%r`. Preserves forensic "same-password-seen-twice"
  signal without persisting the cleartext to journald/loki/elastic
  where real-user typos against the honeypot would otherwise leak.
  (`plenith/ssh_server.py`)
- **H-6:** dashboard prints a stderr WARNING when bound to anything
  other than loopback (127.0.0.1 / ::1 / localhost). The dashboard
  has no authentication and serves the full attacker IoC stream;
  binding to public is a real footgun. (`tools/dashboard.py`)

### Fixed
- **Counter-AI trap was functionally inert** (engineering Bug #4).
  `maybe_inject_trap()` ran at *plant-time* in `responses.py`, but
  decoys are planted on the first relevant attacker command (e.g.
  `sudo`) while the trap doesn't arm until composite confidence
  crosses 0.70 — many commands later. Plant-time injection
  therefore ran with `trap_armed=False` virtually every time,
  baking a clean body into the VFS. Subsequent reads of the same
  decoy returned the trap-less content, even after the trap armed.
  Fixed by moving injection to *read-time* via the dynamic-renderer
  machinery: `Session.plant_decoy()` registers a renderer that
  calls `maybe_inject_trap()` on every read with the current
  trap_armed state. Same static body in the VFS, but the read-time
  check produces a clean response pre-arm and a trap-bearing
  response post-arm. (`plenith/session.py`, `plenith/responses.py`)
- **Counter-AI state evaporated on every reconnect** (engineering
  Bug #5). `CounterAIState` (timestamps, lexical history, trap
  marker/payload, trap-armed/leaked flags, confidence) was purely
  in-memory and never serialized; `Session._fresh_observed()`
  didn't include the counter-AI gate-state keys, so
  `_deserialize_observed()` silently dropped them too. Multi-day
  APT engagements lost their accumulated detection signal every
  time the attacker disconnected, and `alert_attacker_llm_detected`
  could re-fire on each connection. Fixed by adding
  `CounterAIState.to_dict()` / `from_dict()`, wiring the snapshot
  into `Session.to_persistent_state`, restoring on
  reconnect, and adding the seven counter-AI keys to
  `_fresh_observed()`. (`plenith/counter_ai.py`, `plenith/session.py`)
- **`tools/audit.py` missed every docker-stack session log**
  (engineering Bug #6, regression in commit `0219516`). The
  helper added in that commit globbed `logs_dir.glob("*.json")`
  flat, but docker agents write to
  `state-docker/logs/<hostname>/*.json`. Fixed by `_iter_log_files()`
  which walks both the flat dev-mode layout and one level of
  hostname subdirectories. (`tools/audit.py`)

### Added
- **Documentation lint suite** (`tests/test_docs_lint.py`): four
  regression-prevention tests catching the classes of drift found
  in the v1.0 audit — legacy project names outside historical
  records, MIT-license claims, stale `plenith/rotation.py` file
  refs, and documented test-count drift from the live
  `pytest --collect-only` count (with ±5% tolerance for in-flight
  PRs).
- **40 new regression tests** across `tests/test_api.py`,
  `tests/test_audit.py`, `tests/test_counter_ai.py` covering each
  of the six critical findings.

### Changed
- **Project renamed from MirrorCore to Plenith.** The prior name was
  unavailable in the security namespace. See ADR 013 for the
  rationale and metaphor fit. All identifiers updated: Python package
  (`plenith/`), Prometheus metric prefix (`plenith_*`), environment
  variable prefix (`PLENITH_*`), Docker image namespaces, GitHub URL
  placeholders, runbook filenames (`Plenith*.md`), Grafana dashboard
  filenames, and Helm chart path. No deprecation shim — there are no
  external deployments yet to break.
- Test count is now **1031 passing** (up from 991 at commit `0219516`).
- THREADS.md (launch build-in-public copy) Thread 1 post 5/9
  rewritten to quote the actual conservative-gate behavior and
  the live qwen-14B persona-C measurement (composite 0.05–0.34
  across runs), replacing the unsupported "8% catch rate, 0
  false positives across 600+ synthetic sessions" claim.
- README.md, QUICKSTART.md, FAQ.md, ROADMAP.md, PRE_LAUNCH_CHECKLIST.md
  test counts swept to current (1031).
- README.md license reference at line 44 corrected from "MIT" to
  "Apache 2.0", matching LICENSE/NOTICE.
- `docs/RED_TEAM.md` debug guidance for persona-C now explains the
  conservative gate as the *expected* behavior for moderate-strength
  LLMs, not a sign of a broken trap.
- Stale doc references swept: `plenith/rotation.py` →
  `plenith/rotation/` (package); `check_for_echoed_trap()` and
  `score_session()` (didn't exist) → `observe_command()`;
  `github.com/example/plenith` → `github.com/Plenith/Plenith`;
  `mirrorcore_agent_heartbeat_*` → `plenith_agent_heartbeat_*`.

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
  (`plenith/rotation/` package — artifacts, corp, rotator, seeds).
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

1031 tests passing across 1200+ assertions. Categories:

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
