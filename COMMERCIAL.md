# What's Free, What's Commercial

This document is the public statement of which parts of Plenith are
permanently free + open source, and which parts the maintainer
organization offers commercially. It's written so a procurement
team or a CISO can read it once and know exactly what they get
without paying, what's paid, and which kinds of paid offerings
exist.

If you're a developer or operator: **everything you need to deploy,
operate, and customize Plenith is in this repository, under
Apache 2.0, free forever**. The commercial offerings exist to fund
the project's mission (see `MISSION.md`) — they're additive, not
gatekeeping.

If you're a buyer evaluating Plenith for procurement: skip to
section "Commercial offerings" below.

---

## What's free + open source

Under [Apache 2.0 (LICENSE)](LICENSE), the following are free
forever — no per-host fees, no per-engagement fees, no enterprise-
tier locks, no telemetry, no license-key activation:

### Platform
- The orchestrator
- SSH proxy and per-engagement state machine
- LLM client (LM Studio / Ollama / OpenAI-compatible)
- Persona engine + response cache + simulation bot
- All 14 heuristics + the V2 policy scaffold
- Content rotator (deployment-keyed synthetic data)
- Counter-AI detection module
- REST API + bearer-token auth + per-tenant RBAC + OpenAPI spec
- Plugin system (4 base classes, entry-point + directory discovery)
- Plenith dashboard (operator UI)

### Reliability + observability
- `/metrics` Prometheus endpoint
- Two Grafana dashboards (SOC overview, platform health)
- Nine Prometheus alert rules with per-alert operator runbooks
- OpenTelemetry tracing shim
- Agent heartbeat back-channel
- Performance benchmark + regression gate

### Security + integrity
- Hash-chained audit log + verifier CLI
- Backup + restore tools with SHA-256 manifest
- CycloneDX SBOM generator
- Signed-release workflow (cosign keyless + SLSA provenance)
- Secrets resolver (env / file / Vault / AWS SM with lazy imports)
- Retention enforcement (cron-driven purge)
- Container runtime profiles (seccomp + AppArmor)
- Default-DROP nftables ruleset for the decoy bubble

### Integration surface
- SIEM connectors: Splunk HEC, Elasticsearch bulk, syslog TCP/UDP,
  generic webhook
- SOAR webhook connector
- MITRE ATT&CK mapping
- STIX 2.1 / TAXII 2.1 IoC publishing
- Slack / Teams / generic ChatOps notifiers
- MFA bridge (Duo + Okta)

### Documentation
- README, QUICKSTART, HARDENING, DPIA, DATA_HANDLING, THREAT_MODEL,
  COMPLIANCE_MAPPING, SECRETS, PLUGINS, VERIFY_RELEASES, CONTRIBUTING,
  MISSION, TRADEMARK, GOVERNANCE, MAINTAINERS, ROADMAP — and every
  one of the 14 ADRs
- All runbooks
- Default persona library

### What "free forever" means

- The maintainer-org will never relicense the items above to a more
  restrictive license. See `MISSION.md` "open-source-forever
  promise" for the binding statement.
- All future security patches, bug fixes, and reliability
  improvements to the above ship under the same Apache 2.0 license.
- Anyone can self-host indefinitely. No phone-home telemetry, no
  license-key activation, no kill switch.

---

## Commercial offerings

The maintainer organization offers the following commercially. Net
revenue from these is the funding source for the mission's
children's-development commitment (`MISSION.md` § "30% pledge").

### One-time deliverables

| Offering | What you get | Typical fit |
| :--- | :--- | :--- |
| **Compliance bundle** | Pre-filled DPIA template, SOC 2 / ISO 27001 control mapping with your auditor's framework, threat-model variant for your vertical, audit-evidence packet | Org pursuing SOC 2 Type 1 / 2 or ISO 27001 readiness |
| **Vertical persona pack** | Industry-specific synthetic personas: banking (SWIFT, treasury), healthcare (HIPAA-flavored DBA, HL7 integrator), federal (NIST 800-53 roles), OT/ICS (Modbus operator, historian DBA) | Org with industry-specific attacker profile concerns |
| **Managed deployment** | We deploy + tune + operate Plenith for the first 90 days, hand off with documented runbooks specific to your environment | Org that wants the platform but doesn't have spare SOC engineering capacity |

### Recurring subscriptions

| Offering | What you get | Cadence |
| :--- | :--- | :--- |
| **Threat-intel feed** | Aggregated, anonymized IoC stream from opted-in deployments. STIX/TAXII-formatted. You see what's hitting other Plenith deployments. | Monthly subscription |
| **Trained RL policy checkpoints** | Periodic updates to the V2 action-selection policy, trained on aggregate engagement data from opted-in subscribers | Quarterly checkpoint releases |
| **Premium support** | SLA-backed direct access to maintainers. Severity-1 response within 4 hours; root-cause analysis on confirmed bugs. | Annual contract |

### Future / planned

The following are on the commercial roadmap but not yet shipping:

- **Hosted dashboard (SaaS)** — for SOCs that prefer to outsource
  the dashboard's operational layer while keeping engagement data
  on their own infrastructure. Per-host or per-engagement pricing.
  Status: planned, post-1.5.
- **Training + certification** — Plenith Operator certification
  program for SOC analysts. Status: planned, post-2.0.

---

## What the maintainer organization will NOT commercialize

Some specific things we publicly commit NEVER to commercialize:

- **Per-host or per-engagement runtime licensing.** You can deploy
  Plenith on as many hosts and observe as many engagements as you
  want, free, forever.
- **Compliance-relevant features behind a paywall.** Audit-chain
  integrity, retention enforcement, multi-tenancy, secrets
  resolution — these are all in the open-source core and stay
  there. Compliance is not the upsell; expertise + deliverables
  around compliance is.
- **Security patches behind a paywall.** Every security fix lands
  in the open-source core. Premium-support customers get faster
  response, not different patches.
- **Plugin-API gating.** Any operator can write any plugin without
  asking us. The plugin system is part of the OSS core.

If we ever try to walk back any of these commitments, that's a
mission-violation — see `MISSION.md` "Things we will not do" and
the amendment procedure.

---

## Pricing transparency

Where we publish prices, they go on the project website (not in
this file — prices change; this file shouldn't churn). When pricing
is bespoke (managed deployment, enterprise support tiers), we
disclose the floor + ceiling publicly so buyers know the range.

We don't do hidden enterprise quotes. If a sales conversation isn't
visible to your finance team, ask why.

---

## How to engage commercially

Today (pre-launch): open a GitHub issue with the `commercial` label
describing what you're trying to accomplish. The maintainers will
respond within 5 business days.

Post-launch (when the website + sales process exist): the project
site will have a `/commercial` page with the offerings above and a
contact form.

For procurement teams that need vendor-onboarding paperwork
(W-9, COI, security questionnaire response, MNDA), open the same
`commercial`-labeled issue and we'll route it.

---

## Why this document exists

Procurement teams routinely ask "what does your free tier include
and what's the upsell pressure?" before they recommend a tool to
their organization. The answer for Plenith is: **the free tier is
the whole product; the commercial offerings are services around it
and content for it, not the engine itself.**

This document is the durable, citable answer to that question.

---

*Last updated: 2026-05-12.*
*Companion to [MISSION.md](MISSION.md), [LICENSE](LICENSE), and
[TRADEMARK.md](TRADEMARK.md).*
