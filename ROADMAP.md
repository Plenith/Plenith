# Roadmap

This is the public roadmap for Plenith. It describes what's
landed, what's in flight, and what's targeted for future
releases. It is **not** a calendar commitment — dates here are
intentions, not promises. Open-source projects honor commitments
through transparency, not deadlines.

The roadmap is reviewed every quarter. Items shift between
buckets as priorities change, contributor availability changes,
and as we learn from operators. If something here matters to
you, comment on the linked tracking issue.

---

## How to read this document

| Bucket | Meaning |
| :--- | :--- |
| **Done** | Shipped in a tagged release. See `CHANGELOG.md`. |
| **In progress** | Active work; tracking issue exists; reasonable confidence it ships in the next release |
| **Next** | Planned for the version after the current in-progress one |
| **Considering** | We're thinking about it; not committed |
| **Out of scope** | Specifically not on the path. Listed so operators know not to wait for it. |

Anything not in this list is in the "might or might not happen
based on contributor interest" pile — file an issue if you want
it.

---

## Done — v1.0.0

The foundation. See [`CHANGELOG.md`](CHANGELOG.md) for the
complete list. Headline items:

- Async SSH-proxy orchestrator with persona-driven LLM responses
- 14-rule heuristic policy + V2 RL policy scaffold
- Counter-AI detection (timing / lexical / proof-by-trap)
- Multi-tenancy with per-tenant RBAC + deployment-id namespacing
- Plugin system (4 base classes, entry-point + directory discovery)
- Hash-chained tamper-evident audit log + verifier CLI
- Cosign keyless signed releases + SLSA provenance + CycloneDX SBOM
- Secrets resolver (env / file / Vault / AWS SM with lazy imports)
- Retention enforcement with subject-access-request scoping
- Container runtime profiles (seccomp + AppArmor) + nftables ruleset
- DPIA, data-handling reference, SOC 2 / ISO 27001 control mapping
- 9 Prometheus alerts each with a named operator runbook
- 1126 tests passing in CI matrix (Python 3.11–3.14, Ubuntu + Windows)

---

## In progress — v1.1 (target: Q3 2026)

Items are scoped, in active development, or have a clear
implementation path. Aim is the v1.0 + 90 days timeline.

### Trained RL policy checkpoint v1
The V2 policy infrastructure shipped in v1.0; the *trained model
weights* did not. v1.1 ships the first production checkpoint
trained on aggregate engagement data from opt-in deployments.
- Owner: TBD
- Tracking: open an issue with `roadmap:rl-v1` to follow
- Dependencies: at least 30 days of opt-in engagement data from
  3+ deployments

### Vertical persona pack — banking (first commercial pack)
Industry-specific synthetic personas: SWIFT operator, treasury
analyst, FX trader, fraud investigator. First in the commercial
persona-pack line described in `COMMERCIAL.md`.
- Owner: TBD
- Tracking: `roadmap:persona-banking`
- Customer collaboration welcome (banking-vertical advisors)

### Independent trademark + brand clearance
Pre-launch trademark attorney's clearance opinion on "Plenith"
across USPTO TESS, EUIPO, WIPO, plus common-law marks.
- Owner: maintainer-org
- Status: budgeted; not yet engaged
- Blocks: public launch announcements

### Pre-commit + lint cleanup
The 1,084 ruff violations found during v1.0 setup are tracked
under `roadmap:lint-sweep`. Plan: enable additional rule families
(UP, SIM) one at a time, with each PR including the fix sweep.
- Owner: open to first contributor
- Tracking: `roadmap:lint-sweep`

### docs/IMPACT/2026.md — first annual impact report
Per `MISSION.md` § "Governance" §1, an annual impact report is
published by April 1 of each year. The 2026 report (covering
calendar year 2026) is targeted for early 2027 but the **template
+ scaffold** ships in v1.1 so contributors and customers can see
the shape early.

---

## Next — v1.2 (target: Q4 2026)

Scoped less precisely than v1.1; expect ordering changes.

- **Vertical persona pack — healthcare** (HIPAA-flavored DBA,
  HL7 integrator, EHR admin)
- **Vertical persona pack — federal** (NIST 800-53 roles)
- **Compliance-bundle prototype for first paying customer**:
  delivered SOC 2 evidence packet against a real auditor's
  framework
- **Threat-intel feed v0**: aggregated, anonymized IoC stream to
  opt-in subscribers via TAXII
- **API rate limiting**: token-bucket per token, configurable
  per-tenant, separate from the reverse-proxy layer
- **Encrypted-at-rest audit chain**: optional AES-GCM wrapper on
  the on-disk engagement logs for jurisdictions where filesystem
  encryption isn't sufficient
- **First real-world deployment case study** (published, with
  customer's permission)

---

## Considering — v2.x (target: 2027)

Larger initiatives that need design work, contributor capacity, or
revenue traction before committing.

### Hosted dashboard (managed SaaS tier)
A multi-tenant hosted dashboard for SOCs that want to outsource
the dashboard's operational layer. Engagement data remains on the
customer's infrastructure; only dashboard UI + alert routing runs
in our cloud.
- Major design questions: data-residency commitments, customer-
  managed encryption keys, fail-back to self-hosted

### Trained RL policy v2 (per-vertical models)
Industry-specific RL policies trained on engagement data scoped to
each vertical (banking vs. healthcare vs. OT). Sold as part of the
vertical persona pack subscription.

### Plenith Operator Certification
Training + certification program for SOC analysts. Includes:
- Curriculum (online + optional in-person)
- Hands-on lab environment
- Practical + written exam
- Certified-Partner program for organizations

### OT-specific orchestrator (Plenith OT)
The current platform is IT-oriented (SSH, web). An OT variant
would handle Modbus, DNP3, S7, and other ICS protocols. Likely
shipped as a separate optional package, not a fork.

### Mobile attacker engagement
Decoy for mobile-OS attackers (Android scrcpy, iOS shortcuts,
etc.). Mostly research; depends on whether real-world deployments
see meaningful mobile-vector activity.

### Cross-deployment federated learning
Multiple operators contribute to a shared trained-policy without
exposing their raw engagement data to each other. Privacy-
preserving aggregation. Research-grade.

---

## Out of scope

These are specifically NOT on Plenith's path. Listed here so
operators don't wait for them and so contributors don't surprise
themselves by proposing them:

- **Closed-source enterprise features**. Per `MISSION.md` and
  `COMMERCIAL.md`. Anything in the orchestrator core stays Apache
  2.0. No "enterprise tier" with extra core code.
- **Per-host runtime licensing**. Same source.
- **Active offensive capabilities**. Plenith catches attackers and
  deceives them. It does not hack back, retaliate, or actively
  disrupt the attacker's infrastructure. That's a different
  product class and not one we're building.
- **Endpoint agent**. Plenith is network-side. We don't ship an
  EDR-style agent that runs on the customer's real production
  endpoints. Network monitoring + deception fabric only.
- **Identity provider replacement**. Plenith integrates with your
  IdP (via the MFA bridge). It is not a replacement for Okta /
  Duo / Auth0.
- **General-purpose SIEM**. We ship to your SIEM; we are not one.
- **Compliance certification of the software itself**. The
  software doesn't get SOC 2 / ISO 27001 / FedRAMP certified —
  organizations get certified, and Plenith helps them. See
  `docs/COMPLIANCE_MAPPING.md` for the precise distinction.

---

## How to influence the roadmap

The roadmap follows what operators actually need + what
contributors are willing to build. If something here matters to
you:

1. **Comment on the tracking issue.** Use cases + concrete needs
   help us prioritize.
2. **Volunteer to do the work** (or a piece of it). The fastest
   path from "considering" to "in progress" is a credible
   contributor stepping up.
3. **For commercial items**: open a `commercial`-labeled issue.
   Customer-funded engineering is one of the things that pulls
   "considering" items forward.

We do NOT prioritize on:
- Frequency of asks alone (one customer with a specific need can
  outweigh ten asks for the same thing if the customer is funding
  it)
- Vendor pressure (we don't take partner-influenced commitments)
- Generic "more features" requests

---

## Changes to this document

This roadmap is reviewed quarterly. Updates land via normal PR
flow — no special governance. Major reshapes (e.g. dropping a
"next" item, adding a major commercial offering) get noted in the
PR description so the change history is auditable in git log.

This document is editorial — it doesn't bind the project to any
specific delivery. The binding commitments live in
[`MISSION.md`](MISSION.md), [`LICENSE`](LICENSE),
[`TRADEMARK.md`](TRADEMARK.md), and
[`COMMERCIAL.md`](COMMERCIAL.md).

---

*Last reviewed: 2026-05-12.*
*Next review: 2026-08-12.*
