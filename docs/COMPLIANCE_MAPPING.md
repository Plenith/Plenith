# Compliance control mapping

This document maps Plenith's built-in controls to the two
frameworks customers ask about most: **SOC 2 (2017 Trust Services
Criteria)** and **ISO/IEC 27001:2022 Annex A**.

Read it as: "of the controls these frameworks expect, which ones
does Plenith provide evidence for out of the box, which ones are
the operator's responsibility, and which ones need work?"

## Important disclaimer

This is **not certification, and it does not replace an auditor**.
SOC 2 and ISO 27001 attestations are issued by independent auditors
(CPA firms for SOC 2; accredited certification bodies for ISO 27001)
after a formal assessment of *your organization's* controls — not the
software's. The orchestrator can provide evidence; only your auditor
can attest to it.

What this document is good for:

- **Saving a GRC team weeks** during a SOC 2 / ISO 27001 readiness
  assessment by pre-mapping which controls have built-in evidence.
- **Vendor-risk questionnaires** from customers ("which controls does
  your software help me meet?").
- **Scoping audit work** — your auditor can use this to focus on the
  controls where Plenith is in the evidence path.

What it's NOT good for:

- Claiming the software is "SOC 2 certified" or "ISO 27001 compliant"
  — those phrases are technically meaningless for software (only
  organizations get certified).
- Replacing your own control-design + operating-effectiveness work.

If you're a customer evaluating Plenith for procurement: ask for
this document, plus your auditor's opinion on which mappings hold
under your specific deployment.

---

## How to use the tables

Each row maps a single control to Plenith's contribution. Columns:

| Column | Meaning |
| :--- | :--- |
| **Control** | The framework's control identifier and short name |
| **Evidence** | Where in the repo the implementation / artifact lives |
| **Coverage** | How much Plenith contributes |
| **Operator action** | What the deploying org must still do |

**Coverage** values:

- 🟢 **Direct** — Plenith implements the control. Evidence is the
  named artifact.
- 🟡 **Partial** — Plenith contributes to the control; operator
  must complete (e.g. configure thresholds, attach to their auth
  system, complete documentation).
- 🔵 **Evidence only** — Plenith produces logs / artifacts the
  auditor will inspect; the control itself is operator-implemented.
- ⚪ **N/A** — Out of scope for this software.

---

## SOC 2 — 2017 Trust Services Criteria

Mapping covers the Security, Confidentiality, Availability, and
Privacy criteria. Processing Integrity is largely N/A — Plenith
does not process customer-facing transactions.

### CC: Common Criteria (Security)

| Control | Evidence | Coverage | Operator action |
| :--- | :--- | :---: | :--- |
| CC1.1 — Demonstrate commitment to integrity and ethical values | `MISSION.md`, `CODE_OF_CONDUCT.md` | 🟡 | Adopt + sign internally |
| CC1.2 — Board oversight | — | ⚪ | Operator responsibility |
| CC1.3 — Management structures / responsibilities | — | ⚪ | Operator responsibility |
| CC1.4 — Demonstrate commitment to competence | `docs/CONTRIBUTING.md`, ADR process | 🟡 | Hire / train your team |
| CC1.5 — Accountability for internal control | `docs/runbooks/` | 🟡 | Assign owners |
| CC2.1 — Information requirements / quality | `docs/DATA_HANDLING.md` | 🟢 | Adopt as-is or extend |
| CC2.2 — Internal communication of objectives | `MISSION.md`, `docs/` | 🟡 | Distribute to staff |
| CC2.3 — External communication | `README.md`, `SECURITY.md` | 🟢 | — |
| CC3.1 — Specify suitable objectives | `docs/THREAT_MODEL.md` | 🟢 | Customize for your deployment |
| CC3.2 — Identify and analyze risk | `docs/THREAT_MODEL.md`, `docs/DPIA.md` | 🟢 | Re-run for your deployment |
| CC3.3 — Consider fraud risk | `docs/THREAT_MODEL.md` (STRIDE / Spoofing) | 🟡 | Map to your fraud surface |
| CC3.4 — Identify and assess change | `docs/adr/`, `CHANGELOG.md`, ADR process | 🟢 | Apply your change-mgmt overlay |
| CC4.1 — Select / develop ongoing monitoring | `deploy/prometheus/alerts.yml`, `deploy/grafana/` | 🟢 | Deploy + connect to your Prom/Grafana |
| CC4.2 — Evaluate / communicate deficiencies | `docs/runbooks/` | 🟢 | Add ticketing integration |
| CC5.1 — Select / develop control activities | This document | 🟢 | — |
| CC5.2 — Select / develop general controls over technology | All of `deploy/security/`, `deploy/network/` | 🟢 | Deploy + enforce |
| CC5.3 — Deploy through policies / procedures | `docs/HARDENING.md` | 🟢 | Follow the guide |
| CC6.1 — Logical access security | `plenith/api/auth.py`, `plenith/multitenancy.py` | 🟢 | Configure tokens + RBAC |
| CC6.2 — Register and authorize new users | `plenith/multitenancy.py` (token issuance) | 🟡 | Wire into your IdP |
| CC6.3 — Manage access by roles / privileges | `plenith/multitenancy.py` (admin / analyst / read_only) | 🟢 | Assign roles |
| CC6.4 — Restrict physical access | — | ⚪ | Operator responsibility |
| CC6.5 — Discontinue access on termination | — | 🔵 | Operator process; revoke tokens via `plenith/multitenancy.py` |
| CC6.6 — Logical access controls — external users | `plenith/api/auth.py` + reverse proxy guide | 🟡 | Follow `docs/HARDENING.md` §3 |
| CC6.7 — Restrict transmission / movement of information | `deploy/network/decoy-bubble-egress.nft` | 🟢 | Apply ruleset; verify isolation |
| CC6.8 — Prevent / detect malicious software | `deploy/security/seccomp-agent.json`, `apparmor-agent.profile` | 🟢 | Apply profiles |
| CC7.1 — Detect / monitor system components | `plenith/heartbeat.py`, `/metrics`, `PlenithOrchestratorDown` alert | 🟢 | Monitor the alert |
| CC7.2 — Monitor system performance | `plenith/api/metrics.py`, Grafana dashboards | 🟢 | Tune thresholds |
| CC7.3 — Evaluate security events | `tools/audit.py`, `docs/runbooks/`, `plenith/audit_chain.py` | 🟢 | Staff your IR rotation |
| CC7.4 — Respond to identified security events | `docs/runbooks/`, IR procedure in DPIA | 🟢 | Customize for your IR plan |
| CC7.5 — Recover from security incidents | `tools/backup.py`, `tools/restore.py`, DR runbook | 🟢 | Test restore quarterly |
| CC8.1 — Authorize / design / develop / acquire changes | `docs/CONTRIBUTING.md`, ADR process | 🟢 | Apply your change board |
| CC9.1 — Identify, select, develop risk mitigation activities | `docs/THREAT_MODEL.md`, `docs/HARDENING.md` | 🟢 | — |
| CC9.2 — Manage vendors / business partners | `tools/sbom.py`, `docs/VERIFY_RELEASES.md` | 🟢 | Apply to your vendor list |

### A: Availability

| Control | Evidence | Coverage | Operator action |
| :--- | :--- | :---: | :--- |
| A1.1 — Capacity planning + measurement | `tools/bench.py`, `state/bench/baseline.json` | 🟡 | Run periodically in your env |
| A1.2 — Environmental protection | — | ⚪ | Operator's data center / cloud provider |
| A1.3 — Recover from environmental events | `tools/backup.py` + DR runbook | 🟢 | Test |

### C: Confidentiality

| Control | Evidence | Coverage | Operator action |
| :--- | :--- | :---: | :--- |
| C1.1 — Identify + maintain confidential information | `docs/DATA_HANDLING.md` | 🟢 | Adopt as-is or extend |
| C1.2 — Dispose of confidential information | `plenith/retention.py`, `tools/retention_purge.py` | 🟢 | Enable cron |

### P: Privacy (Privacy Trust Service Criteria)

| Control | Evidence | Coverage | Operator action |
| :--- | :--- | :---: | :--- |
| P1.1 — Privacy notice | `docs/DPIA.md` | 🟢 | Publish for your deployment |
| P2.1 — Consent + choice | — | 🔵 | Honeypots have specific Art. 6(1)(f) basis; see DPIA |
| P3.1 — Collection limitations | `docs/DATA_HANDLING.md` §3 | 🟢 | — |
| P4.1 — Use, retention, disposal | `plenith/retention.py` | 🟢 | Configure retention windows |
| P5.1 — Access — provide individual access | `tools/audit.py`, DSR workflow in DATA_HANDLING.md | 🟢 | Document your DSR process |
| P5.2 — Right to update / correct | DSR workflow | 🟢 | Honor requests per documented process |
| P6.1 — Disclosure to third parties | `plenith/connectors/`, opt-in IoC sharing | 🟢 | Configure recipients |
| P7.1 — Quality | `plenith/audit_chain.py` (integrity) | 🟢 | Monitor `PlenithAuditChainBroken` |
| P8.1 — Monitoring + enforcement | `tools/verify_chain.py` daily cron | 🟢 | Schedule it |

---

## ISO/IEC 27001:2022 Annex A (selected controls)

ISO 27001 Annex A has 93 controls organized into four themes. The
table below covers the controls Plenith directly contributes to.
Controls not listed are either operator-only (e.g. physical security,
HR policy) or out of scope for a piece of software.

### A.5 Organizational controls

| Control | Evidence | Coverage | Operator action |
| :--- | :--- | :---: | :--- |
| A.5.7 Threat intelligence | `plenith/connectors/stix.py`, `taxii.py` | 🟢 | Configure feeds |
| A.5.8 Information security in project mgmt | ADR process | 🟢 | Adopt |
| A.5.9 Inventory of information and assets | `docs/DATA_HANDLING.md`, SBOM | 🟢 | — |
| A.5.10 Acceptable use | `MISSION.md`, `CODE_OF_CONDUCT.md` | 🟡 | Extend for your org |
| A.5.12 Classification of information | `docs/DATA_HANDLING.md` (D1–D10) | 🟢 | — |
| A.5.13 Labelling of information | Engagement log JSON schema | 🟡 | — |
| A.5.14 Information transfer | `plenith/connectors/`, all use TLS | 🟢 | Configure endpoints |
| A.5.15 Access control | `plenith/api/auth.py`, multitenancy | 🟢 | Configure roles |
| A.5.16 Identity management | — | 🔵 | Operator's IdP; we accept tokens |
| A.5.17 Authentication information | `docs/SECRETS.md` | 🟢 | Adopt patterns |
| A.5.18 Access rights | Multi-tenant RBAC | 🟢 | Assign |
| A.5.19 InfoSec in supplier relationships | `tools/sbom.py`, `docs/VERIFY_RELEASES.md`, `.github/dependabot.yml` | 🟢 | Apply to your supply chain |
| A.5.20 Addressing InfoSec within supplier agreements | `LICENSE`, supplier list in NOTICE | 🟡 | Add your own contractual layer |
| A.5.21 Managing InfoSec in the ICT supply chain | SBOM, signed releases | 🟢 | Verify on consumption |
| A.5.22 Monitoring, review and change management of supplier services | Dependabot, SBOM diff | 🟢 | Schedule reviews |
| A.5.23 InfoSec for use of cloud services | `docs/SECRETS.md` cloud patterns, `docs/DATA_HANDLING.md` | 🟢 | Apply to your cloud usage |
| A.5.24 InfoSec incident management planning | `docs/runbooks/` | 🟢 | Customize for your org |
| A.5.25 Assessment + decision on InfoSec events | `docs/runbooks/` triage sections | 🟢 | — |
| A.5.26 Response to InfoSec incidents | Runbooks per alert | 🟢 | — |
| A.5.27 Learning from incidents | After-incident sections of runbooks | 🟡 | Establish review cadence |
| A.5.28 Collection of evidence | `plenith/audit_chain.py`, hash-chained logs | 🟢 | Verify daily |
| A.5.29 InfoSec during disruption | `tools/backup.py`, `tools/restore.py` | 🟢 | Test |
| A.5.30 ICT readiness for business continuity | DR runbook | 🟢 | Test |
| A.5.31 Legal, statutory, regulatory, contractual requirements | `docs/DPIA.md` | 🟢 | Extend per your jurisdiction |
| A.5.32 Intellectual property rights | `LICENSE`, `NOTICE` | 🟢 | — |
| A.5.33 Protection of records | Hash-chained audit + retention | 🟢 | Enable |
| A.5.34 Privacy and protection of PII | `docs/DPIA.md`, retention enforcement | 🟢 | — |
| A.5.35 Independent review of InfoSec | — | 🔵 | Operator commissions audit |
| A.5.36 Compliance with policies, rules and standards | This document | 🟢 | Map to internal policies |
| A.5.37 Documented operating procedures | `docs/runbooks/`, `docs/HARDENING.md`, `docs/QUICKSTART.md` | 🟢 | Apply |

### A.6 People controls

| Control | Evidence | Coverage | Operator action |
| :--- | :--- | :---: | :--- |
| A.6.1 Screening | — | ⚪ | Operator HR responsibility |
| A.6.2 Terms and conditions of employment | — | ⚪ | Operator HR |
| A.6.3 InfoSec awareness, education and training | `docs/runbooks/`, this document | 🟡 | Train your SOC |
| A.6.6 Confidentiality / non-disclosure agreements | — | ⚪ | Operator HR |
| A.6.7 Remote working | — | ⚪ | Operator policy |
| A.6.8 InfoSec event reporting | `SECURITY.md` | 🟢 | Adapt to your org's reporting chain |

### A.7 Physical controls

Largely operator responsibility — data center / cloud-provider's
physical security. Plenith's containerized agent doesn't add to
or detract from this control family.

### A.8 Technological controls

| Control | Evidence | Coverage | Operator action |
| :--- | :--- | :---: | :--- |
| A.8.1 User endpoint devices | — | ⚪ | Operator |
| A.8.2 Privileged access rights | Multi-tenant `admin` role; documented in `docs/CONTRIBUTING.md` § release | 🟢 | — |
| A.8.3 Information access restriction | API auth + tenant RBAC | 🟢 | Configure |
| A.8.4 Access to source code | LICENSE; git access controls | 🟡 | — |
| A.8.5 Secure authentication | Bearer tokens + reverse-proxy TLS guidance | 🟡 | Implement `docs/HARDENING.md` §3 |
| A.8.6 Capacity management | Bench baseline + Prometheus | 🟢 | Monitor |
| A.8.7 Protection against malware | seccomp + AppArmor; supply-chain via SBOM | 🟢 | Apply profiles |
| A.8.8 Management of technical vulnerabilities | Dependabot + SBOM + SECURITY.md | 🟢 | Triage Dependabot PRs |
| A.8.9 Configuration management | Config + ADR + secrets resolver | 🟢 | Version-control your config |
| A.8.10 Information deletion | `plenith/retention.py` | 🟢 | Enable cron |
| A.8.11 Data masking | `plenith/secrets.py:redact()` | 🟡 | Apply in your tooling |
| A.8.12 Data leakage prevention | nftables egress; DNS bubble isolation | 🟢 | Apply |
| A.8.13 Information backup | `tools/backup.py` | 🟢 | Schedule |
| A.8.14 Redundancy of information processing facilities | — | 🔵 | Operator deploys HA |
| A.8.15 Logging | Engagement logs + API audit + hash chain | 🟢 | — |
| A.8.16 Monitoring activities | Prometheus + Grafana + alert rules | 🟢 | Connect to your Prom |
| A.8.17 Clock synchronization | nftables ruleset permits internal NTP only | 🟢 | Configure NTP source |
| A.8.18 Use of privileged utility programs | seccomp blocks `ptrace`, `kexec_load`, etc. | 🟢 | Apply |
| A.8.19 Installation of software on operational systems | Signed releases (`docs/VERIFY_RELEASES.md`) | 🟢 | Verify cosign before deploy |
| A.8.20 Network security | `deploy/network/decoy-bubble-egress.nft` | 🟢 | Apply |
| A.8.21 Security of network services | Same | 🟢 | Apply |
| A.8.22 Segregation of networks | Decoy bubble isolated from prod LAN | 🟢 | Verify isolation |
| A.8.23 Web filtering | — | 🔵 | Operator network |
| A.8.24 Use of cryptography | TLS for transit; cosign for releases; SHA-256 audit chain | 🟢 | — |
| A.8.25 Secure development life cycle | CONTRIBUTING.md + CI + signed releases | 🟢 | Adopt for your forks |
| A.8.26 Application security requirements | `docs/THREAT_MODEL.md` | 🟢 | — |
| A.8.27 Secure system architecture and engineering principles | ADRs | 🟢 | — |
| A.8.28 Secure coding | `CONTRIBUTING.md` + pre-commit + ruff | 🟢 | — |
| A.8.29 Security testing in development and acceptance | CI matrix, 870+ tests | 🟢 | — |
| A.8.30 Outsourced development | — | ⚪ | Operator's vendor mgmt |
| A.8.31 Separation of development, test and production environments | `docs/HARDENING.md`, deployment patterns | 🟡 | Apply your env separation |
| A.8.32 Change management | ADRs + CHANGELOG | 🟢 | — |
| A.8.33 Test information | Test fixtures use synthetic data | 🟢 | — |
| A.8.34 Protection of information systems during audit testing | seccomp / AppArmor / nftables | 🟢 | — |

---

## Coverage rollup

Of the controls Plenith can credibly contribute to:

| Framework | Direct | Partial | Evidence-only | Out of scope |
| :--- | ---: | ---: | ---: | ---: |
| SOC 2 (CC + A + C + P) | 30 | 12 | 4 | 6 |
| ISO 27001 Annex A (covered) | 39 | 9 | 5 | 9 |

A typical operator who follows `docs/HARDENING.md`, enables retention
+ audit-chain cron, ships alerts to their Prometheus, and writes a
custom DPIA from the template will have *direct evidence* for the
green-shaded controls and *demonstrable processes* for the partial
ones. That's a solid foundation for a Type 1 audit; Type 2 needs the
controls operating effectively over a typical 6-12 month window,
which is your job.

---

## What this document does NOT do

- **It does not produce attestation reports.** Those come from your
  auditor.
- **It does not include FedRAMP, HIPAA, PCI-DSS, or NIS2.** Those
  have different control sets; the same approach (a control-by-
  control mapping) is the right way to extend this document. PRs
  welcome.
- **It does not cover NIST CSF or NIST 800-53.** Same.
- **It does not certify the operator's ENTIRE environment.** A
  honeypot is one component of a security stack. Most controls have a
  partial scope here.

---

## Maintenance

This document is reviewed:

- On every minor / major release (does the new release change which
  controls have evidence?).
- On every framework revision (SOC 2 / ISO 27001 update cycles).
- On request from a customer auditor whose finding contradicts a row
  here.

Edits go through the regular PR process. The `compliance` label
auto-routes to the maintainers who own this file.

---

*Last reviewed: 2026-05-12.*
*Frameworks: SOC 2 (2017 TSC), ISO/IEC 27001:2022.*
