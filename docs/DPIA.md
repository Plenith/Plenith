# Data Protection Impact Assessment (DPIA) — Plenith

**Document type:** GDPR Art. 35 Data Protection Impact Assessment
**Version:** 1.0
**Date:** 2026-05-12
**Scope:** A default Plenith deployment operated by a single
organization for the purpose of intrusion deception on its own network.

> **This DPIA is a template + a worked example.** It assumes the
> default configuration described in this repo. If you tune retention
> windows, expose the dashboard externally, or run Plenith as a
> service for third parties, you MUST redo Section 3 (data flow) and
> Section 5 (risk assessment) for your deployment. Have a qualified
> Data Protection Officer countersign before going to production.

---

## 1. Why a DPIA is required

GDPR Art. 35 requires a DPIA when processing is "likely to result in a
high risk to the rights and freedoms of natural persons." Plenith's
default deployment ticks two of the European Data Protection Board's
nine indicators:

- **Systematic monitoring of a publicly accessible area** — the
  honeypot is, by design, internet-reachable and records every
  inbound connection.
- **Data concerning vulnerable subjects** — attackers may attempt to
  authenticate using credentials they stole from other people; the
  platform observes (incidentally) the credentials those people once
  used.

Two indicators trigger the DPIA requirement. We document the
assessment here.

## 2. Roles

| Role | Identity | Responsibilities |
| :--- | :--- | :--- |
| Data Controller | The operating organization | Decides purpose / means of processing |
| Data Processor | None by default | If you use a managed SaaS LLM, that vendor is a processor — add to your record of processing |
| Joint Controller | None | If you share IoCs with a community (TAXII/STIX), the receiving party is a joint controller for that scoped subset |
| DPO | <name to be filled by deployer> | Reviews this DPIA and signs Section 9 |

## 3. Data flow

### 3.1 Categories of personal data processed

| Category | Source | Fields | Lawful basis (Art. 6) |
| :--- | :--- | :--- | :--- |
| Network identifiers | SSH connections | Source IP, port, TLS fingerprint | Art. 6(1)(f) — legitimate interest in network security |
| Authentication metadata | SSH session | Claimed username, public key fingerprint, password hash (never the plaintext) | Art. 6(1)(f) |
| Command history | SSH session | Every command typed by the attacker | Art. 6(1)(f) |
| Time / behavioral data | SSH session | Inter-command timing, session duration | Art. 6(1)(f) |
| Derived intelligence | Orchestrator | Engagement narrative, action history, severity classification | Art. 6(1)(f) |
| Operator audit | API / dashboard | Operator identity (Bearer token claim), actions taken (e.g. token rotation) | Art. 6(1)(b) — contract with employer |

We **do not** intentionally collect:
- Real names, addresses, biometrics, or other "special category" data
  per Art. 9.
- Payment information.
- Health data.

If an attacker pastes such data into the session (e.g. exfiltrates a
file from somewhere else and uses the decoy as scratch space), it
becomes incidentally collected. See Section 5 risk row "Incidental
special-category data."

### 3.2 Data flow diagram

```
Internet → [SSH proxy] → [Orchestrator] → state-docker/logs (90-day)
                                          state-docker/persistence (90-day)
                                          caches/* (180-day, content-hashed)

[Orchestrator] → [SIEM connector] → Customer SIEM (retention per customer policy)
              → [STIX/TAXII connector] → Threat-intel community (anonymized only)
              → [Heartbeat / metrics] → Customer Prometheus (90-day)
```

The orchestrator is the only component that holds raw, un-aggregated
attacker data on disk. Everything downstream (SIEM, STIX) is either
aggregated or scoped via an opt-in policy.

### 3.3 Recipients

| Recipient | Purpose | Data shared |
| :--- | :--- | :--- |
| Customer SOC team | Operational response | Full engagement record |
| Customer SIEM | Long-term retention per existing policy | Alerts only (not full command history by default) |
| Threat-intel partners (opt-in) | Community defense | IoCs only (IP, hash, domain) — never command content |
| Cloud LLM provider (if used) | Response generation | Prompt context — see Section 5 risk row "LLM context leakage" |
| Plenith maintainers | None (no telemetry) | Nothing — we ship no callback |

## 4. Necessity and proportionality

### 4.1 Necessity

The processing is necessary for the stated purpose (deception-based
intrusion detection) because:

- Without recording attacker commands, we cannot detect compromise.
- Without recording source IPs, we cannot block repeat offenders or
  share IoCs.
- Without recording timing, we cannot detect LLM-driven attackers
  (the counter-AI signal in §5.3 of Plenith.md).

### 4.2 Proportionality

We minimize processing by:

- **Hashing passwords on capture.** The plaintext is never written to
  disk; we store SHA-256.
- **Hashing source IPs in long-term archives.** Engagement logs retain
  the plaintext IP for 90 days for active triage; archived
  intelligence (kept for IoC sharing) uses HMAC-SHA-256 with a per-
  deployment key.
- **Not recording LLM prompt contents at the application layer.**
  Tracing spans (OpenTelemetry) record prompt SIZE, not prompt
  TEXT. See `plenith/tracing.py`.
- **Synthetic personas, not real employees.** The decoy users are
  generated; no real-world person's name, IP, or biometric is used as
  a decoy.

## 5. Risk assessment

### 5.1 Likelihood × severity matrix

| ID | Risk | Likelihood | Severity | Mitigation | Residual |
| :-- | :--- | :---: | :---: | :--- | :---: |
| R1 | Bystander whose IP is in engagement log is identifiable | Medium | Low | 90-day retention; IP-hashing in archive | Low |
| R2 | Attacker pastes real PII into session ("incidental special-category data") | Low | High | Quarterly review of logs to redact known PII; retention purge | Low |
| R3 | LLM context leakage (if using cloud LLM) — attacker payload sent to third party | High (only if cloud LLM in use) | Medium | Use local LLM (LM Studio default); if cloud, DPA with provider | Low |
| R4 | Audit-log tampering hiding a compromise | Low | High | Hash-chained logs (`plenith/audit_chain.py`) | Low |
| R5 | API token compromise → bulk data export of attacker records | Low | Medium | Per-tenant tokens; rate limiting (planned); audit-log on API access | Low |
| R6 | Synthetic-data fingerprinting → attacker identifies the honeypot from disk content | Medium | Low | Content rotation (`plenith/rotation.py`) | Low |
| R7 | Cross-deployment data leakage via backup/restore | Low | High | Deployment-ID stamping in backups; refuse cross-deployment restore | Low |
| R8 | Operator query without legitimate purpose | Low | Medium | RBAC + audit log on dashboard / API queries | Low |
| R9 | Subject access request: legitimate user wants their data removed | Medium | Medium | See Section 7 (DSR procedure) | Low |
| R10 | Retention policy not actually enforced | Medium | Medium | `plenith/retention.py` cron-driven enforcement; tested | Low |

### 5.2 Risks specific to honeypot deployments

The honeypot context creates some tensions not present in routine
processing:

- **Lawful basis tension.** We rely on Art. 6(1)(f) "legitimate
  interest." A bystander whose stolen credentials are tried by an
  attacker has not consented. Our mitigation is minimal retention +
  hashing, and we will not share their identifier with third parties.
- **The "attacker" may be a security researcher.** If you are a public
  -facing organization, "attackers" include legitimate penetration
  testers and curious researchers. Our SECURITY.md provides a safe-
  harbour for the latter; the policy is binding.
- **Cross-jurisdictional traffic.** A deployment in the EU may
  record commands from attackers in any jurisdiction. We process the
  data where it lands (EU) under EU law; we do not transfer raw data
  out of the EU by default (no managed-SaaS dependency by default).
- **Right to be forgotten by attackers.** We assert legitimate
  interest in security takes priority over Art. 17 (erasure) for the
  raw forensic record. Anonymized derivatives (IoCs) are kept longer;
  raw records expire on the documented schedule regardless.

## 6. Technical and organizational measures

Cross-references throughout the repository:

| Control area | Documented at |
| :--- | :--- |
| Access control (auth) | `plenith/api/auth.py`, `plenith/multitenancy.py` |
| Encryption in transit | TLS termination via reverse proxy; documented in `docs/QUICKSTART.md` |
| Encryption at rest | Out of scope at the application layer — use full-disk encryption on the host |
| Audit logging | `plenith/audit_chain.py`, hash-chained on disk |
| Backup + integrity | `tools/backup.py`, `tools/restore.py` (SHA-256 manifest) |
| Retention enforcement | `plenith/retention.py`, `tools/retention_purge.py` |
| Network isolation | `deploy/network/decoy-bubble-egress.nft` |
| Runtime confinement | `deploy/security/seccomp-agent.json`, `deploy/security/apparmor-agent.profile` |
| Vulnerability management | `SECURITY.md`, `.github/dependabot.yml` |
| Supply-chain integrity | Signed releases — `docs/VERIFY_RELEASES.md` |
| Threat model | `docs/THREAT_MODEL.md` |

## 7. Data subject rights

### 7.1 Right of access (Art. 15)

A subject requesting access to their personal data must provide:
identification, the source IP they were using at the time, and a time
window. The operator runs:

```bash
python tools/audit.py --source-ip <ip> --since <date> --json
```

The output is the subset of engagement records matching that IP. The
operator reviews for irrelevant / third-party content before disclosure.

### 7.2 Right to erasure (Art. 17)

We resist erasure for legitimate security interest under Art. 17(3)(e).
For requests we agree to honor (e.g. demonstrably mistaken inclusion
of a legitimate user's IP):

```bash
python tools/retention_purge.py --filter source_ip=<ip> --confirm
```

This removes engagement records matching the predicate. The hash chain
is preserved by re-stamping (see retention module docs).

### 7.3 Right to rectification (Art. 16)

Engagement records are immutable forensic data. Rectification of
factually wrong content is via deletion + re-creation only if the
subject can prove the original was inaccurate.

### 7.4 Right to object (Art. 21)

Subjects may object to processing. We balance objection against the
legitimate-interest basis; in practice most objections from real
attackers are not honored. Objections from non-attackers caught
accidentally are honored under the erasure procedure.

## 8. Data Protection Officer review

| Field | Value |
| :--- | :--- |
| DPO name | <to be filled> |
| Review date | <to be filled> |
| Approval status | <approved / approved with conditions / rejected> |
| Conditions (if any) | <…> |
| Next review due | <today + 12 months> |
| Signature | <…> |

## 9. Change history

| Version | Date | Changes |
| :--- | :--- | :--- |
| 1.0 | 2026-05-12 | Initial DPIA published with Plenith 1.0 |

---

## Appendix A — minimum prior-consultation checklist (Art. 36)

If your DPIA identifies a high residual risk that you cannot mitigate,
you must consult the supervisory authority before processing.

After completing Sections 1–8 above, score residual risk:

- [ ] All risks in Section 5 reduced to Low residual? → **No
  consultation required.**
- [ ] Any risk remains Medium residual? → Document mitigation plan;
  no consultation required but re-review in 6 months.
- [ ] Any risk remains High residual? → **Consult the supervisory
  authority** before deploying.

In a typical Plenith deployment, all risks reduce to Low residual
once the retention policy, hash-chained audit log, and network
isolation are enforced.
