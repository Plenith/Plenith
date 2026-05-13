# Data Handling Reference

The DPIA (`docs/DPIA.md`) is the formal risk assessment. This file is
the engineer-readable companion: for each kind of data Plenith
touches, what we collect, where it lives, how long, who can read it,
and how it's deleted.

If you're filling out a vendor risk questionnaire for a customer, this
page maps directly to the questions they're going to ask.

---

## Data categories

| ID | Category | Example fields | Sensitivity | Lawful basis |
| :--- | :--- | :--- | :---: | :--- |
| D1 | Network identifiers | source IP, port, ASN | Low | Art. 6(1)(f) |
| D2 | Auth metadata | claimed user, pubkey fingerprint, pw-hash | Medium | Art. 6(1)(f) |
| D3 | Command stream | every command typed in a session | Medium | Art. 6(1)(f) |
| D4 | Behavioral telemetry | inter-command timing, dwell time, lexical signals | Low | Art. 6(1)(f) |
| D5 | LLM context | system prompt + ground truth + recent history | Medium | Art. 6(1)(f) |
| D6 | Derived intelligence | engagement narratives, action history | Low | Art. 6(1)(f) |
| D7 | IoC archive | hashed IPs, malware hashes, exfil domains | Low | Art. 6(1)(f) |
| D8 | Operator audit | API caller identity + action | Medium | Art. 6(1)(b) |
| D9 | Operational metrics | counters from /metrics endpoint | Low | Legitimate interest |
| D10 | Plugin output | site-local plugin observations | Site-dependent | Site-dependent |

---

## Lifecycle table

For each category: where it's written, max retention, the actual
purging mechanism, and what happens if you're asked to remove a
specific record.

### D1 — Network identifiers

| Aspect | Value |
| :--- | :--- |
| Written by | `plenith/ssh_server.py` → `Session.__init__` |
| Storage path | `state-docker/logs/<host>/<engagement>.json` (raw) |
| Format | Plain JSON — `source_ip`, `connection_count` |
| Retention (default) | **90 days** raw, then converted to HMAC hash and retained for 1 year as IoC |
| Enforcement | `plenith/retention.py` via daily cron `tools/retention_purge.py` |
| Access control | Filesystem (POSIX) + multi-tenant API filtering (`plenith/multitenancy.py`) |
| Deletion (DSR) | `python tools/retention_purge.py --filter source_ip=X.Y.Z.W --confirm` |
| Cross-border transfer | None by default. If using cloud LLM, the IP does NOT leave the host (we strip it from LLM context). |

### D2 — Auth metadata

| Aspect | Value |
| :--- | :--- |
| Written by | `plenith/ssh_server.py` |
| Storage path | Engagement log (same as D1) |
| Format | `claimed_user` (plaintext), `pubkey_fingerprint` (already hash), `password_hash` (SHA-256 of plaintext at capture) |
| Retention (default) | 90 days |
| Special handling | **Passwords are NEVER stored plaintext, not even momentarily on disk.** SHA-256 happens before the value crosses the socket boundary in any logged field. |
| Deletion (DSR) | Same `retention_purge.py --filter` mechanism |

### D3 — Command stream

| Aspect | Value |
| :--- | :--- |
| Written by | `plenith/session.py` → `commands` list per session |
| Storage path | Engagement log (same as D1) |
| Format | `commands: [{cmd, ts, source}]` — full text of every command |
| Retention (default) | 90 days |
| Sharing | Commands are NOT shared with the threat-intel community (only IoC derivatives). Commands MAY be shared with the customer SIEM if so configured. |
| LLM context | When LLM is invoked, the **recent** command window is in the LLM prompt context. Local LLM by default → no third-party transfer. Cloud LLM → covered by your DPA with the provider. |
| Deletion (DSR) | Same mechanism |

### D4 — Behavioral telemetry

| Aspect | Value |
| :--- | :--- |
| Written by | `plenith/counter_ai.py`, `plenith/session.py` |
| Storage path | Engagement log under `observed.*` keys |
| Format | Floats / counts (timing rhythm, lexical purity, injection counts) |
| Retention (default) | 90 days alongside its engagement |
| Notes | This data is aggregated; an individual command's timestamp is in D3, the derived rhythm score lives here. |

### D5 — LLM context

| Aspect | Value |
| :--- | :--- |
| Written by | `plenith/llm_client.py` |
| Persistence | **Not persisted by default.** The full prompt is constructed in memory, sent to the LLM endpoint, response captured, prompt discarded. |
| Tracing | OpenTelemetry spans record prompt SIZE in characters, NOT content. See `plenith/tracing.py:llm_call_span`. |
| LLM endpoint | Local (LM Studio/Ollama) by default → no third party. Cloud → see provider's DPA. |
| Cloud-LLM warning | If you configure a cloud endpoint, the system-prompt template + ground-truth files + recent commands are sent to that provider. Treat as a sub-processor under your DPA. Add to your record of processing. |

### D6 — Derived intelligence

| Aspect | Value |
| :--- | :--- |
| Written by | `plenith/narrate.py`, `plenith/heuristics.py` (action list) |
| Storage path | Engagement log under `narrative` and `actions_taken` |
| Retention (default) | 90 days alongside its engagement |
| Integrity | Hash-chained via `plenith/audit_chain.py`. Modifications detectable. |

### D7 — IoC archive

| Aspect | Value |
| :--- | :--- |
| Written by | `plenith/connectors/stix.py` (when STIX/TAXII publishing enabled) |
| Storage path | `state/ioc-archive/<year>/<month>.jsonl` |
| Format | STIX 2.1 SDOs (Indicator, Observed-Data) |
| Anonymization | Source IPs hashed (HMAC-SHA-256 with per-deployment key). Command content NOT included. |
| Retention (default) | **1 year.** Long retention is intentional — IoCs are the durable artifact of intrusion observation. |
| Sharing | Opt-in via TAXII publish config. Receiving parties are joint controllers for their copy. |
| Deletion (DSR) | Hashed IPs are technically pseudonymized; un-hashing requires the deployment key. If a deployment key is rotated, prior IoCs become non-attributable. Document this in your DPA. |

### D8 — Operator audit

| Aspect | Value |
| :--- | :--- |
| Written by | `plenith/api/server.py` middleware |
| Storage path | `state/audit/api_<date>.jsonl` |
| Format | One line per API call: timestamp, principal (token claim), method, path, status |
| Retention (default) | **2 years** — operator audit retention is intentionally longer for compliance. |
| Access control | Read access requires `admin` role. |

### D9 — Operational metrics

| Aspect | Value |
| :--- | :--- |
| Exposed at | `/metrics` (Prometheus exposition format) |
| Content | Counters / gauges. No personal data. (`plenith_engagements_total` is a count; it does not name engagements.) |
| Retention | Per Prometheus configuration, typically 15–90 days. Out of scope of this app. |
| PII risk | None — all values are aggregates. |

### D10 — Plugin output

| Aspect | Value |
| :--- | :--- |
| Source | Third-party plugins (see `docs/PLUGINS.md`) |
| Storage | Plugin-determined |
| Notes | **Plugins are your responsibility.** A plugin that ships attacker data to a third-party API is a new processor under YOUR control. Audit before deploying. |

---

## Retention policy summary

The defaults align with §13 of Plenith.md (Operational policies):

| Data | Retention | Set in | Purger |
| :--- | :---: | :--- | :--- |
| Engagement logs (D1-D6) | 90 d | `config.yaml: retention.engagements_days` | `retention_purge.py` |
| IoC archive (D7) | 365 d | `config.yaml: retention.ioc_days` | `retention_purge.py` |
| API audit (D8) | 730 d | `config.yaml: retention.api_audit_days` | `retention_purge.py` |
| Heartbeats | 7 d | `config.yaml: retention.heartbeats_days` | `retention_purge.py` |
| Response cache | 180 d | `config.yaml: retention.cache_days` | `retention_purge.py` |
| Engagement state (in-flight) | While engagement is active + 30 d quiescence | `plenith/state_store.py` | Built-in |

Operators may **shorten** any of these, never lengthen them above the
documented maximums without re-running the DPIA.

---

## Subject Access Request workflow

1. **Verify identity** of the requester. (Out of scope for this app.)
2. **Locate records:**
   ```bash
   python tools/audit.py --source-ip <IP> --since <date>
   ```
   or, if you have a non-IP correlator (e.g. an email address the
   subject pasted into a session):
   ```bash
   grep -lr "<correlator>" state-docker/logs/
   ```
3. **Review for third-party content.** If the records mention a
   second IP (e.g. an attacker's pivot host that isn't the subject),
   redact before disclosure.
4. **Provide records** in a machine-readable format (JSON is fine —
   the engagement log IS the disclosure format).
5. **Document the request** in `state/audit/dsr_requests.jsonl` with
   the date, the action taken (provided / refused / partial), and the
   justification.

## Data breach notification workflow

If you suspect personal data has been exposed (e.g. a vulnerability in
the API has allowed unauthorized access, or a backup was leaked):

1. **Within 1 hour:** notify your internal incident response.
2. **Within 24 hours:** scope assessment — which records were
   accessible? For how long? By whom?
3. **Within 72 hours:** if the breach is "likely to result in a risk
   to the rights and freedoms" of subjects, notify your supervisory
   authority. GDPR Art. 33.
4. **As soon as practical:** notify affected individuals if "high
   risk." GDPR Art. 34.

This app provides the forensic evidence (engagement logs + API audit)
to support the assessment. It does not replace your incident response
process.

---

## Quick reference

If someone asks…

| Question | Answer is in… |
| :--- | :--- |
| "Do you collect IP addresses?" | D1 |
| "How long do you keep the data?" | Retention summary above |
| "Can I get my data removed?" | DSR workflow above |
| "Where is the data physically stored?" | On the host you control — there's no Plenith SaaS |
| "Do you share with the US?" | Not by default. Cloud LLM is the only third-party path; opt-in. |
| "What's your DPIA?" | `docs/DPIA.md` |
| "What's your breach process?" | See above |
| "Are you SOC 2 / ISO 27001 / FedRAMP certified?" | Plenith the software does not hold these certifications. Your deployment of Plenith inherits your organization's certifications — the controls table in DPIA §6 maps the app's contributions. |

---

Last reviewed: 2026-05-12. Re-review on retention policy change or
DPIA re-run.
