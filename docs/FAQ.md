# Frequently Asked Questions

The questions we anticipate getting most often, with prepared,
honest answers. Updated as new questions surface.

If your question isn't here, open a GitHub Discussion — and if
the question comes up more than twice, we'll add it here.

---

## Free, open source, and revenue

### Is Plenith really free forever?

**Yes**, the open-source core is permanently free under Apache
License 2.0. This is the durable commitment in
[`MISSION.md`](../MISSION.md) and [`LICENSE`](../LICENSE).
Specifically, the maintainer organization has committed in writing
to:

- Never relicense the core to a less permissive license
- Never move features from the core into a paid tier
- Never add license keys, telemetry, or activation servers to
  the core
- Apply all future security patches and bug fixes under the
  same Apache 2.0 license

The full enumeration of what's permanently OSS lives in
[`COMMERCIAL.md`](../COMMERCIAL.md).

### What's the catch?

**There isn't one — that's the design.** The commercial offerings
(see below) are *services and content around the engine*, not
gatekeeping of the engine. You can run Plenith forever, on as
many hosts and engagements as you want, without paying anyone.

### So how does the project make money?

Through seven categories of commercial offering — none of which
gate the OSS core:

1. **Compliance bundles** — pre-filled DPIA, SOC 2 / ISO 27001
   control mapping, audit-evidence packets
2. **Vertical persona packs** — industry-specific synthetic
   personas (banking, healthcare, federal, OT)
3. **Managed deployment** — we deploy + tune + operate for the
   first 90 days
4. **Threat-intel feed subscription** — aggregated, anonymized
   IoC stream from opted-in deployments
5. **Trained policy checkpoints** — periodic updates to the V2
   action-selection policy
6. **Premium support** — SLA-backed direct access to maintainers
7. **Future**: hosted dashboard (v2.x), training + certification
   (post-2.0)

Full details in [`COMMERCIAL.md`](../COMMERCIAL.md).

### What's the 30% pledge?

A binding commitment that **at least 30% of net commercial revenue**
goes to children's-development initiatives. Specifically defined in
[`MISSION.md`](../MISSION.md) § "The children's-development
commitment":

- Early childhood education programs
- Literacy and numeracy support
- Health, nutrition, and safety
- Direct family support for caregivers of the above

Annual public reporting in `docs/IMPACT/` documents how the
money flowed each year. The 30% is a floor, not a ceiling.

### What stops you from quietly changing the 30% pledge?

The amendment procedure in `MISSION.md` § "Governance":

- Any weakening change requires 60 days of public notice
- A majority vote of contributors with 10+ accepted commits
- The procedure itself cannot be amended unless the new procedure
  is stricter

It's not impossible to change, but it's not silent and not fast.
That's the point.

### What happens to the pledge if you're acquired?

Per [`GOVERNANCE.md`](../GOVERNANCE.md) § "Succession planning":

- Acquisition is a mission-affecting decision
- Requires the same 60-day notice + majority vote
- The acquirer must publicly accept the mission (open-source-
  forever, trademark policy, 30% pledge) **in writing before the
  acquisition closes**
- If an acquisition is contingent on dissolving the commitments,
  the answer is "no"

The legal mechanism is the trademark + mission charter, not the
maintainer's personal goodwill. Even if every original maintainer
left, the commitments survive in the chartering documents.

---

## Architecture and security

### Is the LLM watching my commands?

No — the LLM only sees:

1. The synthetic persona's system prompt
2. The attacker's commands and recent context
3. Ground-truth file contents we deliberately exposed

It does NOT see anything from your real production systems,
because Plenith doesn't have access to them. The decoy bubble is
network-isolated from your production network — see
`docs/HARDENING.md` § 1 and `docs/THREAT_MODEL.md`.

### Do you collect telemetry?

**No telemetry, no phone-home, no analytics.** The orchestrator
runs entirely on your infrastructure with no callback to us.

You can verify this:
- `grep -r "telemetry\|callback\|phone" plenith/` returns nothing
- The SBOM enumerates every runtime dependency
- The CI build is reproducible from the signed release tag

### Can I use a cloud LLM (OpenAI, Anthropic, etc.)?

Yes, technically — the LLM client speaks OpenAI-compatible
protocol so any compatible endpoint works. But: doing so means
attacker command streams and recent context leave your network
and go to the cloud provider. Most enterprises decline this for
sensitive deployments.

The default and recommended path is a **local LLM** (LM Studio,
Ollama, or self-hosted vLLM) so engagement data never crosses
your perimeter. See `docs/DATA_HANDLING.md` § D5 for the data-
flow analysis.

### What data do you keep, and for how long?

Documented in `docs/DATA_HANDLING.md`. Summary:

| Category | Default retention |
| :--- | :--- |
| Engagement logs (commands, observations) | 90 days |
| Engagement state (in-flight session data) | 120 days |
| IoC archive (hashed IPs, malware hashes) | 365 days |
| API audit log (operator actions) | 730 days |
| Agent heartbeats | 7 days |
| Response cache | 180 days |

All retention windows are operator-configurable. Enforcement is
automatic via `tools/retention_purge.py` on a daily cron.

### What about GDPR?

Full DPIA at `docs/DPIA.md`. Highlights:

- Lawful basis: Art. 6(1)(f) (legitimate interest in network
  security)
- Subject-access-request workflow documented; uses
  `tools/audit.py` + `tools/retention_purge.py --filter`
- Source IPs hashed in long-term IoC archives
- No transfer to third countries by default (with local LLM)

### Has it been audited / pen-tested?

**Not yet** — this is one of the openly-documented gaps in the
roadmap. The release-1.0 self-attestation includes:

- Hash-chained audit log (tamper-evident by construction)
- 938 tests in CI
- A documented threat model + STRIDE walk-through
- An ADR-recorded design history
- Signed releases with SLSA provenance

A third-party pen-test report is on the v1.1 roadmap. We will
publish the result (good or bad) when it lands.

### How does it compare to Acalvio / Illusive / CounterCraft?

| Feature | Plenith | Acalvio | Illusive | CounterCraft |
| :--- | :--- | :--- | :--- | :--- |
| License | Apache 2.0 | Commercial | Commercial | Commercial |
| Self-hosted | ✓ | ✓ | ✓ | ✓ |
| Per-host runtime fees | None | Per-host | Per-host | Per-engagement |
| LLM-driven response generation | ✓ | Limited | — | Limited |
| Counter-AI detection (LLM-driven attacker detection) | ✓ | — | — | — |
| Hash-chained audit log | ✓ | — | — | — |
| Public source | ✓ | — | — | — |
| Mission-driven non-profit allocation | 30% pledge | — | — | — |

This is comparison-with-honesty: established competitors have more
operational maturity, more enterprise references, longer pen-test
histories. We have transparency, no per-host pricing, and the LLM
+ counter-AI angle. Different bets.

---

## Operations

### How long does a real deployment take?

- **Single-host MVP** (Tier 1 in `DEPLOYMENT_GUIDE.md`): ~5 minutes
- **docker-compose multi-host fabric** (Tier 2): ~30 minutes
- **Production Kubernetes** (Tier 3): ~1 day including hardening
- **Production + integration with your SIEM + alerting**: ~1 week

The 1-week number assumes your team is familiar with Kubernetes
+ Helm + Prometheus. If you're newer to those, longer.

### What does the SOC analyst actually see?

A web dashboard at `:8765` that auto-refreshes via Server-Sent
Events. Shows:

- Live engagement list, severity-ranked
- Per-engagement narrative + action history
- Container status + DNS query log
- Severity tally across all engagements
- Deployment metadata (corp identity, content signature)

For deeper triage, the analyst stays in their existing SIEM
(Splunk / Wazuh / Sentinel / Elastic). Plenith ships CEF-formatted
alerts there via the SIEM connector; the analyst clicks through
to Plenith's dashboard for live context when an alert needs it.

### Can I integrate with my existing SOAR?

Yes. Plenith ships a generic SOAR webhook connector
(`plenith/connectors/soar.py`). It POSTs alerts as JSON to your
SOAR's ingest URL with retry + dead-letter handling.

For more sophisticated integration, the REST API at `:8000` lets
your SOAR query / mutate engagement state programmatically. See
the OpenAPI spec at `:8000/openapi.json`.

### What about the rest of my SIEM stack?

Out of the box:

- **Splunk HEC** — `plenith/connectors/siem.py:SplunkHEC`
- **Elasticsearch bulk** — `plenith/connectors/siem.py:ElasticBulk`
- **Syslog (TCP / UDP)** — same module
- **Generic webhook** — same module
- **STIX 2.1 / TAXII 2.1** — `plenith/connectors/{stix,taxii}.py`
- **Slack / Teams / generic ChatOps** —
  `plenith/connectors/chatops.py`

Not built in but easy to add via plugins (`docs/PLUGINS.md`):
QRadar, Sentinel-specific, custom internal SIEMs.

### Does it work with my IdP?

For MFA: yes (Duo, Okta — see
`plenith/connectors/mfa_providers.py`). The MFA bridge sits
between attempted authentications and the decoy-vs-real routing
decision.

For API auth: the bearer-token model in v1.0 is simple. v2.x
roadmap adds OIDC / SAML for the REST API; bearer tokens remain
as the option for service accounts.

### How much hardware does it need?

The orchestrator + dashboard + REST API run comfortably on:

- **2 vCPU, 4 GB RAM** for a single-host MVP without a local LLM
- **8 vCPU, 16 GB RAM, 1× consumer GPU** if running a local LLM
  alongside (LM Studio with qwen2.5-7b-instruct-1m needs ~6 GB
  VRAM)
- **Per-decoy container** adds ~256 MB RAM

Disk: ~10 GB for state + logs over a typical 90-day retention
window. More if you log everything and retain longer.

The benchmark baseline + tolerance table is at
`state/bench/baseline.json`.

### Can attackers escape the decoy bubble?

That is the threat model question. See `docs/THREAT_MODEL.md`
for the STRIDE walk-through and the documented attack scenarios.

The summary: the decoy bubble is **network-isolated** (default-
DROP egress per `deploy/network/decoy-bubble-egress.nft`),
**syscall-restricted** (seccomp profile in
`deploy/security/seccomp-agent.json`), and **filesystem-bounded**
(AppArmor profile in `deploy/security/apparmor-agent.profile`).
If an attacker achieves RCE inside a decoy container, those three
layers bound what they can do.

A pivot from a decoy back into the orchestrator host (the worst
case) would require all three layers to fail simultaneously. The
hash-chained audit log (`plenith/audit_chain.py`) ensures that
even if the worst happens, the tampering is detectable from
disk-state alone.

### What's the operational cost in analyst hours?

Real talk: the platform reduces ALERT TRIAGE work compared to
generic-honeypot or naive deception (we pre-classify, score, and
deduplicate), but it does NOT eliminate the need for a human in
the loop.

Realistic per-week numbers in a typical mid-size SOC:

- **Initial deployment** (Tier 3 + integration): 40–80 hours
  one-time
- **Weekly tuning during the first month**: ~5 hours
- **Steady-state operations**: ~1–2 hours/week for routine
  triage, plus incident-driven time when something fires
- **Quarterly content rotation + persona refresh**: ~4 hours

Compare to your existing IDS / SIEM triage hours and budget
accordingly. The platform's value isn't in eliminating SOC labor;
it's in producing higher-fidelity intel for the labor you already
have.

---

## License and compliance

### Can I fork it?

Yes — Apache 2.0 explicitly allows forking. Two trademark-policy
rules apply (see [`TRADEMARK.md`](../TRADEMARK.md)):

1. Rename your fork. Don't call it "Plenith" or a variation
   (Plennith, Plenith X, etc.).
2. Don't use the Plenith logo as your fork's primary brand mark.

You may describe your fork as "derived from Plenith" or "based
on Plenith" — that's truthful descriptive use and is fine.

### Can I use this in a commercial product?

Yes. Apache 2.0 permits commercial use, including bundling
Plenith into a larger commercial offering. The trademark policy
constrains what you can call your product (see `TRADEMARK.md` §
"Naming derived works that integrate with Plenith"), but the
code use is open.

If you build something interesting on top of Plenith, we'd
appreciate hearing about it.

### Will it work for SOC 2 / ISO 27001 audit prep?

Plenith ships with `docs/COMPLIANCE_MAPPING.md` — a control-by-
control mapping for SOC 2 (2017 TSC) and ISO/IEC 27001:2022 Annex
A. This is **not certification** (only your auditor can issue
that), but it's the evidence map your GRC team can hand to the
auditor.

For higher-touch help (custom mapping to your auditor's
framework, audit-evidence packet, threat-model variant for your
vertical), the **compliance bundle** is the commercial offering
that delivers this. See `COMMERCIAL.md`.

### What about FedRAMP / HIPAA / PCI-DSS?

Not directly mapped in v1.0. The COMPLIANCE_MAPPING.md framework
extends naturally to those — PRs welcome, or a custom mapping is
part of the commercial compliance bundle.

### Is there a vulnerability disclosure program?

Yes — see [`SECURITY.md`](../SECURITY.md). Three reporting
channels (preferred: GitHub Private Vulnerability Reporting),
documented response timelines (2 business days to acknowledge,
30 days for high/critical fix, 90 days for medium/low),
explicit safe-harbour for good-faith researchers.

---

## The mission

### Why children's development specifically?

The founder's choice. Not because it's the only worthy cause,
but because it's the cause the founder has the most conviction
about supporting — and the durability of the commitment depends
on the founder caring enough about it that they won't quietly
walk it back when revenue tempts them.

Concentrating the allocation on one category also makes the
accounting clean: each annual impact report can demonstrate
specific outcomes rather than diffuse "social good" spending.

### Why 30% and not a higher / lower number?

30% is a floor. The actual allocation may exceed it. The number
was chosen as the maximum the founder believes is durably
sustainable across business cycles — high enough to be meaningful,
not so high that the business risks failure in a downturn and the
commitment evaporates with it.

If revenue exceeds what the business needs to operate, the
allocation can rise. The procedural lock is on the floor, not
the ceiling.

### Why not 100% ?

Operational continuity. A 100%-allocation project that runs out
of operating budget closes — and then the allocation drops to
zero forever. 30% means the business can keep operating, keep
generating revenue, and keep allocating into year 10, year 20.

A project shooting for sustainable 30% over 30 years allocates
strictly more total dollars than a 100% project that closes in
year 2.

### What if you raise venture capital?

Mission compatibility would be the gate. Per
[`MISSION.md`](../MISSION.md) § "Things we will not do":
relicensing, telemetry, vendor lock-in, deceptive marketing — all
off the table. A VC term sheet that requires any of those is one
we decline.

A VC term sheet that respects the mission (Apache 2.0 forever,
30% pledge intact, governance unchanged) — that's worth talking
about, with the same 60-day public-notice procedure that applies
to any mission-affecting change.

### How do I verify any of these commitments are real?

- Read [`MISSION.md`](../MISSION.md) — the binding statement
- Read [`GOVERNANCE.md`](../GOVERNANCE.md) — the procedural locks
- Read [`LICENSE`](../LICENSE) — the irrevocable Apache 2.0 grant
- Watch for `docs/IMPACT/<year>.md` annual reports — first one
  due 2027-04-01 covering CY 2026
- File an issue with the `mission` label if anything looks off

Trust is built through reproducibility. The commitments are
in version-controlled files; any silent change is detectable in
git log; any explicit change requires the documented procedure.

---

## Community and contributing

### How do I contribute?

See [`CONTRIBUTING.md`](../CONTRIBUTING.md). Short version: fork,
fix, PR. Tests required. CHANGELOG entry for user-visible changes.

### How do I report a security issue?

See [`SECURITY.md`](../SECURITY.md). **Not** as a public issue.

### Who runs this project?

Maintainers listed in [`MAINTAINERS.md`](../MAINTAINERS.md).
Governance defined in [`GOVERNANCE.md`](../GOVERNANCE.md).
Mission Stewards have the binding authority over mission-affecting
decisions.

### Is there a Slack / Discord?

Not yet. GitHub Issues + Discussions are the official channels.
Decisions happen where the public can see them, by design (no
private decision channels for project direction).

---

*Last updated: 2026-05-12.*
*If your question isn't here, [open a Discussion](https://github.com/Plenith/Plenith/discussions).*
