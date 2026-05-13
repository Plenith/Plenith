# Mission

Plenith exists to make defensive deception practical for organizations
that could not otherwise afford it, and to redirect a meaningful share
of any proceeds from this work to children's development.

This document is the durable statement of that mission. Strategy, product,
roadmap, and partnerships all answer to it.

---

## Why this exists

Two facts shape the field:

1. **Credential theft and lateral movement are the dominant intrusion
   patterns** in real breaches. The Verizon DBIR, Mandiant M-Trends, and
   nearly every public incident retrospective have said this for a
   decade. Most SOCs still respond reactively, after compromise.
2. **The tools that catch attackers earlier — deception platforms —
   have historically been priced for large enterprises only.** A small
   bank, a community hospital, a school district, a regional utility,
   or a non-profit handling sensitive data cannot realistically procure
   Acalvio or Illusive. They get the same threat and a fraction of the
   defensive surface.

Plenith is a deliberate attempt to put the deception tool in the
hands of the defenders who currently can't pay for one. The core is
open source, will remain open source, and is documented in enough
depth that a small operator can deploy it without buying anything from
us.

We also recognize that durable software needs durable funding. The
sections below describe how we intend to be commercially sustainable
without compromising the open-source promise.

---

## What is open source forever

The following will always be available under the Apache 2.0 License
(see `LICENSE`):

- The orchestrator and every component required to run it end-to-end:
  SSH proxy, persona engine, response cache, LLM client, heuristics,
  responses, content rotator, multi-tenancy, plugin system, audit
  chain, retention, secrets resolver, REST API, dashboard, all
  connectors (SIEM / SOAR / threat-intel), MFA bridge, training
  scaffolding.
- The hardening artifacts: seccomp, AppArmor, nftables rules.
- The compliance documentation: DPIA, data-handling reference,
  threat model, ADRs, runbooks, hardening guide.
- All test suites.
- All future bug fixes and security patches to the above.

We will not relicense the core in any direction less permissive. We
will not move features from the core into a paid layer. We will not
add license keys, telemetry, or activation servers to the core.

---

## What may be commercial

These are the areas where we intend to fund the work without
compromising the open-source promise:

1. **Compliance bundles** — pre-filled DPIA, SOC 2 / ISO 27001 control
   mappings, audit-evidence templates, threat-model variants per
   vertical. Sold as one-time deliverables.
2. **Vertical persona packs** — banking, healthcare, federal, OT/ICS.
   Refreshed annually. The default persona library remains in the
   open-source core.
3. **Managed deployment + tuning** — professional services for orgs
   that need help getting Plenith deployed and integrated with
   their existing SOC tooling.
4. **Threat-intel feed** — an opt-in subscription to the aggregated,
   anonymized IoC stream contributed by other deployments. Subscribers
   see what's hitting other Plenith installations; the orchestrator
   itself remains free.
5. **Trained policy checkpoints** — periodic updates to the V2
   action-selection policy, trained on aggregate engagement data from
   subscribers who opt in. The training pipeline ships in the core;
   the trained weights are the paid artifact.
6. **Premium support** — direct access to the maintainers under SLA.

Anything else we contemplate must answer to the open-source-forever
promise above.

---

## The children's-development commitment

A meaningful portion of net proceeds from the commercial offerings
above is committed to supporting children's development. The specifics
follow.

### The pledge

**No less than 30% of net commercial revenue** (defined as gross
revenue from the offerings listed above, minus direct operating costs
of delivering them) will be allocated to children's-development
initiatives.

This is a floor, not a ceiling. It applies regardless of revenue
level — including in early years when revenue is small. If we cannot
operate the business on the remaining 70%, we will scale operations
down, not scale this commitment down.

### What "children's development" means

To prevent mission drift, this is the operational definition used:

- **Early childhood education** — programs serving children up to age
  8, with emphasis on under-resourced communities.
- **Literacy and numeracy support** — formal or non-formal programs
  helping children acquire core academic skills.
- **Health, nutrition, and safety** — programs that address the
  conditions that allow children to learn.
- **Direct family support** for the parents and caregivers of the
  above children, where that is the necessary intervention.

It does NOT mean:

- Tech-in-schools initiatives, unless they pass the same impact bar
  as the categories above.
- Anything carrying our name or branding (no donor-naming).
- Anything political, religious, or sectarian.
- Anything that requires us to remain visible (the recipients have
  no obligation to acknowledge us).

### Governance

To make this commitment durable rather than aspirational:

1. **Annual reporting.** A public report (this repo, `docs/IMPACT/`,
   published by April 1 each year) listing for the prior calendar year:
   gross commercial revenue, direct operating costs, the resulting
   30%+ floor, the actual amount allocated, and the recipients with
   any disclosable details.
2. **External counsel.** Before the first allocation exceeds $50,000,
   we will establish a 501(c)(3) sponsor relationship or equivalent
   non-profit structure so the allocation is held under independent
   governance rather than at our discretion.
3. **Right to amend, not weaken.** This document may be amended to
   strengthen the commitment (raise the percentage, broaden the scope,
   improve governance) but not to weaken it. Any reduction below the
   30% floor or removal of governance requires a majority vote of all
   contributors who have submitted ten or more accepted commits to
   the core, with public posting of the proposed change at least 60
   days before any vote.

### Why a written commitment

Founders frequently express intentions like this; few survive contact
with growth pressure, term sheets, or acquirer demands. We are writing
it down here so that:

- New contributors can read the mission before contributing.
- Customers can know what their dollar funds.
- Future versions of us are bound by it.
- A potential acquirer will know it travels with the project.

If a commercial transaction is ever offered that would dissolve this
commitment, the right answer is to decline that transaction.

---

## What we will not do

To make the mission credible, some things have to be off the table:

- **No relicensing to a less permissive license.** Not "BSL-with-a-
  4-year-Apache-fallback," not "FSL," not Elastic License v2.
- **No telemetry, no phone-home, no license checks** in the core.
  Operators run it on their network without us seeing them.
- **No vendor lock-in features** that exist only to make migration
  away from Plenith expensive.
- **No opaque pricing.** Commercial offerings will have published
  prices and self-serve onboarding wherever possible.
- **No selling attacker data we collect.** Engagement data is the
  operator's. Even anonymized IoCs are shared only with their opt-in.
- **No deceptive marketing** about effectiveness. Claims will be
  backed by reproducible benchmarks (see `tools/bench.py` and the
  baseline at `state/bench/baseline.json`).

---

## How to challenge this

If you think we're drifting:

- **Open an issue** with the `mission` label. The maintainers will
  respond within 30 days. If you're satisfied, we close it; if not,
  you're free to keep it open and publicly visible.
- **Read the annual impact report** (when it begins). If the numbers
  don't reconcile with public-revenue claims, say so.
- **Fork.** The Apache 2.0 license guarantees this option. If we ever
  fail the mission so badly that a fork is the right answer, the
  project will have failed and the right thing is for it to continue
  under different stewardship.

---

## Acknowledgement

We did not invent intrusion deception, hash-chained audit logs,
mandatory-access-control profiles, or LLM-driven response generation.
The platform stands on prior art from honeypot researchers, the
Wazuh / T-Pot communities, every author of the dependencies in
`requirements.txt`, and the security-research community generally.
Where we have made specific decisions that differ from prior art, the
reasons are documented in `docs/adr/`.

---

*Last updated: 2026-05-12.*
*This document is binding on the project as described above; amendment
requires the procedure under "Governance" §3.*
