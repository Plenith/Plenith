# Maintainers

This file lists the humans currently responsible for the Plenith
project. The roles and the path to becoming a maintainer are
defined in [`GOVERNANCE.md`](GOVERNANCE.md).

If you need to reach a maintainer:

- For bugs or feature requests, open an issue.
- For security reports, follow [`SECURITY.md`](SECURITY.md).
- For code-of-conduct concerns, email
  `conduct@plenith.io`.
- For commercial inquiries, open an issue with the `commercial`
  label.
- For anything else, GitHub Discussions.

---

## Current maintainers

> **Note**: this section is intentionally left thin pre-launch. As
> humans formally take on maintainer responsibilities, they're
> added here with their GitHub handle, area of focus, time zone,
> and an optional pronouns line. Mission Stewards are marked with
> ⭑.

<!-- TEMPLATE — replace before publishing
| Name | GitHub | Role | Focus areas | Time zone |
| :--- | :--- | :--- | :--- | :--- |
| <Name> ⭑ | [@handle](https://github.com/handle) | Founder, Mission Steward | Orchestrator, mission | UTC-5 |
| <Name>   | [@handle](https://github.com/handle) | Maintainer | Connectors, integrations | UTC+1 |
-->

| Name | GitHub | Role | Focus areas | Time zone |
| :--- | :--- | :--- | :--- | :--- |
| _to be filled_ | — | Founder, Mission Steward ⭑ | All | — |

The minimum number of Mission Stewards (per `GOVERNANCE.md`) is
**three**. Until that threshold is met, the project operates with
the founder as sole Mission Steward; this is documented as a known
gap that the first two additional Mission Stewards close.

---

## Emeritus maintainers

Maintainers who have stepped down but were active contributors at
some point. We list them as a thank-you and for historical record.

_None yet. Once people step down voluntarily, they go here._

---

## Responsibilities

Maintainers commit to:

1. **Triage incoming issues within 14 days**. "Triage" doesn't mean
   resolve — it means tag, ask clarifying questions, route to the
   right person, or close as out-of-scope. Issues that go untouched
   for >14 days indicate a maintainer-capacity problem we need to
   address.
2. **Review pull requests** within a reasonable time (target 7
   days for normal-size PRs; longer for ADRs that benefit from
   sitting).
3. **Keep the test suite green**. Maintainers do not merge PRs
   that fail CI. Maintainers don't push directly to main.
4. **Apply the code of conduct evenly**. If a contributor's
   behavior crosses lines, deal with it according to
   `CODE_OF_CONDUCT.md` — even if that contributor is a major
   reviewer or sponsor.
5. **Defer to ADRs on architecture changes**. If a PR proposes a
   non-trivial design change, ask for an ADR first.
6. **Respect the mission**. If a proposed change would weaken the
   open-source-forever promise or the children's-development
   pledge, the maintainer's job is to push back (and surface it to
   the Mission Stewards if necessary).

Maintainers do NOT commit to:

- Working a specific number of hours per week
- Being on-call for outages (this is an OSS project; commercial
  support is a separate offering)
- Reviewing every PR personally (we share load)
- Being available during specific hours (we're async)

---

## Path to becoming a maintainer

See [`GOVERNANCE.md` § "Becoming a maintainer"](GOVERNANCE.md). The
short version:

- Submit substantive contributions for ~3 months
- Demonstrate good judgment in review participation
- Operate within the mission
- Get nominated by an existing maintainer
- No Mission Steward objects within 14 days

The maintainer team is intentionally not a fixed size. We add
people when there's both a person ready and work that needs them.

---

## A note on compensation

Plenith maintainers are not paid by the project for maintainer
work. Some maintainers may be paid through the commercial offerings
(`COMMERCIAL.md`) for specific work — e.g. delivering a managed
deployment, building a compliance bundle, providing premium support
to a paying customer. That commercial-engagement work is separate
from open-source-maintainer responsibilities and is governed by
each maintainer's own arrangement with the maintainer organization.

This separation matters because:

1. The OSS core remains open-source-forever regardless of who pays
   anyone for anything.
2. Commercial work supports the mission; the 30% pledge applies to
   net revenue from that work.
3. Maintainer status is not for sale. Being a paying customer does
   not make anyone a maintainer; being a maintainer does not
   require being a paying customer.

---

## How this list is maintained

Changes to this file (adding a maintainer, transitioning to
emeritus, etc.) are made via PR. Each change requires:

- For adding: a Mission Steward's approval (per the maintainer-
  becoming process)
- For voluntary departure: just the maintainer themselves opening
  the PR
- For involuntary removal: documented process per `GOVERNANCE.md`

The file is reviewed annually by the Mission Stewards to confirm
the listed humans are still active. Inactive maintainers (no
contributions for >12 months without explicit "on hiatus" notice)
are moved to Emeritus.

---

*Last updated: 2026-05-12.*
