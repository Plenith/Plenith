# Governance

This document describes how decisions get made on the Plenith
project: who has authority over what, how contributors become
maintainers, how disputes resolve, and how the project ensures the
mission (`MISSION.md`) survives changes in leadership.

The model is **intentionally simple for v1.0**: a small maintainer
team operates as a benevolent collective. As the project grows,
this document will be amended to add structure (technical steering
committee, sub-project owners, formal voting body). We are
deliberately NOT building governance theater ahead of need.

The one thing we ARE building from day one is the **mission-
protection layer**: governance that prevents future versions of us
from dissolving the open-source-forever promise or the
children's-development pledge.

---

## Roles

### Contributor

Anyone who has submitted any merged change to the project — code,
documentation, runbook update, ADR, anything. Contributors have:

- Authority to open issues, pull requests, and discussions
- Standing in conduct disputes (`CODE_OF_CONDUCT.md`)
- Right to be consulted on mission-affecting amendments (see below)
- The right to fork under Apache 2.0 if they disagree with project
  direction

### Maintainer

A contributor with merge access to the main branch. Maintainers
have:

- Authority to merge pull requests after review
- Authority to release new versions (tag + sign)
- Authority to enforce the code of conduct
- Responsibility to triage incoming issues within 14 days
- Responsibility to keep the project's mission visible in
  technical decisions

Maintainers are listed in `MAINTAINERS.md`.

### Mission Steward

A subset of maintainers (typically 2–5 people) who additionally
have authority over mission-related decisions:

- Approval of commercial-offering definitions (per `COMMERCIAL.md`)
- Approval of impact-report content (`docs/IMPACT/`)
- Approval of the annual allocation to children's-development
  initiatives
- Final say on any amendment to `MISSION.md`, `TRADEMARK.md`, or
  `GOVERNANCE.md`

Mission Stewards are listed in `MAINTAINERS.md` with the
"steward" annotation. The minimum number of Mission Stewards is
**three**; the maximum is **seven** (to keep the body decisive).

---

## How decisions get made

### Day-to-day technical decisions

**Lazy consensus**. A maintainer proposes a change (PR or issue),
gives other maintainers reasonable time to object (typically 72
hours for non-urgent changes), and merges if no one objects. This
is the same model the Linux kernel and most ASF projects use.

Disagreements escalate to a maintainer huddle (async or
synchronous). If the huddle can't resolve, the maintainer with
domain ownership decides; for cross-cutting decisions, a Mission
Steward arbitrates.

### Significant technical decisions

Anything that meets ONE of:
- Changes the public API (REST, plugin, connector, on-disk format)
- Adds a new runtime dependency
- Changes the build / release / signing process
- Affects the threat model or compliance mapping
- Affects performance on the orchestrator hot path

Goes through an **ADR**. Format: `docs/adr/NNN-short-name.md`
following the Nygard structure (Context, Decision, Why,
Consequences). The PR introducing the ADR is the discussion
forum. Once accepted, the ADR is permanent — superseding ADRs are
new ADRs.

### Mission-affecting decisions

Any change to `MISSION.md`, `TRADEMARK.md`, `GOVERNANCE.md`, or
`COMMERCIAL.md` requires Mission Steward approval.

If the change **weakens** any of:
- The open-source-forever promise
- The 30% children's-development pledge
- The amendment procedure itself

then the procedure in `MISSION.md` § "Governance" applies:
- 60 days public notice before any vote
- Majority vote of contributors with ten or more accepted commits
  to the core
- Posted in the issue tracker with the `mission-amendment` label

If the change **strengthens** any of the above (raises the
percentage, broadens the scope, tightens the procedure), it can
proceed with simple Mission Steward approval — no public vote
required.

### Conflict of interest

A maintainer or Mission Steward whose employer, ownership stake,
or significant financial relationship would benefit from a
specific decision must declare the conflict and recuse from the
decision. The declaration goes in the relevant issue or PR.

---

## Becoming a maintainer

The path is informal but the bar is real:

1. **Sustained, substantive contribution** for at least three
   months. "Sustained" means roughly monthly meaningful work.
   "Substantive" means not just typo fixes — code, runbooks, ADRs,
   review participation, issue triage.
2. **Demonstrated judgment**. Reviewed others' PRs constructively.
   Said "let's defer this" or "this needs an ADR" when
   appropriate. Didn't merge their own controversial changes
   without consultation.
3. **Operates within the mission**. Hasn't pushed for changes that
   would weaken `MISSION.md`. Hasn't argued for closing parts of
   the OSS core.
4. **A current maintainer nominates them.** The nomination goes to
   the maintainer huddle. Other maintainers can support or object.
5. **No objection from a Mission Steward within 14 days** → the
   contributor becomes a maintainer.

There is no fixed maintainer-count cap. We add maintainers when
there's both a person ready and work that needs them.

## Becoming a Mission Steward

Mission Stewards are appointed by the existing Mission Stewards
unanimously, from the existing maintainer pool. The bar is the
same as maintainer plus:

- Sustained maintainer activity for at least 12 months
- Demonstrated commitment to the mission across at least one
  contested decision

If the Mission Steward body falls below three (death, illness,
voluntary departure, removal), the remaining stewards must appoint
replacements within 90 days. If that fails, the maintainer body as
a whole elects replacements by simple majority.

## Removing a maintainer or Mission Steward

A maintainer may step down at any time by opening an issue.

Involuntary removal requires:

- A specific cause documented in writing (gross policy violation,
  abandonment of duties for >12 months, conflict of interest not
  declared)
- Notification to the affected maintainer with right of reply
- A vote of the remaining Mission Stewards (unanimous for a
  Mission Steward; majority for a regular maintainer)
- The action and rationale published in `docs/conduct-log.md` (or
  equivalent for non-conduct issues)

---

## Succession planning

Because the mission spans 10+ years, succession matters more than
typical OSS projects.

### If the founder leaves

The maintainer + Mission Steward bodies continue. No single person
can dissolve the project's commitments unilaterally. The procedural
locks in `MISSION.md` apply.

### If all current maintainers leave

The maintainer + Mission Steward bodies are responsible for
appointing successors before they leave. If for any reason there
are zero active maintainers for >90 days, the project enters
**maintenance mode**:

- Repository is archived (read-only)
- A static notice is added explaining the project status
- The trademark and mission commitments survive in their current
  form
- Any contributor with ten or more accepted commits may petition
  to revive the project; the petition needs to demonstrate ability
  + commitment to the mission

This prevents the worst case: the project being silently abandoned
or quietly taken over by someone outside the mission.

### If the project is acquired

Acquisition is a mission-affecting decision. It requires:

- Public 60-day notice
- Majority vote of contributors with ten or more accepted commits
- The acquirer publicly accepts the mission (open-source-forever,
  trademark policy, children's-development pledge) IN WRITING
  before the acquisition closes

If an acquisition offer is contingent on dissolving any of those
commitments, the correct answer is "no."

---

## Project communication

| Channel | Use |
| :--- | :--- |
| GitHub Issues | Bugs, feature requests, mission-amendment proposals |
| GitHub Discussions | General Q&A, design discussion |
| GitHub Pull Requests | Code review, ADR discussion |
| Security Advisories | Vulnerability reports per `SECURITY.md` |
| `conduct@plenith.io` | Code-of-conduct concerns |
| `trademark@plenith.io` | Trademark concerns |

There is intentionally no Slack / Discord / private channel for
project decisions. Decisions happen where the public can see them.

---

## Why this much structure for a small project?

Two reasons:

1. **The mission requires durable governance.** If we are sloppy
   about decision authority now, we will be sloppy about it in
   year 5 when there are millions of dollars in play. The 30%
   pledge to children's-development needs procedural locks, not
   handshake commitments.
2. **Procurement teams ask.** Enterprise SOCs evaluating Plenith
   will ask "who governs this project?" If the answer is "I don't
   know, some dudes on GitHub," they walk. If the answer is
   "documented governance with mission protection clauses," they
   keep evaluating.

The structure here is the minimum that addresses both. We will
not add more theater unless growth demands it.

---

## Amendments to this document

This document follows the same amendment procedure as `MISSION.md`
§ "Governance":

- Strengthening changes (more transparency, more protection):
  Mission Steward approval.
- Weakening changes (less transparency, less protection): 60-day
  public notice + majority vote of contributors with ten or more
  accepted commits.

Editorial changes (typos, formatting, link fixes) can be made by
any maintainer via normal PR review.

---

*Last updated: 2026-05-12.*
*Companion to [MISSION.md](MISSION.md), [TRADEMARK.md](TRADEMARK.md),
[COMMERCIAL.md](COMMERCIAL.md), [CONTRIBUTING.md](CONTRIBUTING.md),
[MAINTAINERS.md](MAINTAINERS.md).*
