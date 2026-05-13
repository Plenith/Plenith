---
name: Feature request
about: Propose a new capability or significant change
title: "[feature] short summary"
labels: enhancement, triage
---

<!--
Open this BEFORE writing code for non-trivial features. We'd rather
spend 5 minutes here than ask you to redo a weekend's work. Small
fixes / docs improvements can go straight to a PR.
-->

## What problem does this solve? (required)

The user need or operational gap. Not the proposed solution yet —
just the problem.

## Who is affected?

- [ ] Operators deploying Plenith in production
- [ ] SOC analysts triaging engagements
- [ ] Plugin / connector authors
- [ ] Contributors to the core
- [ ] Other:

## Proposed solution (required)

Your suggested approach. If you have multiple options in mind, list
them with the trade-offs.

## Alternatives considered

Other approaches you thought about and why they're worse. ("None"
is acceptable but uncommon.)

## How does this fit the mission?

The project mission is in `MISSION.md`. Briefly: does this push
toward the open-source-forever / defenders-who-can't-pay goal? Does
it require closing any part of the core? Any tension is fine to
acknowledge — we'd rather discuss it explicitly than discover it
later.

## Scope check

- [ ] Adds a runtime dependency (which? why?)
- [ ] Changes a public API (REST / plugin / connector / on-disk format)
- [ ] Requires an ADR (`docs/adr/`)
- [ ] Affects the threat model (`docs/THREAT_MODEL.md`)
- [ ] Affects retention / compliance (`docs/DPIA.md` / `docs/DATA_HANDLING.md`)
- [ ] None of the above — pure internal change

## Are you willing to implement this?

- [ ] Yes — I'd open the PR
- [ ] Yes, with guidance on the design
- [ ] No, but I'd review and test
- [ ] No

(All answers are fine. Knowing helps maintainers prioritize.)
