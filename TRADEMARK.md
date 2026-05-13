# Trademark Policy

The **source code** in this repository is licensed under
[Apache License 2.0](LICENSE). The **name "Plenith" and the Plenith
logo** are NOT covered by that license. This is the standard pattern
followed by Linux, Kubernetes, PostgreSQL, and most major OSS
projects: code is permissively licensed; brand is held centrally.

This file documents what you can and cannot do with the Plenith
brand. If you have a use case not covered here, open an issue or
contact the maintainers at `trademark@plenith.io`.

---

## What's covered by this policy

- The word **Plenith** (in any case: Plenith / PLENITH / plenith)
- The Plenith logo (once published in `docs/assets/`)
- Any combination mark that includes "Plenith" plus an additional
  descriptor (e.g. "Plenith Cloud", "Plenith Enterprise")
- Domain names containing "plenith" that are operated by the
  project (e.g. `plenith.io`, `plenith.dev`, `docs.plenith.io`)

The source code, documentation prose, configuration files,
runbooks, and other written content of the repository are NOT
covered here — those are governed by the LICENSE.

---

## What you CAN do without permission

The intent is to make legitimate use of Plenith as easy as
possible while protecting against confusion and misrepresentation.

### Permitted uses

1. **Use the name to describe Plenith.** "I deploy Plenith for
   intrusion deception." "Our SOC uses Plenith." "This bug
   reproduces on Plenith 1.0." Truthful descriptive use is fine
   and welcome.
2. **Reference Plenith in technical writing.** Blog posts, talks,
   conference papers, academic articles — go ahead. We'd
   appreciate a link if it makes sense.
3. **Run your own Plenith deployment** and call it that
   internally. Operating an instance of Plenith does not require a
   trademark license.
4. **Distribute unmodified Plenith** under the LICENSE terms with
   the project's name. The Apache 2.0 license already allows
   redistribution; this trademark policy doesn't restrict it.
5. **Describe your fork or derived work** — but see "Forks" below.
6. **Use the name in URLs of community resources** that are clearly
   community-run, not official, and don't impersonate the project.
   Example: `reddit.com/r/plenith` (community-run subreddit). Bad
   example: `plenith-official.com` (impersonates).

### Forks

Apache 2.0 lets you fork. The trademark policy adds two rules to
the fork:

- **Rename your fork.** A fork should not be called "Plenith" —
  pick a different name. This is the same rule Apache, Linux, and
  PostgreSQL follow. Your fork can describe itself as "based on
  Plenith" or "a fork of Plenith" or "Plenith-derived" — but its
  primary name should be distinct.
- **Don't use the Plenith logo** as the primary brand of the
  fork. You may reference it in documentation that explains the
  fork's lineage.

---

## What you CANNOT do without permission

1. **Name your own product "Plenith"** or anything confusingly
   similar (Plenithe, Plennith, Plenith Pro, Plenith Cloud, Plenith
   X, etc.) that would suggest official affiliation.
2. **Register a domain** containing "plenith" for a commercial
   product or service that is not Plenith. (Personal blogs,
   community resources, and fan sites are fine — see "Permitted
   uses" §6.)
3. **Sell merchandise** (t-shirts, stickers, mugs, etc.) bearing
   the Plenith name or logo without permission.
4. **Offer "Plenith-certified" services** without a partner
   agreement. We may publish a partner / certification program
   later; until then, the certification line is not available.
5. **Use the Plenith logo modified.** The logo's geometry, color,
   and aspect ratio are fixed. Don't recolor, distort, animate, or
   composite it without permission.
6. **Suggest endorsement** of your product, project, or business
   by the Plenith maintainers when no such endorsement exists.
7. **File trademark applications** for "Plenith" (or
   confusingly-similar marks) in any jurisdiction. The
   maintainer-org reserves that right.

---

## The fork-naming convention we ask you to follow

If you maintain a public fork of Plenith for any reason, please:

1. Choose a distinct name that's not a Plenith variation
   (e.g. "Foo" — not "Plenith-Foo" or "Foo-Plenith" or "PlenithX").
2. Note the upstream in your README:
   > Foo is derived from [Plenith](https://github.com/Plenith/Plenith)
   > and tracks Plenith ≥ 1.0. Foo is not affiliated with the
   > Plenith project; the Plenith name and logo are used here only
   > to indicate lineage.
3. Don't use the Plenith logo as your fork's primary brand mark.

We will not pursue a fork that follows these conventions, even if
the fork explicitly competes with the upstream project. This is
the same posture the Linux Foundation takes with its trademark
program.

---

## Naming derived works that integrate with Plenith

If your product **uses** Plenith as a component (e.g. a managed
service that runs Plenith for customers, a plugin that extends
Plenith, a SIEM integration that consumes Plenith alerts), you may
use the Plenith name **descriptively**:

- "Foo SOC, powered by Plenith"
- "Foo SIEM with Plenith integration"
- "Foo for Plenith"

You may NOT use:

- "Plenith Foo" (sounds like an official Plenith product)
- "Plenith Cloud by Foo" (sounds like an official Plenith hosted service)
- "Foo Plenith Enterprise" (sounds like an official Plenith tier)

The test is: would a reasonable buyer confuse your product with
something the Plenith maintainers ship?

---

## Why this matters

The mission (`MISSION.md`) commits a meaningful share of net
commercial revenue from Plenith offerings to children's-development
initiatives. The trademark is one of the legal mechanisms that
makes that revenue possible — without brand control, anyone could
offer "Plenith Cloud" and capture revenue intended to flow toward
the mission.

The Apache 2.0 license guarantees that the *code* stays free
forever. The trademark policy guarantees that the *brand* stays
attached to the project's mission. Both protections work together.

---

## Reporting misuse

If you see someone using "Plenith" in a way that violates this
policy (impersonating the project, selling Plenith-branded
products, offering Plenith-certified services without permission),
please report it to `trademark@plenith.io`.

We will respond within 14 days. Most cases resolve with a polite
notice; we reserve formal legal action for cases of clear
deliberate misappropriation.

---

## Changes to this policy

This policy may be amended, but only in directions that maintain
or strengthen the mission's revenue protections (`MISSION.md` §
"Governance"). The amendment procedure is the same as for
MISSION.md: 60-day public notice, majority vote of contributors
with ten or more accepted commits to the core.

---

*Last updated: 2026-05-12.*
*Based on the [CNCF trademark usage guidelines](https://www.linuxfoundation.org/trademark-usage)
and the [Apache Software Foundation trademark policy](https://www.apache.org/foundation/marks/).*
