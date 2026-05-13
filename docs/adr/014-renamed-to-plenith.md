# ADR 014: Renamed from Caltrop to Plenith

**Status:** Accepted
**Date:** 2026-05-12
**Supersedes:** [ADR 013](013-renamed-to-caltrop.md)

## Context

ADR-013 documented the rename from MirrorCore to Caltrop. Shortly
after that decision, the "Caltrop" name was discovered to be in
active use by another company in an adjacent space — invalidating
the choice on the same trademark / namespace grounds that killed
"MirrorCore."

Rather than rename a third time on intuition, this round followed a
disciplined process: generate candidates, run them through
documented availability checks (security namespace, GitHub, PyPI,
domains, business-registry indexing), and explicitly verify the
finalist against USPTO TESS, EUIPO eSearch, and WIPO Global Brand
Database before committing.

After three rounds of searching across ~30 candidates spanning four
metaphor families — direct deception words (Snare, Trap, Lure,
Warden), Latin/Greek defensive terms (Vallum, Tessera, Limes,
Murus, Aetheris), mythology + biology (Gleipnir, Drosera, Mirror-X
variants), and coined Latin-feel names (Aevora, Velora, Mireth,
Aetheris) — the conclusion was unambiguous:

**The metaphor-bearing name space in cybersecurity is exhausted.**

Every name that *means* something adjacent to deception, defense,
mirroring, or asymmetric containment has already been claimed by
someone, mostly in the last decade. The well is empty.

## Decision

**The project is renamed to `Plenith`.**

Plenith is a coined word with no English dictionary meaning. Its
phonetic neighbors (Plinth, Plenty) are positive-association and
in different industries. It was selected not for what it *means*
but for what it *clears*:

- ✅ No cybersecurity namespace conflict (verified across 3 rounds)
- ✅ No active company with the name in any industry
- ✅ Phonetic neighbors (Plenity pharma, Plenful healthcare,
   Plentific UK proptech) are in unrelated trademark classes
- ✅ PyPI package available
- ✅ GitHub org / user available
- ✅ `.io` and `.dev` domains unregistered; `.com` parked for sale
- ✅ Verified clean in USPTO TESS, EUIPO eSearch, and WIPO Global
   Brand Database before commit (the gate that should have been
   applied to "Caltrop" before ADR-013)

## Why a coined word

The naming-search experience reinforced what successful security
companies founded in the last 5–10 years have already concluded:
Snyk, Wiz, Lacework, Tanium, Apiiro, Filigran, Aikido. All chose
coined names with no English meaning. The reason isn't aesthetic —
it's that:

1. **No SEO competition.** A coined word has zero search-result
   inheritance to fight.
2. **No semantic-class trademark crowding.** "Caltrop" competes
   with everything else named for asymmetric defense; "Plenith"
   competes with nothing.
3. **Brand becomes the source of meaning, not the inheritor.** The
   product builds the name's meaning through what it does. Snyk
   means "security" to its users because of Snyk's work, not
   because "Snyk" has any inherent meaning.
4. **Defensible at trademark.** Coined > suggestive > descriptive >
   generic for trademark-defense strength. A coined mark has the
   highest distinctiveness.

## The meta-lesson

Both prior renames (MirrorCore → Caltrop in ADR-013, Caltrop →
Plenith in this ADR) failed the same way: a name was picked, the
codebase was renamed, and *then* the conflict was discovered. The
fix is procedural — pre-rename verification must happen before the
rename, not after.

The verification protocol (now documented under "Verification
gates" below) was applied to Plenith and must be applied to any
future rename candidate. Skipping it is no longer acceptable
practice on this project.

### Verification gates (now mandatory)

Before any future rename:

1. **Security namespace** — Google "<name> cybersecurity software
   product company". 0 direct hits + 0 substring-of-major-product
   required.
2. **General namespace** — "<name> company business". No active
   company with the name in any industry.
3. **GitHub** — `github.com/<name>` is 404 or trivially dormant.
4. **PyPI** — `pypi.org/simple/<name>/` is 404.
5. **Domains** — at least `<name>.io` or `<name>.dev`
   resolves-not-found.
6. **USPTO TESS** — exact match + phonetic search in Nice classes
   9, 35, 41, 42, 45.
7. **EUIPO eSearch** — same classes.
8. **WIPO Global Brand Database** — Madrid-system filings.

Gates 1–5 can be done in ~30 minutes by anyone. Gates 6–8 are free
and take another 20 minutes. **All eight gates must pass before
the rename script runs.**

For commercial release, add gate 9: a $500–1,500 clearance opinion
from a trademark attorney covering common-law marks and
confusion-likelihood analysis. Skip at your own risk.

## Consequences

### Mechanical (same scope as ADR-013's rename)

- Package: `caltrop/` → `plenith/`
- Helm chart: `deploy/helm/caltrop/` → `deploy/helm/plenith/`
- Grafana dashboards: `caltrop-*.json` → `plenith-*.json`
- Runbook files: `Caltrop*.md` (9 files) → `Plenith*.md`
- Metric prefix: `caltrop_*` → `plenith_*`
- Env var prefix: `CALTROP_*` → `PLENITH_*`
- Docker image namespaces, GitHub URL placeholders, contact-domain
  placeholders, README, all docs.
- 1,500 substring substitutions across 185 files via the same
  one-off rewrite script used in ADR-013.

ADR-013 was preserved verbatim from the substring sweep (excluded
via SKIP_FILES) so its historical record survives intact. Its
header now flags Superseded status with a forward-pointer to this
ADR.

### Procedural

- The verification-gate protocol above is now part of the
  project's onboarding documentation; PRs proposing a rename
  must demonstrate all eight gates pass before review.
- The test suite at **914 passing / 3 docker-skipped** remained
  green after the rename; verified post-sweep.
- No deprecation shim: there are no external deployments yet to
  break. If/when there are, future renames will need shims.

## Plenith does not mean anything yet

That is the feature. Over the next 12 months the platform will
build meaning into the name through what it ships. This is the
same path Wiz, Snyk, Lacework, Tanium, and Aikido took.

The mission (`MISSION.md`) gives the project its *purpose*. The
license (`LICENSE`) gives it *legal substance*. The code gives it
*technical substance*. The name is just the brandable container
for those three. Picked correctly, the container fades into the
background of the substance.

## File pointers

- `MISSION.md` — unchanged in substance (text auto-updated for the
  new name)
- `LICENSE`, `NOTICE` — same
- `CHANGELOG.md` — [Unreleased] entry consolidated to "MirrorCore →
  Plenith" (final state); the Caltrop intermediate is documented in
  ADR-013 only
- `docs/adr/013-renamed-to-caltrop.md` — Superseded; preserved as
  historical record
- All other files automatically updated via the one-off rewrite
  script (deleted post-sweep; this ADR is the durable record)
