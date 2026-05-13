# ADR 013: Renamed from MirrorCore to Caltrop

**Status:** **Superseded by [ADR 014](014-renamed-to-plenith.md)** — the
"Caltrop" name was subsequently discovered to be in use by an active
company in an adjacent space. ADR-014 documents the second rename to
Plenith and the lesson learned about pre-rename verification.

This document is preserved as historical record of the original
decision, including the metaphor and rationale that informed it. The
*reasoning* below remains valid for evaluating future candidate names;
only the *choice* was superseded.

**Date:** 2026-05-12

## Context

The project was internally referred to as "MirrorCore" through the
MVP and 1.0 development. Before the first public release we
discovered the name was already in use by an unrelated product, with
namespace collisions on GitHub, PyPI, and trademark databases.

Two choices: pick a new name, or push forward and risk confusion plus
a likely trademark dispute. The cost of renaming pre-launch (touch
every file, regenerate docs, replace all references) is one
afternoon. The cost of renaming post-launch (every existing operator
has to relearn the name, every blog post / Stack Overflow answer / IoC
feed entry is now wrong) is permanent.

Rename now.

## Decision

**The project is renamed to `Caltrop`.**

A caltrop is a small four-spiked iron device used since antiquity to
disable horses and vehicles — an asymmetric defensive weapon used by
smaller forces against larger ones. The metaphor fits:

- **Asymmetric defense.** A two-analyst SOC defending a network
  against well-funded attackers is exactly the caltrop scenario. The
  deception is the spikes — small, distributed, unavoidable for
  anyone trying to move through the terrain.
- **Same shape from any angle.** A caltrop has the property that
  whichever way it lands, a spike points up. The deception platform
  has the same shape: whichever direction the attacker probes, they
  meet a planted decoy.
- **Defensive only.** A caltrop has no offensive use — it is laid
  down and waited on. So is this platform.

## Why this name specifically

We considered several alternatives. The ones that came closest:

- **Effigy** — direct deception metaphor, strong word, available in
  the security namespace.
- **Trove** — what the attacker thinks they're stealing, what we plant.
- **Sleight** — "sleight of hand," magic-trick deception.
- **Mockingbird** — bird that mimics other birds; fits LLM-driven
  realism but crowded namespace.

Caltrop won on:

1. **Single concrete metaphor** that encodes the entire business case.
2. **Logo writes itself** — a four-pointed iron caltrop, identifiable
   at any size.
3. **No security-namespace collision** as of pre-launch search.
4. **Pronounceable globally** — /ˈkæl.trɒp/ resolves cleanly across
   English, Romance, Germanic, and East-Asian phoneme inventories.
5. **Short** — five letters, fits in a CLI prefix and a domain.

## Why

1. **Pre-launch is the only cheap window for a rename.** Once we have
   external operators, every blog post / dashboard URL / IoC feed
   entry / trademark filing is locked in.
2. **Trademark hygiene.** The prior name conflicted with an
   established product. Continuing would have invited a cease-and-
   desist within months of any visibility.
3. **The metaphor is stronger.** "MirrorCore" leans on the *what*
   (we mirror real systems). "Caltrop" leans on the *why* (asymmetric
   defense for outnumbered defenders). The second is the actual
   selling point.

## Consequences

### Mechanical

- **Package**: `mirrorcore/` → `caltrop/`. All imports updated.
- **Metric prefix**: `mirrorcore_*` → `caltrop_*`. Operators with
  existing Prometheus dashboards using the old prefix will lose
  history at the rename boundary — acceptable because we have no
  external deployments yet.
- **Env var prefix**: `MIRRORCORE_*` → `CALTROP_*`. Same rationale.
- **Docker images**: `mirrorcore/agent` → `caltrop/agent`, etc.
- **GitHub URLs**: every reference updated to `Plenith/caltrop`. The
  `Plenith` placeholder remains pending decision on the GitHub
  organization name.
- **Domain references**: `mirrorcore.example` → `caltrop.example` in
  the DPIA + CODE_OF_CONDUCT contact fields. These are templates
  for operators to replace anyway.
- **Filenames**: nine runbook files in `docs/runbooks/` renamed
  from `MirrorCore*.md` to `Caltrop*.md`.
- **Grafana dashboards**: `mirrorcore-*.json` files renamed
  accordingly.
- **Helm chart**: `deploy/helm/mirrorcore/` → `deploy/helm/caltrop/`.

### Procedural

- **All 12 prior ADRs retain their numbers.** This ADR is 013. ADRs
  are never renumbered; renaming the project doesn't change ADR
  identity.
- **The test suite at 914 passing tests remained green after the
  rename.** Verified with one full run post-rename.
- **No deprecation shim shipped.** With zero external deployments,
  back-compat aliases would be dead code. If the project develops a
  user base on the new name and someone later needs to migrate from
  a fork that retained the old name, that's a separate exercise.

### Open items

- **Repo root directory name.** The working directory is still
  `mirrorcore-mvp/`; this becomes `caltrop/` when the project is
  pushed to GitHub for the first time. Left for the GitHub-org
  decision moment.
- **GitHub organization name.** Default placeholder is `Plenith` in all
  documentation. Final value depends on availability of
  `github.com/caltrop` (preferred) or alternatives.

## File pointers

- `MISSION.md`, `LICENSE`, `NOTICE`, `CHANGELOG.md` — all updated.
- `docs/runbooks/` — all 9 runbooks renamed; index updated.
- `tests/test_alerts_config.py`, `tests/test_secrets.py`,
  `tests/test_project_meta.py` — string expectations rewritten to
  match new identifiers.
- The one-off rewrite script (`_rename_sweep.py`) is removed; this
  ADR is the durable record of the decision.
