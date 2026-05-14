# Pre-Launch Checklist

Items to complete before the project is announced publicly. This
is the canonical "are we ready" gate. Each item is bounded
(check-or-don't) so you can run through the list in an hour and
know exactly what's left.

The list reflects lessons from the v1.0 build, including the
multi-rename sequence that taught us pre-rename verification
isn't optional (see [ADR 014](adr/014-renamed-to-plenith.md)).

---

## Part A — Brand verification (8 free gates)

Per ADR 014, no rename or first public push happens before all
eight gates pass. The current name **Plenith** has cleared
gates 1–5 (see the brand-handle availability report from the
2026-05-12 background sweep). Gates 6–8 are your action items.

### Gate 1 — Security namespace ✅
- [x] `<name> cybersecurity software product company` web search
      shows 0 direct hits + 0 substring-of-major-product

### Gate 2 — General business namespace ✅
- [x] `<name> company business` web search shows no active business
      using the name in any industry

### Gate 3 — GitHub ✅
- [x] `github.com/<name>` returns 404
- [x] `api.github.com/users/<name>` returns 404
- [x] `api.github.com/orgs/<name>` returns 404

### Gate 4 — Package registries ✅
- [x] `pypi.org/simple/<name>/` returns 404
- [x] `registry.npmjs.org/<name>` returns 404
- [x] `crates.io/api/v1/crates/<name>` returns 404 (if Rust components ever ship)
- [x] `hub.docker.com/v2/repositories/<name>/` is empty

### Gate 5 — Domains ✅
- [x] At least one of `<name>.io` / `<name>.dev` / `<name>.sh` is
      registerable (resolves-not-found OR explicitly available
      via registrar)

### Gate 6 — USPTO TESS ⬜
- [ ] Exact match search in classes 9, 35, 41, 42, 45 — 0 LIVE
      hits
- [ ] Phonetic search in same classes — 0 LIVE hits
- [ ] Document the searches with screenshots in
      `docs/IMPACT/2026.md` § 4.4 ("Mission compliance check")

### Gate 7 — EUIPO eSearch ⬜
- [ ] Same search in EUIPO eSearch
- [ ] Document findings

### Gate 8 — WIPO Global Brand Database ⬜
- [ ] Madrid-system filings search
- [ ] Document findings

When all 8 gates ✅, brand-verification is complete.

---

## Part B — Legal + IP

### Trademark attorney clearance opinion
- [ ] Engage trademark attorney with the eight-gate report
- [ ] Receive written clearance opinion ($500–$1,500 typical)
- [ ] File this opinion in the maintainer-org's legal records
- [ ] Update [ADR 014](adr/014-renamed-to-plenith.md) with
      reference to the opinion

### Trademark registration (post-launch but plan now)
- [ ] Decide registration scope (US-only vs. US + EU + UK)
- [ ] File USPTO trademark application in classes 9 + 42 (minimum)
- [ ] Track application progress (10–18 months typical to
      registration)

### License + notice files
- [x] `LICENSE` (Apache 2.0)
- [x] `NOTICE` (Apache 2.0 § 4(d) required attribution)
- [x] `TRADEMARK.md` (brand policy)
- [x] `COMMERCIAL.md` (what's free vs. paid)

---

## Part C — Project hygiene

### Required public files
- [x] `README.md`
- [x] `LICENSE` + `NOTICE`
- [x] `SECURITY.md`
- [x] `CODE_OF_CONDUCT.md`
- [x] `CONTRIBUTING.md`
- [x] `CHANGELOG.md`
- [x] `MISSION.md`
- [x] `TRADEMARK.md`
- [x] `COMMERCIAL.md`
- [x] `GOVERNANCE.md`
- [x] `MAINTAINERS.md`
- [x] `ROADMAP.md`
- [x] `.github/PULL_REQUEST_TEMPLATE.md`
- [x] `.github/ISSUE_TEMPLATE/{bug_report,feature_request,config}*`
- [x] `.github/workflows/{ci,release}.yml`
- [x] `.github/dependabot.yml`

### Documentation
- [x] `docs/QUICKSTART.md` (60-second install)
- [x] `docs/THREAT_MODEL.md`
- [x] `docs/HARDENING.md`
- [x] `docs/DPIA.md`
- [x] `docs/DATA_HANDLING.md`
- [x] `docs/COMPLIANCE_MAPPING.md`
- [x] `docs/SECRETS.md`
- [x] `docs/PLUGINS.md`
- [x] `docs/VERIFY_RELEASES.md`
- [x] `docs/adr/` (14 ADRs)
- [x] `docs/runbooks/` (one per Prometheus alert)
- [x] `docs/IMPACT/README.md` + `_TEMPLATE.md`
- [x] `docs/security-pgp.txt` (stub — replace before launch)

### Pre-commit + CI quality gates
- [x] `.pre-commit-config.yaml`
- [x] `ruff.toml`
- [x] CI matrix: Python 3.11/12/13/14 × Ubuntu/Windows
- [x] Coverage floor enforced in CI (currently 70%)
- [x] ruff lint enforced in CI (defect-catcher rules)

### Test suite
- [x] 1126 tests passing + 1 docker/Windows-skipped on dev
      workstation

---

## Part D — Handle registration (post-clearance, pre-announcement)

In priority order. Items checked here represent registrations
already secured. Background-agent verification on 2026-05-12
confirmed all major platforms returned 404.

### Critical (do FIRST after clearance)
- [x] GitHub organization `Plenith` ✅ **Secured 2026-05-12.** Repo URL: https://github.com/Plenith
- [ ] PyPI placeholder `plenith` package (publish 0.0.0 with repo
      URL to reserve the namespace)
- [ ] npm placeholder `plenith` package
- [x] Domain `plenith.io` ✅ **Secured 2026-05-12.**
- [ ] Domain `plenith.dev` (run `whois plenith.dev` first; register
      as defensive secondary)

### Important (within first week)
- [ ] Docker Hub organization `plenith`
- [ ] LinkedIn company page `linkedin.com/company/plenith`
- [ ] X / Twitter handle `@plenith` (manual browser check first)
- [ ] YouTube channel `@plenith`

### Optional but recommended
- [ ] Reddit `r/plenith` subreddit (claim as community-run; tie to
      Discord/GitHub)
- [ ] crates.io `plenith` (if any Rust components on roadmap)
- [ ] Domain `plenith.com` — currently parked at $15K on Spaceship
      marketplace. Decision: negotiate, accept the parked-domain
      status (use `.io` as canonical), or budget for acquisition
      later when revenue justifies.

---

## Part E — Operational readiness

### Vulnerability disclosure infrastructure
- [ ] Generate the PGP key for `security@plenith.io`
- [ ] Replace placeholder in `docs/security-pgp.txt` with real key
- [ ] Enable GitHub Private Vulnerability Reporting on the repo
- [ ] Add the maintainer team as Security Advisory Admins

### Release infrastructure
- [x] Release workflow tested in dry-run (no real tag pushed yet)
- [ ] Cosign keyless signing verified end-to-end with a test tag
- [ ] First real release: tag `v1.0.0`, watch the workflow, verify
      with `docs/VERIFY_RELEASES.md` instructions

### Monitoring + alerting
- [ ] Prometheus instance set up for the maintainer org's own
      Plenith deployment (eat-our-own-dogfood proof)
- [ ] Alertmanager routing for the 9 alerts to a real on-call
- [ ] Grafana dashboards imported and rendering

### Self-deployment
- [ ] Maintainer org runs its own Plenith deployment on a public
      IP for at least 30 days before the public announcement
- [ ] At least one captured engagement (real or red-teamed) to
      cite in the launch announcement

---

## Part F — Communications

### Launch announcement materials
- [ ] One-paragraph elevator pitch
- [ ] One-page product summary
- [ ] 90-second demo video (per the build-in-public conversation)
- [ ] At least 2-3 build-in-public technical threads queued
      (counter-AI proof-by-trap, hash-chained audit logs, LLM
      realism — items called out earlier in the project history)
- [ ] FAQ document covering pricing, mission, license, governance

### Community surfaces
- [ ] GitHub Discussions enabled with starter topics
- [ ] At least one prepared response to "is this really free
      forever?" / "what's the upsell?"
- [ ] At least one prepared response to "what happens to the 30%
      pledge if you're acquired?"

### Press / external
- [ ] Press kit (logo files in `docs/assets/` once logo exists)
- [ ] Boilerplate company description
- [ ] Maintainer bios (with permission)

---

## Part G — Mission protection

### Procedural locks operational
- [x] `MISSION.md` documents the 30% pledge + amendment procedure
- [x] `GOVERNANCE.md` documents the Mission Steward body
- [x] `TRADEMARK.md` protects the brand-revenue path

### Minimum viable governance
- [ ] At least 3 Mission Stewards named in `MAINTAINERS.md`
      (currently shows founder as sole Mission Steward — known
      gap)
- [ ] 501(c)(3) sponsor relationship initiated (required before
      first allocation > $50K per `MISSION.md` § Governance §2)
- [ ] First annual impact report template populated and ready for
      data collection (template ready at `docs/IMPACT/_TEMPLATE.md`)

---

## How to use this checklist

- Run through it ~weekly during pre-launch
- Items marked ✅ checked in this commit are the ones already done
  as of 2026-05-12
- Items marked ⬜ are open
- File one issue per ⬜ item; close it when checked
- Pre-launch is complete when every box in Parts A–E is ✅
- Parts F–G can lag launch by a few weeks if necessary, but Part G
  Mission Steward count must reach 3 within 90 days of launch

When the checklist is fully green, the next event is the **public
announcement** (the build-in-public-then-launch path from the
social-media conversation, not a cold launch).

---

*Last updated: 2026-05-12.*
*Owner: Mission Stewards (per `GOVERNANCE.md`).*
