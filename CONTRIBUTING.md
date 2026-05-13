# Contributing to Plenith

Thanks for considering a contribution. This document covers the
practical bits: dev setup, the workflow we follow, what we look for
in a PR, and where to ask if you're stuck.

Before contributing, please read [`MISSION.md`](MISSION.md). The
mission shapes how we evaluate proposals — we say no to things that
would compromise the open-source-forever promise even when they'd be
technically nice.

If your contribution is security-related, follow [`SECURITY.md`](SECURITY.md)
instead of this doc — security reports go through a private channel.

---

## TL;DR

```bash
# One-time setup
git clone https://github.com/Plenith/Plenith
cd plenith
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
pre-commit install

# Day-to-day
pytest                          # run the suite (~100s)
pre-commit run --all-files      # lint + format

# Before opening a PR
pytest && pre-commit run --all-files
```

That's it. Read on for details.

---

## Where to start

| You want to… | Start here |
| :--- | :--- |
| Report a bug | [Open an issue](https://github.com/Plenith/Plenith/issues/new?template=bug_report.md) |
| Propose a feature | [Open an issue](https://github.com/Plenith/Plenith/issues/new?template=feature_request.md) before coding — saves rework |
| Fix a typo or doc bug | Open a PR directly, no issue needed |
| Add a connector | Read `plenith/connectors/__init__.py` and `docs/PLUGINS.md` |
| Add a detector / responder / policy plugin | Read `docs/PLUGINS.md` first |
| Add a new persona | YAML under `personas/`; mirror an existing one |
| Improve heuristics | Read `plenith/heuristics.py` + the test suite |
| Report a security vulnerability | **Do not open a public issue.** See [`SECURITY.md`](SECURITY.md) |

## Issues we welcome

- Bug reports with a minimal reproducer.
- Documentation improvements — clarifications, fixed examples,
  missing operational notes.
- Detector / responder / persona contributions from your vertical.
- Connector contributions for SIEMs / SOARs / threat-intel platforms
  we don't yet support.
- Performance regressions caught by `tools/bench.py --compare`.
- ADR proposals for non-trivial design changes.

## Issues we'll likely decline

- Refactors that don't enable a concrete future change.
- Style-only changes without an attached lint/test improvement.
- Adding a runtime dependency without strong justification (the
  dep tree is deliberately tight; see `requirements.txt`).
- Re-implementing functionality already present in a stdlib module.
- Features that would require closing or restricting the core
  license (see `MISSION.md`).

---

## Development setup

### Prerequisites

- Python **3.11+** (we test 3.11 / 3.12 / 3.13 / 3.14 in CI).
- Docker + docker-compose v2 (only required for tests that exercise
  the multi-host fabric; most tests don't need it).
- An OpenAI-compatible local LLM endpoint (LM Studio / Ollama) if
  you want to manually test the LLM path.

### Setup

```bash
python -m venv .venv
source .venv/bin/activate                 # Windows: .venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt
pre-commit install
```

`pre-commit install` adds a git hook that runs ruff + black on each
commit. To run the hooks manually against the whole tree:

```bash
pre-commit run --all-files
```

### Running tests

```bash
pytest                              # whole suite
pytest tests/test_orchestrator.py   # one file
pytest -k counter_ai                # by keyword
pytest --cov=plenith             # with coverage
```

The full suite takes ~100s on a modern laptop. We aim for it to stay
under 180s; PRs that meaningfully push the suite past that should
include a justification.

Tests that need Docker live under markers — skip them on a laptop
without Docker:

```bash
pytest -m "not docker"
```

### Project layout

```
plenith-mvp/
├── plenith/         Core library code
│   ├── api/            REST API surface (FastAPI)
│   ├── connectors/     SIEM / SOAR / TI / MFA / ChatOps
│   ├── compliance/     Compliance evidence + reports
│   └── training/       V2 RL policy training
├── tools/              CLIs (audit, backup, restore, bench, etc.)
├── tests/              pytest test suite
├── docs/               Operator + contributor documentation
│   ├── adr/            Architecture Decision Records
│   └── runbooks/       One per Prometheus alert
├── deploy/             Production deploy artifacts
│   ├── grafana/        Dashboards
│   ├── prometheus/     Alert rules
│   ├── security/       seccomp + AppArmor profiles
│   └── network/        nftables rulesets
├── personas/           Synthetic persona definitions
├── plugins/            Drop-in plugin directory
└── linux-fork/         Multi-host docker-compose fabric
```

---

## The PR workflow

1. **Pick or open an issue.** For anything bigger than a typo, an
   issue first saves both of us time.
2. **Fork + branch.** Name the branch descriptively
   (`add-elastic-connector`, `fix-counter-ai-false-positive`, etc.).
3. **Write the code AND the test.** A change without a test is
   incomplete; we will ask for one. The test should pin the *new*
   behavior in a way that fails before your change and passes after.
4. **Run the suite locally.** `pytest && pre-commit run --all-files`.
5. **Open the PR** using the [template](.github/PULL_REQUEST_TEMPLATE.md).
   Link the issue. Describe the *why* — the diff already shows the
   *what*.
6. **CI runs the full matrix.** Address any failures. Maintainers
   review when CI is green.

### What a good PR looks like

- One logical change. If you find yourself writing "and also" in the
  description, that's a sign for two PRs.
- The diff is small enough to review thoroughly (< 500 lines is the
  norm; larger needs justification).
- Tests cover the new behavior, not just the new code.
- No formatting churn from a different editor (pre-commit takes
  care of this if you run it).
- Documentation updated in the same PR — if you change behavior,
  the relevant page in `docs/` should reflect it.
- Public API changes (REST, plugins, connectors) call this out in
  the PR description and propose a CHANGELOG entry.

### What we look for in review

- **Correctness** — does it do what it says, including edge cases?
- **Test coverage** — does the test actually fail without the
  change?
- **API stability** — does this preserve backward compatibility, or
  is it a versioned break?
- **Performance** — for hot-path code, does `tools/bench.py` show no
  regression beyond the documented tolerances?
- **Security** — does this widen the attack surface? See
  `docs/THREAT_MODEL.md` for what we consider.
- **Mission fit** — does this push toward the open-source-forever
  goal in `MISSION.md`?

---

## Style guide

We're pragmatic, not dogmatic. The pre-commit hooks enforce the bits
that matter (line length, import order, type-hint syntax).

### Python

- Line length: 88 (black's default).
- Type hints on public functions; encouraged elsewhere.
- Prefer descriptive names over comments. Save comments for the
  *why*, not the *what*.
- Tests use plain `assert` (no `unittest.TestCase`); pytest fixtures
  preferred to manual setup/teardown.
- Async / await everywhere on the orchestrator's hot path.
- Optional imports inside functions (see `plenith/secrets.py` for
  the pattern).

### Documentation

- Markdown files use [CommonMark](https://commonmark.org).
- Code examples must be copy-paste runnable on a fresh install
  unless explicitly marked otherwise.
- Operator-facing files (`docs/`) are written for humans first;
  use tables, not paragraphs, when comparing options.

### Commit messages

We don't enforce a specific format, but useful messages help.
Typical structure:

```
short summary in imperative mood (≤72 chars)

Optional longer explanation of the *why* and the *trade-off*. Wrap at
72 chars. Reference issues like #123 in the body, not the title.
```

---

## Adding a new dependency

The dep tree is deliberately tight (under 10 direct runtime deps).
Adding one requires:

1. A justification in the PR description: why the existing tools
   don't work.
2. A check that the dep ships with a permissive license (Apache 2,
   MIT, BSD). GPL-family deps need an ADR.
3. A check that the dep is actively maintained (recent release,
   issues responded to).
4. Pinning in `requirements.txt` (`pkg>=X,<Y`) — open ranges break
   reproducibility.

If your feature is optional, prefer **lazy import** + a clear error
message when the dep is missing (see `plenith/tracing.py` and
`plenith/secrets.py` for examples). This keeps the base install
small.

---

## Architecture Decision Records

For non-trivial design changes:

1. Read existing ADRs under `docs/adr/`. We follow the Nygard
   format: Context, Decision, Why, Consequences.
2. Open a PR adding `docs/adr/NNN-short-name.md` with the next
   number. Mark status as Proposed.
3. Discuss in the PR. Once accepted, change status to Accepted in
   a follow-up commit; reference the ADR in any code change that
   implements it.

ADRs are NEVER renumbered or deleted. Superseding an old ADR is a
new ADR that says "this supersedes ADR NNN."

---

## Releasing (maintainers only)

Releases are tag-driven:

```bash
git tag -s v1.1.0 -m "release 1.1.0"
git push origin v1.1.0
```

This triggers `.github/workflows/release.yml` which:

- Builds the source tarball.
- Generates the CycloneDX SBOM.
- Signs everything with cosign (keyless / sigstore).
- Attaches SLSA build provenance.
- Creates the GitHub Release with verification instructions
  pointing to `docs/VERIFY_RELEASES.md`.

Maintainers move the `[Unreleased]` section of `CHANGELOG.md` to the
new version + date, in the same commit as the tag (or the commit
immediately before).

---

## Questions?

- General discussion: GitHub Discussions on the repo.
- Specific bugs: Issues.
- Security: see [`SECURITY.md`](SECURITY.md).
- Anything else, including "is this contribution welcome before I
  spend a weekend on it": Discussions.

Thank you. We mean it.
