# ADR 011: Plugin system shape — four base classes, two discovery paths

**Status:** Accepted
**Date:** 2026-05

## Context

Operators in regulated industries (banking, healthcare, OT/ICS) and
specific verticals routinely need to add detection logic or response
side effects that ship outside the core repo. They can't get them
merged upstream (proprietary, sector-specific, or both), but they also
can't fork — divergence becomes unmanageable across upgrades.

The four extension surfaces they typically want to hit:

1. **Detection** — "if the command matches our SWIFT-staging regex,
   add an observation."
2. **Response** — "when a credential-exfil alert fires, also push a
   block rule to our edge firewall."
3. **Policy** — "swap the heuristic ladder for our ML policy."
4. **Connector** — "ship alerts to our proprietary internal SIEM."

The decision space: how many plugin base classes do we expose, and how
do plugins get discovered?

## Decision

**Four base classes, two discovery mechanisms.**

### Four classes — one per extension surface

`DetectorPlugin`, `PolicyPlugin`, `ResponderPlugin`, `ConnectorPlugin`.
Each has exactly one required method.

Alternatives considered:

- **One mega-base with optional methods**: rejected. Authors couldn't
  tell from the type system whether their `decide()` would even be
  called. Single-method classes are crystal clear.
- **No base classes, just a protocol/dict**: rejected. We want a class
  attribute (`name`, `version`) for SBOM + introspection, and `isinstance`
  checks for the registry routing.
- **Generic event-bus pattern**: rejected. Too unconstrained — plugin
  authors would invent their own event names and break across versions.

### Two discovery paths

1. **Entry points** (`plenith.plugins` group) — for pip-installed
   plugins. Industry-standard mechanism, supported by importlib.metadata
   in stdlib.
2. **Directory drop-in** (`./plugins/*.py`) — for site-local plugins.
   No packaging required.

We're not building a third (e.g. a URL fetcher, a remote registry).
Two paths covers the operator scenarios we've actually seen.

## Why

1. **Failure isolation.** Every plugin invocation is wrapped in
   `try/except + log`. A site-local detector with a `NameError` cannot
   break the orchestrator. This is the absolute hard requirement for a
   system running on a SOC's hot path.
2. **Explicit contracts.** A typed base class is easier to read in
   isolation than "duck-type this protocol." Maintainers reviewing a
   third-party plugin should be able to skim the file and know what it
   does.
3. **No new runtime dependency.** `importlib.metadata` and
   `importlib.util` are stdlib. We don't take a hit on stluna,
   pluggy, stevedore, or another plugin-framework dependency.
4. **The directory path is the operator-friendly default.** Telling a
   SOC analyst "write a Python file in `./plugins/`" is one step.
   Telling them to `pip install -e .` a private package is several.

## Consequences

- **Plugins run in-process.** A misbehaving plugin's resource use
  (memory, CPU, threads) is the platform's resource use. Compare the
  webhook-based external-service alternative: that adds latency and
  ops surface but isolates failure to the network boundary.
  Decision: in-process is the right trade for V1 — operators who need
  sandboxing can write a thin plugin that posts to their service.
- **Plugin policies override built-ins.** `build_policy("engine: x")`
  consults plugin registry FIRST. If a plugin registers under a built-in
  name (`heuristic`, `rl`, `trained_rl`), the plugin wins. Documented
  in `docs/PLUGINS.md` — authors should pick distinct names.
- **Responders are additive.** When `alert_credential_exfil` fires, the
  built-in `responses._REGISTRY` executor (if any) runs first, then
  every plugin responder declared for that action. Plugins extend; they
  don't replace. Authors who want to *replace* a built-in must
  contribute a PR — that's intentional friction so security-critical
  behavior isn't silently overridden by a config drop.
- **API version 1.0**. New methods on existing base classes are major
  bumps (breaking). Adding new base classes is minor. The `version`
  attribute on plugin instances is the author's; we read it for SBOM
  but don't enforce.
- **No remote plugin registry.** Plugins must come from `pip install`
  or a local file. The threat model (`docs/THREAT_MODEL.md` §EoP) is
  unambiguous: a malicious plugin gets full python-process privileges.
  An auto-update channel would multiply that risk; we don't ship one.

## File pointers

- `plenith/plugins.py` — base classes + registry + discovery
- `tests/test_plugins.py` — 26 tests covering registry, discovery,
  failure isolation, and the build_policy plugin path
- `docs/PLUGINS.md` — operator-facing how-to
- `run.py` — startup discovery hook
- `plenith/orchestrator.py` — calls `run_detectors` and
  `run_responders` on the hot path
- `plenith/policy.py:build_policy` — consults plugin registry first
