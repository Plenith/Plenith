# ADR 012: Secrets resolver — opt-in URI references, lazy backend deps

**Status:** Accepted
**Date:** 2026-05

## Context

`config.yaml` originally held secrets inline: LLM API key, REST API
bearer tokens, Splunk HEC tokens, etc. That's the universal way every
secrets-handling story starts and the universal way every procurement
review blocks it.

Three things needed to be true of the fix:

1. **No breaking change.** Existing deployments shouldn't have to
   migrate everything at once; plaintext values must keep working.
2. **No new mandatory dependency.** Most operators don't run Vault.
   A SOC that wants `env://` shouldn't have to install `hvac` and
   `boto3` just because we support them as options.
3. **Loud failure.** A misconfigured reference must fail at startup,
   not silently. A service that boots with a `None` token is worse
   than one that doesn't boot.

## Decision

**Opt-in `<scheme>://<spec>` references at any string position in
`config.yaml`. Built-in providers for env / file / Vault / AWS SM.
Backend libraries are lazy-imported. Failures are fatal.**

### Provider interface

A provider is a callable `(spec_after_scheme, params) -> str`.
Registered with `register_provider("scheme", fn)`. The resolver walks
the config tree and dispatches on the scheme prefix.

### Discovery + dispatch

Schemes are registered at module load. `_parse_reference(value)`
returns None for plaintext, returns `(scheme, spec, params)` for
references — so a value like `https://example.com` (HTTP URL, not a
secret) passes through unchanged because `https` isn't registered.

### Resolution failure

`SecretResolutionError` raised with a message including:
- the field path in the config (`llm.api_key`)
- the reference URI
- the provider's error

`run.py` and `tools/api_server.py` catch this once at startup, print
a useful diagnostic, and exit with code 2.

## Why

### Why not a "load from $BACKEND for all secret-looking values"
approach?

Two reasons:

1. **Heuristics rot.** Detecting "secret-looking" values via key name
   (`api_key`, `token`, `password`) sounds clean but breaks the day
   someone adds a field named `webhook_path` that contains a token in
   the URL. Explicit references are unambiguous.
2. **Mixed deployments are normal.** A SOC may pull production tokens
   from Vault but use env vars for the LLM key (because the LLM is on
   a local machine with no Vault connectivity). One value, one
   backend, declared per-value.

### Why URI syntax instead of a `{secret: name}` dict?

The dict form (`api_key: {provider: vault, path: secret/data/foo,
key: token}`) is more readable for complex references but breaks the
"plaintext stays plaintext" goal — it changes the *type* of the field
from string to dict.

URI strings let:

- Plaintext stay plaintext.
- Validators and downstream consumers keep expecting a string.
- The whole reference fit on one line in code review.

The tradeoff is less discoverability — the `?param=value` and
`#fragment` syntax has to be documented. `docs/SECRETS.md` is that
documentation.

### Why lazy-import the backend libraries?

`hvac` is ~5 transitive packages; `boto3` is ~30. A SOC that uses only
`env://` shouldn't pay either cost.

`plenith/secrets.py` imports the libraries INSIDE the provider
function. The function only runs when a `vault://` or `aws-sm://`
reference appears in the config — operators get a clear ImportError
message AT USE, not at platform install.

### Why fail loud on resolution errors?

We considered three options:

| Behavior on miss | Outcome |
| :--- | :--- |
| Return the URI literal | Service starts with `api_key = "env://FOO"` — auth attempts fail with a confusing 401, hard to debug |
| Return None / empty string | Service starts with no auth — security catastrophe |
| **Raise / exit non-zero** | Service refuses to start; operator sees the exact field name and the reason at startup |

Option 3 is the only safe choice. The `?default=...` parameter
provides an explicit opt-in for fallback when an operator wants it.

### Why not hot-reload secrets?

A long-running service that picks up rotated secrets mid-flight is
appealing — until it isn't. Mid-process credential rotation means
some in-flight requests use the old credential, some use the new one;
race conditions become possible across the orchestrator's many
concurrent sessions.

Restart-on-rotation is operationally trivial (a systemd unit reload),
the failure mode is obvious, and it composes cleanly with deploy
pipelines. We don't ship hot-reload.

## Consequences

- **Operators must understand reference URIs.** This is one
  additional concept beyond YAML — but it's well-documented and
  parallel to common patterns (e.g. `kubectl` uses `secretRef:` in
  values, Kustomize uses `valueFrom:`, etc.).
- **The resolver is a single integration point.** Every config-loading
  call site has to invoke `resolve()`. Currently that's `run.py` and
  `tools/api_server.py`. Future config readers should follow the
  same pattern.
- **Connectors take resolved values.** Connector constructors
  (`SplunkHEC(token=...)`, etc.) receive plain strings after resolve.
  The resolver runs before the orchestrator is even built.
- **No support for binary secrets.** AWS SM `SecretBinary` is
  explicitly rejected — we couldn't construct a clean string API for
  the field. Operators with binary secrets should mount them as files
  and use `file://`.
- **`env://`-style refs are now blessed as a permission boundary.**
  A SOC that uses only env vars is on the supported path. They are
  *less* secure than Vault / AWS SM (env vars are readable via
  `/proc/<pid>/environ`), but they are MORE secure than plaintext
  in `config.yaml` and they require zero extra infrastructure.
- **Custom providers are first-class.** Azure Key Vault, GCP Secret
  Manager, and proprietary backends can register their own scheme
  without forking. Documented in `docs/SECRETS.md`.

## File pointers

- `plenith/secrets.py` — resolver core + built-in providers
- `tools/secrets_check.py` — staging-gate CLI
- `docs/SECRETS.md` — operator guide with patterns
- `tests/test_secrets.py` — coverage including the lazy-import path
- `run.py`, `tools/api_server.py` — integration points
