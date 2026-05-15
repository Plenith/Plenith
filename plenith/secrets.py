"""Secrets resolver — pull secret values from external stores at config load.

The platform's `config.yaml` traditionally held secrets inline:

    llm:
      api_key: sk-real-credential-here
    connectors:
      splunk:
        hec_token: <real-token>

That's fine for a developer laptop but fails procurement review in any
regulated environment. This module lets operators write references
instead:

    llm:
      api_key: env://PLENITH_LLM_API_KEY
    connectors:
      splunk:
        hec_token: vault://secret/data/plenith/splunk#token

At config-load time, `resolve(cfg)` walks the dict tree and replaces
matching string values with the resolved secret. Plaintext values pass
through unchanged — the feature is opt-in per value, not all-or-
nothing.

## Built-in providers

| Scheme   | Source                          | Optional dep |
| :------- | :------------------------------ | :----------- |
| `env://` | `os.environ[name]`              | none |
| `file://`| Contents of a file              | none |
| `vault://` | HashiCorp Vault KV v2          | `hvac` |
| `aws-sm://` | AWS Secrets Manager           | `boto3` |

Third-party providers can register via `register_provider()` — the
plugin system in `plenith/plugins.py` can wire this in if needed.

## Reference syntax

Every reference looks like `<scheme>://<spec>[#<json-pointer>]`.

- `env://VAR` — read env var `VAR`. If unset → raise unless the
  reference includes a default: `env://VAR?default=foo`.
- `file:///abs/path` or `file://./relative/path` — read the entire
  file (stripping trailing newline). Useful for Docker / Kubernetes
  secret mounts.
- `vault://path#key` — read `path` from Vault's KV v2, return `key`.
  Address + token from `VAULT_ADDR` + `VAULT_TOKEN` env vars (matches
  the Vault CLI).
- `aws-sm://name#key` — read `name` from AWS Secrets Manager, parse
  as JSON, return `key`. If `#key` is omitted, return the raw secret
  string.

## Failure mode

A reference that can't be resolved raises `SecretResolutionError`
during config load. We do NOT silently return `None` or the literal
URI — that's worse than the original plaintext problem because the
service starts with broken auth.

The exception message names the field path (`llm.api_key`) and the
underlying cause so operators can diagnose without grepping.

## Cost

Resolution happens once at startup. Vault / AWS calls are network IO
on cold start (~50–300ms each); env / file are essentially free.
We cache resolved values within one `resolve()` call so repeated
references to the same URI don't hit the backend twice.
"""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any
from collections.abc import Callable
from urllib.parse import parse_qs, urlparse

logger = logging.getLogger("plenith.secrets")

# Match `<scheme>://<rest>` where scheme is a known/registered provider.
# We compile this dynamically because providers can be registered at
# runtime (third-party plugins). Cached on first compile per known
# scheme set.
_SCHEME_RE = re.compile(r"^([a-z][a-z0-9+\-]*)://")

class SecretResolutionError(RuntimeError):
    """Raised when a secret reference cannot be resolved.

    The message includes:
      - the field path in the config (e.g. `llm.api_key`)
      - the reference URI
      - the underlying error from the provider
    """

# ---------------------------------------------------------------------------
# Provider interface
# ---------------------------------------------------------------------------

# A provider is a callable: (spec_after_scheme, query_params) -> resolved_str.
# `spec_after_scheme` is everything between `://` and `?` / `#` (the
# "address" within the backend). `query_params` is the parsed
# ?key=value&... part (with `default` already extracted by the caller).
Provider = Callable[[str, dict[str, list[str]]], str]

_PROVIDERS: dict[str, Provider] = {}

def register_provider(scheme: str, fn: Provider) -> None:
    """Register a custom provider. Scheme MUST be lowercase + a valid
    URI scheme character set (letters, digits, +, -). Re-registering
    replaces."""
    if not re.fullmatch(r"[a-z][a-z0-9+\-]*", scheme):
        raise ValueError(
            f"invalid scheme {scheme!r}; use lowercase letters/digits/+/-"
        )
    _PROVIDERS[scheme] = fn

def registered_schemes() -> list[str]:
    return sorted(_PROVIDERS.keys())

# ---------------------------------------------------------------------------
# Built-in providers
# ---------------------------------------------------------------------------

def _provider_env(spec: str, params: dict[str, list[str]]) -> str:
    """`env://VAR_NAME` — read environment variable."""
    name = spec
    val = os.environ.get(name)
    if val is None:
        raise SecretResolutionError(
            f"env var {name!r} is not set"
        )
    return val

def _provider_file(spec: str, params: dict[str, list[str]]) -> str:
    """`file:///abs/path` or `file://relative/path` — read a file.

    The contents are returned verbatim except a single trailing newline
    is stripped (the common case: `echo my-secret > /run/secret/foo`).
    Use `?strip=false` to preserve every byte.
    """
    if not spec:
        raise SecretResolutionError("file:// reference has no path")
    path = Path(spec)
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as e:
        raise SecretResolutionError(f"could not read {path}: {e}") from e
    strip = params.get("strip", ["true"])[0].lower() != "false"
    if strip:
        content = content.rstrip("\n")
    return content

def _provider_vault(spec: str, params: dict[str, list[str]]) -> str:
    """`vault://kv/path#key` — read a KV v2 secret from HashiCorp Vault.

    Uses VAULT_ADDR + VAULT_TOKEN from env (same convention as the
    Vault CLI). The `spec` is the secret path WITHOUT the `#key`
    portion — `resolve()` strips the fragment and passes it via params
    as `_fragment`.

    Requires `hvac`. Lazy-imported so we don't take the dep unless
    actually used.
    """
    try:
        import hvac    # type: ignore
    except ImportError as e:
        raise SecretResolutionError(
            "vault:// references require the `hvac` package "
            "(pip install hvac). Not installed."
        ) from e

    addr = os.environ.get("VAULT_ADDR")
    token = os.environ.get("VAULT_TOKEN")
    if not addr or not token:
        raise SecretResolutionError(
            "vault:// references require VAULT_ADDR + VAULT_TOKEN env "
            "vars (same as the Vault CLI)."
        )

    key_in_secret = params.get("_fragment", [""])[0]
    if not key_in_secret:
        raise SecretResolutionError(
            "vault:// references must include a fragment key, e.g. "
            "`vault://secret/data/foo#token`"
        )

    client = hvac.Client(url=addr, token=token)
    try:
        # Strip leading "secret/data/" if present — hvac wraps it.
        path = spec
        if path.startswith("secret/data/"):
            path = path[len("secret/data/"):]
        resp = client.secrets.kv.v2.read_secret_version(path=path)
    except Exception as e:
        raise SecretResolutionError(
            f"vault read failed for {spec!r}: {e}"
        ) from e

    data = (resp or {}).get("data", {}).get("data", {}) or {}
    if key_in_secret not in data:
        raise SecretResolutionError(
            f"key {key_in_secret!r} not found in vault secret {spec!r}; "
            f"available keys: {sorted(data.keys())}"
        )
    return str(data[key_in_secret])

def _provider_aws_sm(spec: str, params: dict[str, list[str]]) -> str:
    """`aws-sm://secret-name#key` — read from AWS Secrets Manager.

    If the secret value is a JSON object, the fragment key selects a
    field within it. If the value is a plain string, the fragment must
    be omitted.

    Region: AWS_REGION env var or boto3 default chain.
    Auth: standard boto3 chain (env / shared credentials / instance role).

    Requires `boto3`. Lazy-imported.
    """
    try:
        import boto3    # type: ignore
        from botocore.exceptions import BotoCoreError, ClientError    # type: ignore
    except ImportError as e:
        raise SecretResolutionError(
            "aws-sm:// references require the `boto3` package "
            "(pip install boto3). Not installed."
        ) from e

    secret_name = spec
    key = params.get("_fragment", [""])[0]

    region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
    client_kwargs = {"region_name": region} if region else {}

    try:
        client = boto3.client("secretsmanager", **client_kwargs)
        resp = client.get_secret_value(SecretId=secret_name)
    except (BotoCoreError, ClientError) as e:
        raise SecretResolutionError(
            f"aws secrets manager fetch failed for {secret_name!r}: {e}"
        ) from e

    raw = resp.get("SecretString")
    if raw is None:
        raise SecretResolutionError(
            f"aws secret {secret_name!r} has no SecretString "
            "(binary secrets not supported)"
        )

    if not key:
        return raw

    # Parse as JSON to extract the keyed field
    import json
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        raise SecretResolutionError(
            f"aws secret {secret_name!r} has fragment {key!r} requested "
            f"but secret is not valid JSON: {e}"
        ) from e
    if not isinstance(parsed, dict) or key not in parsed:
        raise SecretResolutionError(
            f"key {key!r} not in aws secret {secret_name!r}; "
            f"available: {sorted(parsed.keys()) if isinstance(parsed, dict) else 'not-a-dict'}"
        )
    return str(parsed[key])

# Built-in providers register at module load. Re-registering at runtime
# replaces — useful for tests.
register_provider("env",    _provider_env)
register_provider("file",   _provider_file)
register_provider("vault",  _provider_vault)
register_provider("aws-sm", _provider_aws_sm)

# ---------------------------------------------------------------------------
# Resolver core
# ---------------------------------------------------------------------------

def _parse_reference(value: str) -> tuple[str, str, dict[str, list[str]]] | None:
    """If `value` looks like `<scheme>://...`, parse and return
    (scheme, spec, params). Otherwise return None.

    Params dict includes the query string (?k=v) AND `_fragment` for
    the #... part (so providers can route on it).
    """
    m = _SCHEME_RE.match(value)
    if not m:
        return None
    scheme = m.group(1)
    if scheme not in _PROVIDERS:
        # Unknown scheme — treat as plaintext rather than fail. The
        # operator may legitimately have a value like `https://...` in
        # the config (URL); we don't want to claim that's a secret ref.
        return None
    # Use urllib to peel off ? and #.
    rest = value[len(scheme) + 3:]    # strip "scheme://"
    # Manually split because urlparse drops empty hostnames for some
    # schemes. We want everything between :// and ? as `spec`.
    fragment = ""
    if "#" in rest:
        rest, fragment = rest.split("#", 1)
    if "?" in rest:
        spec, qs = rest.split("?", 1)
        params = parse_qs(qs, keep_blank_values=True)
    else:
        spec, params = rest, {}
    if fragment:
        params["_fragment"] = [fragment]
    return scheme, spec, params

def _resolve_value(value: str, *, cache: dict[str, str], field_path: str) -> str:
    """Resolve a single string value. Returns the original on no-match
    or raises SecretResolutionError on resolution failure."""
    parsed = _parse_reference(value)
    if parsed is None:
        return value

    # Cache by full URI so we don't double-call backends.
    if value in cache:
        return cache[value]

    scheme, spec, params = parsed
    # Extract `default` from params before passing to the provider, so
    # providers don't have to handle it individually.
    default_vals = params.pop("default", [])
    default = default_vals[0] if default_vals else None

    try:
        resolved = _PROVIDERS[scheme](spec, params)
    except SecretResolutionError as e:
        if default is not None:
            cache[value] = default
            logger.warning(
                "%s: %s resolution failed (%s); using default",
                field_path, value, e,
            )
            return default
        raise SecretResolutionError(
            f"{field_path}: failed to resolve {value!r}: {e}"
        ) from e
    except Exception as e:
        if default is not None:
            cache[value] = default
            logger.warning(
                "%s: %s provider raised %s; using default",
                field_path, value, e,
            )
            return default
        raise SecretResolutionError(
            f"{field_path}: provider error resolving {value!r}: {e}"
        ) from e

    cache[value] = resolved
    return resolved

def resolve(
    cfg: Any,
    *,
    path: str = "",
    cache: dict[str, str] | None = None,
) -> Any:
    """Walk `cfg` (any nested dict / list / scalar) and replace string
    values matching a registered secret-reference scheme.

    The structure is preserved. Lists and dicts are recreated (not
    mutated in place), so the caller's input dict is unchanged.

    Path tracking: `path` accumulates dotted-or-bracketed component
    names for error messages — e.g. an error in `cfg["llm"]["api_key"]`
    reports as `llm.api_key`.

    Cache: passed through recursive calls so the same reference URI
    isn't resolved multiple times (avoids hammering Vault / AWS SM for
    the same value used in two places).
    """
    if cache is None:
        cache = {}

    if isinstance(cfg, dict):
        return {
            k: resolve(
                v,
                path=f"{path}.{k}" if path else str(k),
                cache=cache,
            )
            for k, v in cfg.items()
        }

    if isinstance(cfg, list):
        return [
            resolve(
                v,
                path=f"{path}[{i}]",
                cache=cache,
            )
            for i, v in enumerate(cfg)
        ]

    if isinstance(cfg, str):
        return _resolve_value(cfg, cache=cache, field_path=path or "<root>")

    # ints / floats / bools / None pass through unchanged
    return cfg

# ---------------------------------------------------------------------------
# Inspection — used by tools/secrets_check.py
# ---------------------------------------------------------------------------

def find_references(cfg: Any, *, path: str = "") -> list[tuple[str, str]]:
    """Walk `cfg` and return every (field_path, reference_uri) pair
    that looks like a secret reference. Pure / does NOT resolve."""
    out: list[tuple[str, str]] = []
    if isinstance(cfg, dict):
        for k, v in cfg.items():
            out.extend(find_references(
                v, path=f"{path}.{k}" if path else str(k)
            ))
    elif isinstance(cfg, list):
        for i, v in enumerate(cfg):
            out.extend(find_references(v, path=f"{path}[{i}]"))
    elif isinstance(cfg, str):
        if _parse_reference(cfg) is not None:
            out.append((path or "<root>", cfg))
    return out

def redact(cfg: Any) -> Any:
    """Return a copy of `cfg` with every resolved secret-shaped value
    replaced by `***REDACTED***`. Heuristic-based — matches values at
    keys named like 'token', 'password', 'secret', 'key' (case-
    insensitive). Used for safe display in logs / dashboards.

    Reference-form values (env://, file://, etc.) are returned as-is
    since they don't reveal the secret.
    """
    SENSITIVE_KEYS = re.compile(
        r"(token|password|secret|api_?key|hec|webhook)", re.IGNORECASE
    )

    def _walk(node: Any, parent_key: str | None = None) -> Any:
        if isinstance(node, dict):
            return {k: _walk(v, parent_key=str(k)) for k, v in node.items()}
        if isinstance(node, list):
            return [_walk(v, parent_key=parent_key) for v in node]
        if isinstance(node, str):
            # Reference-form passes through (it's NOT the secret).
            if _parse_reference(node) is not None:
                return node
            if parent_key and SENSITIVE_KEYS.search(parent_key):
                return "***REDACTED***"
        return node

    return _walk(cfg)
