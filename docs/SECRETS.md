# Secrets handling

By default, `config.yaml` accepts plaintext values — fine for a
developer laptop, **not fine for production**. This page covers how to
pull every secret in your config from an external store (env vars,
mounted files, HashiCorp Vault, AWS Secrets Manager, or a custom
provider) without forking the platform.

The mechanism is opt-in per value: write `<scheme>://...` in place of
the plaintext, and `plenith.secrets.resolve` rewrites it at config
load. Mixed configs (some plaintext, some references) are fully
supported.

---

## Built-in providers

| Scheme | Source | Optional dep | Common use |
| :--- | :--- | :--- | :--- |
| `env://` | `os.environ` | none | Local dev, simple containers |
| `file://` | A file on disk | none | Docker secrets, Kubernetes secrets |
| `vault://` | HashiCorp Vault KV v2 | `hvac` | Existing Vault deployment |
| `aws-sm://` | AWS Secrets Manager | `boto3` | EKS / EC2 / Lambda |

Third-party providers can register via `register_provider()` — see
"Custom providers" below.

---

## Reference syntax

Every reference looks like `<scheme>://<spec>[?param=value][#fragment]`.

- `<spec>` — the address within the backend (env var name, file path,
  Vault path, AWS secret name).
- `?param=value` — provider-specific options. The cross-cutting
  options are:
  - `?default=foo` — if the backend fails, use `foo` instead of
    raising. Use sparingly — silent fallbacks hide misconfiguration.
- `#fragment` — for backends that return structured data (Vault KV,
  AWS Secrets Manager with JSON values), select a specific key.

### `env://`

```yaml
llm:
  api_key: env://PLENITH_LLM_API_KEY
```

With a default fallback:

```yaml
llm:
  api_key: env://PLENITH_LLM_API_KEY?default=lm-studio
```

The `default` form is useful for local dev (you set the env var only
in production; locally the literal default works).

### `file://`

```yaml
api:
  token_file: file:///run/secrets/plenith-api-token
```

Trailing newlines are stripped by default (matches the common
`echo SECRET > /run/secret/foo` pattern). To preserve every byte:

```yaml
auth: file:///etc/plenith/key.pem?strip=false
```

Relative paths are interpreted relative to the process's working
directory.

### `vault://`

```yaml
connectors:
  splunk:
    hec_token: vault://secret/data/plenith/splunk#token
```

- Path: standard Vault KV v2 path. `secret/data/` prefix is optional;
  we'll add it if missing.
- Fragment: the key within the secret.
- Auth: read `VAULT_ADDR` + `VAULT_TOKEN` from env (same as the
  Vault CLI). For Kubernetes or other auth methods, set up a sidecar
  that establishes the token before Plenith starts.
- Requires `hvac` (`pip install hvac`).

### `aws-sm://`

```yaml
connectors:
  splunk:
    hec_token: aws-sm://prod/plenith/splunk#token
```

If the secret is a JSON object, the fragment selects a field. If it's
a plain string, omit the fragment:

```yaml
auth: aws-sm://prod/plenith/api-bearer
```

- Region: `AWS_REGION` env var, or boto3's default chain.
- Auth: standard boto3 chain (env / shared credentials /
  instance profile).
- Requires `boto3` (`pip install boto3`).

---

## How it ties into config loading

In `run.py` and `tools/api_server.py`, immediately after
`yaml.safe_load`:

```python
from plenith.secrets import resolve as resolve_secrets, SecretResolutionError

try:
    cfg = resolve_secrets(raw_cfg)
except SecretResolutionError as e:
    print(f"FATAL: secret resolution failed: {e}", file=sys.stderr)
    raise SystemExit(2)
```

A failure to resolve is fatal — the service does NOT start with broken
auth. The exception message names the field path so you can fix the
reference without grepping.

---

## Verifying your references

`tools/secrets_check.py` is the staging gate:

```bash
# List every reference in config.yaml
python tools/secrets_check.py

# Verify each reference actually resolves
python tools/secrets_check.py --resolve

# JSON output for CI
python tools/secrets_check.py --resolve --json
```

Exit code is 0 when every reference resolves, 1 on any failure. Drop
this into your deploy pipeline before the `systemctl start`.

---

## Operational patterns

### Pattern 1 — env vars (smallest setup)

```yaml
# config.yaml
llm:
  api_key: env://PLENITH_LLM_API_KEY
api:
  tokens:
    - env://PLENITH_API_TOKEN
```

```bash
# systemd unit drop-in
# /etc/systemd/system/plenith.service.d/secrets.conf
[Service]
Environment="PLENITH_LLM_API_KEY=sk-..."
Environment="PLENITH_API_TOKEN=..."
```

Or for Docker:

```bash
docker run --env-file /etc/plenith/secrets.env plenith:latest
```

Pros: no new dependency.
Cons: secrets in env vars are visible via `/proc/<pid>/environ` to any
local user. Better than plaintext-in-config; not as good as the next
patterns.

### Pattern 2 — Docker / Kubernetes secrets via `file://`

```yaml
llm:
  api_key: file:///run/secrets/llm-api-key
```

```yaml
# docker-compose.yml
services:
  plenith:
    secrets:
      - llm-api-key
secrets:
  llm-api-key:
    file: ./secrets/llm-api-key.txt
```

```yaml
# Kubernetes
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: plenith
          volumeMounts:
            - name: secrets
              mountPath: /run/secrets
              readOnly: true
      volumes:
        - name: secrets
          secret:
            secretName: plenith-secrets
            items:
              - { key: llm-api-key, path: llm-api-key }
```

Pros: secrets aren't in env vars; the file is owned by root, mode 0400.
Cons: secrets are still plaintext at rest on the node.

### Pattern 3 — HashiCorp Vault

```yaml
llm:
  api_key: vault://secret/data/plenith/llm#api_key
api:
  tokens:
    - vault://secret/data/plenith/api#bearer
connectors:
  splunk:
    hec_token: vault://secret/data/plenith/splunk#token
```

Start the orchestrator with `VAULT_ADDR` + `VAULT_TOKEN` already set.
For long-running services, use Vault Agent as a sidecar that maintains
the token; Plenith reads it once at startup, so periodic token
renewal is invisible.

Pros: central audit log of who pulled which secret when; rotation
without restarting the application (just `systemctl restart` to pick
up new values).
Cons: ops overhead of Vault itself.

### Pattern 4 — AWS Secrets Manager

```yaml
llm:
  api_key: aws-sm://prod/plenith/llm#api_key
connectors:
  splunk:
    hec_token: aws-sm://prod/plenith/splunk#token
```

Attach an IAM role to the EC2 instance / EKS pod that has
`secretsmanager:GetSecretValue` on the relevant ARNs.

Pros: native to AWS deployments; no extra service to run.
Cons: AWS-specific (don't write code that assumes AWS-SM is available
in a multi-cloud config).

### Pattern 5 — SOPS-encrypted files (no built-in provider)

Decrypt to a tmpfs before starting Plenith:

```bash
sops -d /etc/plenith/config.sops.yaml > /run/plenith/config.yaml
python run.py
```

`config.sops.yaml` can still use `file://` and `env://` references
inside — composes cleanly.

---

## Mixing schemes

Different fields can use different backends:

```yaml
llm:
  api_key: env://PLENITH_LLM_API_KEY      # local-dev friendly
api:
  tokens:
    - vault://secret/data/plenith/api#bearer    # production
connectors:
  splunk:
    hec_token: file:///run/secrets/splunk-hec      # k8s secret
  custom_siem:
    api_key: aws-sm://prod/customsiem#key          # AWS native
```

The resolver doesn't care; each value is independent.

---

## Custom providers

To add a new backend (e.g. Azure Key Vault, GCP Secret Manager, or
a proprietary internal store), register a callable at import time:

```python
# myorg_secrets.py
from plenith.secrets import register_provider, SecretResolutionError

def azure_kv(spec, params):
    """Resolve `azure-kv://vault-name/secret-name`."""
    try:
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.secrets import SecretClient
    except ImportError as e:
        raise SecretResolutionError(
            "azure-kv:// requires azure-keyvault-secrets + azure-identity"
        ) from e
    vault_name, secret_name = spec.split("/", 1)
    client = SecretClient(
        vault_url=f"https://{vault_name}.vault.azure.net",
        credential=DefaultAzureCredential(),
    )
    return client.get_secret(secret_name).value

register_provider("azure-kv", azure_kv)
```

Drop `import myorg_secrets` near the top of `run.py` (or ship it as a
plugin discovered by `plenith.plugins`).

A custom provider integrates exactly like a built-in: `azure-kv://...`
in `config.yaml`, the resolver dispatches automatically.

---

## What's still in plaintext

Some files in the repo legitimately contain non-secret config:

- `personas/*.yaml` — synthetic persona definitions. Not secrets.
- `caches/*.yaml` — cached command outputs. Not secrets.
- `state-docker/persistence/*.json` — engagement state. Sensitive but
  not "secret" in the credential sense; protected by retention +
  hash-chained audit.
- `config.yaml` paths, ports, model names, etc. — operational config,
  not credentials.

Only fields that are *credentials* should be moved into a secrets
backend. The DPIA (`docs/DPIA.md`) is the canonical list of what's
sensitive.

---

## Operational guardrails

- **Never log resolved secrets.** The resolver itself doesn't log
  resolved values; if you write code that does, use `redact()` from
  `plenith.secrets` to mask them first.
- **Rotate on demand.** Reading a secret happens once at process
  start. To pick up a rotated value, restart the process. (We don't
  hot-reload because mid-process credential changes are a footgun —
  better to fail loud at startup than silently mix versions.)
- **Pin reference URIs in your IaC.** The plaintext is in your
  secrets backend; the reference is in `config.yaml`. Treat the
  reference like any other code — version-controlled, code-reviewed.
- **Run `secrets_check.py --resolve` in staging** before promoting to
  production. The exit code is your gate.

---

## Verification checklist

Before declaring a production deployment "secrets-clean":

- [ ] `grep -E '(api_key|token|password|secret):' config.yaml` returns
      only `<scheme>://...` references — no plaintext.
- [ ] `python tools/secrets_check.py --resolve --json` exits 0.
- [ ] `python tools/secrets_check.py --resolve --show-redacted`
      produces the expected resolved-and-masked config.
- [ ] No secret values appear in process env / shell history /
      systemd journal.
- [ ] Rotation procedure documented in your runbook (which command
      restarts Plenith after a secret rotation in your backend).
