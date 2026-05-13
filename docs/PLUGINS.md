# Writing a Plenith plugin

Plenith ships with a curated set of detectors, responders, and
SIEM/SOAR/TI connectors. Operators in regulated industries or specific
verticals frequently need to add their own. Rather than forking the
codebase, write a plugin.

There are **four plugin types**:

| Type | When to use | Hot path |
| :--- | :--- | :--- |
| `DetectorPlugin` | Add a new observation signal — "we saw the attacker do X" | Called once per command |
| `PolicyPlugin` | Replace the action-selection engine entirely | Called once per command |
| `ResponderPlugin` | Add a side effect when a particular action fires | Called per action, after the built-in executor |
| `ConnectorPlugin` | Ship alerts to a new external system | Called per alert |

Plugins are loaded via **two mechanisms**:

1. **Entry points** — for pip-installable packages. Best for sharing with
   the community or installing across many Plenith deployments.
2. **Directory drop-in** — for site-local plugins. Put a `.py` file in
   `./plugins/` next to `run.py`. No packaging required.

Both feed the same registry. Pick whichever fits your distribution model.

---

## 1. Detector plugin — adding an observation

```python
# plugins/swift_staging_detector.py
from plenith.plugins import DetectorPlugin


class SwiftStagingDetector(DetectorPlugin):
    """Detect attackers staging fake SWIFT MT103 payment files."""

    name = "swift_staging_detector"
    version = "1.0.0"

    def observe(self, session, command):
        if "MT103" in command and "/tmp/" in command:
            session.observed["swift_staging_attempt"] = True
            session.observed.setdefault(
                "swift_commands", set()
            ).add(command)


PLUGIN = SwiftStagingDetector()
```

That's it. On the next engagement, your detector runs on every command.
The platform's built-in heuristics (`plenith/heuristics.py`) won't
fire on `swift_staging_attempt` — for that you also need either:

- a **policy plugin** that reads `obs["swift_staging_attempt"]` and
  emits an action, or
- a one-line patch in `heuristics.py` for an upstream contribution.

The detector hot path is wrapped in `try/except`; a buggy plugin can't
take down the engagement.

---

## 2. Responder plugin — side effects on action

```python
# plugins/edge_firewall_block.py
import requests
from plenith.plugins import ResponderPlugin


class EdgeFirewallBlock(ResponderPlugin):
    """When the platform alerts on credential exfil or reverse shell,
    push a block rule to our edge firewall via its REST API."""

    name = "edge_firewall_block"
    version = "1.0.0"
    handles = ["alert_credential_exfil", "alert_reverse_shell"]

    def execute(self, session, action):
        requests.post(
            "https://fw.internal/v1/block",
            json={
                "ip": session.source_ip,
                "reason": action["action"],
                "ttl_seconds": 3600,
            },
            timeout=2.0,
        )


PLUGIN = EdgeFirewallBlock()
```

Responder plugins are **additive** — the built-in executor (e.g.
`responses._plant_aws_credentials`) still runs. Plugins run after, in
registration order. A buggy plugin doesn't block sibling responders.

---

## 3. Policy plugin — alternate action selector

```python
# plugins/ml_policy.py
from plenith.plugins import PolicyPlugin


class MLPolicy(PolicyPlugin):
    name = "myorg_ml"
    version = "2.1.0"

    def __init__(self, model_path):
        import joblib
        self.model = joblib.load(model_path)

    def decide(self, session):
        features = self._vectorize(session)
        action_id = int(self.model.predict([features])[0])
        if action_id == 0:
            return None
        return {
            "action":   self._action_name(action_id),
            "severity": self._severity(action_id),
            "rationale": f"MLPolicy chose {action_id}.",
        }

    def _vectorize(self, session):
        ...


def PLUGIN():    # factory — instantiation deferred until load time
    return MLPolicy(model_path="/opt/plenith/models/policy_v3.pkl")
```

Then in `config.yaml`:

```yaml
policy:
  engine: myorg_ml
```

Plugin policies win over the built-in registry, so `engine: myorg_ml`
returns the plugin instance instead of falling back to `heuristic`.

---

## 4. Connector plugin — ship to a custom backend

```python
# plugins/internal_siem.py
import json
import requests
from plenith.plugins import ConnectorPlugin


class InternalSIEM(ConnectorPlugin):
    name = "internal_siem"
    version = "1.0.0"

    def emit(self, alert):
        requests.post(
            "https://siem.internal/api/ingest",
            data=json.dumps(alert),
            headers={"Content-Type": "application/json",
                      "X-Auth": "..."},
            timeout=3.0,
        )


PLUGIN = InternalSIEM()
```

---

## Drop-in directory

The default plugin directory is `./plugins/` next to `run.py`. Create it
if it doesn't exist:

```
plenith-mvp/
├── run.py
├── plugins/                <-- add this
│   ├── swift_staging_detector.py
│   └── edge_firewall_block.py
```

Each `.py` file must export a module-level `PLUGIN` symbol that's one of:

- a `PluginBase` instance (most common)
- a list / tuple of `PluginBase` instances (one file, many plugins)
- a zero-arg callable returning either of the above (factory)

Files starting with `_` (e.g. `__init__.py`, `_helpers.py`) are skipped.

---

## pip-installable plugin

For broader distribution, ship your plugin as a Python package with an
entry point:

```toml
# pyproject.toml
[project]
name = "plenith-swift-detector"
version = "1.0.0"

[project.entry-points."plenith.plugins"]
swift_detector = "plenith_swift_detector:make_plugin"
```

`make_plugin` is a zero-arg callable returning a `PluginBase` instance.
Once `pip install`-ed in the same env as Plenith, it's picked up on
the next start.

---

## Failure isolation

Plugins run on the engagement hot path. **A bug in a plugin must never
take down the platform.** The registry wraps every plugin invocation in
`try/except` and logs the traceback under `plenith.plugins`. The
session continues with the built-in behavior.

This is a hard guarantee: the tests under `tests/test_plugins.py`
exercise the "exploding plugin" case and assert the orchestrator
proceeds.

---

## Performance contract

- `DetectorPlugin.observe()` runs on every command. Target **p99 < 1ms**.
  If your detector needs IO or model inference, defer to a background
  task and just set a flag on `session.observed`.
- `ResponderPlugin.execute()` runs per fired action. Side effects with
  external APIs should use **short timeouts** (2–3s) so the engagement
  loop doesn't block on a slow firewall API.
- `PolicyPlugin.decide()` runs once per command. Same 1ms budget as
  detectors — this is in the inner loop.
- `ConnectorPlugin.emit()` runs once per alert. Connectors should be
  **async-safe**; if you need to do heavy work, hand off to a thread
  or queue.

---

## Introspection

The dashboard's `/api/state.json` includes a `plugins` summary block
(name + category + version) so operators can verify their plugins
loaded. At runtime:

```python
from plenith.plugins import get_registry
print(get_registry().summary())
```

---

## Versioning + back-compat

The plugin API is `1.0`. We follow semver: new optional methods or new
plugin subclasses are minor bumps; renaming or removing methods on the
four base classes is major. The `version` attribute on each plugin is
yours — we don't enforce anything on it, but the SBOM tool reads it.

If you ship a plugin to the community, please:

- Pin the Plenith version you tested against.
- Declare a permissive license (we recommend MIT or Apache 2.0 for
  consistency with the platform itself).
- Add a `README.md` describing the detection / response and any
  required config or secrets.
