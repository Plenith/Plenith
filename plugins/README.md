# Drop-in plugins

This directory is auto-scanned at startup. Drop a `.py` file here that
exports a module-level `PLUGIN` symbol; it gets registered and runs on
the next engagement.

See `../docs/PLUGINS.md` for the full guide.

## Quick examples

A minimal detector:

```python
# my_detector.py
from plenith.plugins import DetectorPlugin

class MyDetector(DetectorPlugin):
    name = "my_detector"
    def observe(self, session, command):
        if "kubectl get secrets" in command:
            session.observed["k8s_secret_dump"] = True

PLUGIN = MyDetector()
```

A minimal responder:

```python
# alert_webhook.py
import requests
from plenith.plugins import ResponderPlugin

class AlertWebhook(ResponderPlugin):
    name = "alert_webhook"
    handles = ["alert_credential_exfil", "alert_reverse_shell"]
    def execute(self, session, action):
        requests.post("https://hooks.example/...", json=action, timeout=2)

PLUGIN = AlertWebhook()
```

Files starting with `_` (e.g. `_helpers.py`, `__init__.py`) are skipped.

Failures in any plugin are logged under `plenith.plugins` and never
propagate to the engagement loop.
