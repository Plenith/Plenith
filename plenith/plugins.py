"""Plugin / extension system for third-party heuristics + responses.

The platform ships with a fixed set of detectors (`heuristics.py`),
response executors (`responses.py`), and SIEM/SOAR/TI connectors
(`connectors/`). Operators in regulated industries or specific verticals
(banking, healthcare, OT) frequently need to add:

  * a custom detector — e.g. "if the command matches our org-specific
    SWIFT-payment-staging regex, set obs['swift_staging_attempt'] = True"
  * a custom response — e.g. "when alert_credential_exfil fires, also
    nuke the source IP at our edge firewall via its proprietary API"
  * a custom policy — e.g. "swap in our ML-based action selector"
  * a custom connector — e.g. "ship to our internal SIEM that doesn't
    speak CEF or Splunk HEC"

Forking the codebase for each is a non-starter — it makes upgrades
painful and tracks divergence in places it shouldn't. This module gives
those extensions a stable contract and two discovery mechanisms:

  1. **Entry points** — for plugins shipped as pip-installable packages.
     Authors add to their `pyproject.toml`:

         [project.entry-points."plenith.plugins"]
         my_swift_detector = "my_plugin:make_detector"

     The entry-point target is a zero-arg callable returning a plugin
     instance, or a plugin instance directly.

  2. **Directory drop-in** — for site-local plugins that aren't worth
     packaging. Operators drop `plugins/<name>.py` files at the repo
     root; each file defines a module-level `PLUGIN = MyDetector(...)`.

Both mechanisms feed the same `PluginRegistry`. Use
`plenith.plugins.get_registry()` from anywhere in the codebase to
read it. The orchestrator, policy builder, and response dispatcher are
all wired to consult the registry.

Failure isolation: a buggy plugin must NEVER take down the orchestrator.
Every plugin invocation is wrapped in try/except + structured-log and
the engagement continues with the built-in behavior.
"""
from __future__ import annotations

import importlib.util
import logging
from pathlib import Path
from typing import Any
from collections.abc import Callable, Iterable, Sequence

logger = logging.getLogger("plenith.plugins")

# ---------------------------------------------------------------------------
# Plugin base classes — these are the contracts third parties bind against.
# Each one is intentionally small. Adding methods later is a breaking
# change to plugin authors, so the surface stays minimal.
# ---------------------------------------------------------------------------

class PluginBase:
    """Common base. All plugins have a name (for logging / introspection)
    and a version (for compatibility checks / SBOM). Subclass one of the
    specialized bases below; don't subclass `PluginBase` directly."""

    name: str = "abstract"
    version: str = "0.0.0"

    def __repr__(self) -> str:   # pragma: no cover - cosmetic
        return f"<{type(self).__name__} name={self.name!r} v{self.version}>"

class DetectorPlugin(PluginBase):
    """Adds observations to `session.observed`. Called once per command
    after the built-in observation update, before the policy fires.

    Implementations should be FAST (target < 1 ms p99) — they run on the
    hot path of every command. Set boolean flags or extend sets on
    `session.observed`; the policy will pick them up next.

    Example:
        class SwiftStagingDetector(DetectorPlugin):
            name = "swift_staging_detector"
            version = "1.0.0"

            def observe(self, session, command):
                if "MT103" in command and "/tmp/" in command:
                    session.observed["swift_staging_attempt"] = True
                    session.observed.setdefault("swift_commands", set()).add(command)
    """

    def observe(self, session, command: str) -> None:
        raise NotImplementedError

class PolicyPlugin(PluginBase):
    """Action selector — same contract as `plenith.policy.Policy`.

    Registered under `name` and selectable via `policy.engine: <name>`
    in `config.yaml`. Returns either an action dict (per the existing
    contract: `{"action": str, "severity": str, "rationale": str}`) or
    None when the policy has nothing to fire this tick.
    """

    def decide(self, session) -> dict[str, Any] | None:
        raise NotImplementedError

class ResponderPlugin(PluginBase):
    """Executes side effects for an action. The orchestrator dispatches
    to ALL responders registered for an action name (not just the first).

    The built-in `responses.py` registry takes precedence — plugin
    responders run AFTER the built-in (if any), so plugins extend rather
    than replace. Use the `handles` attribute to declare which action
    name(s) the responder reacts to.

    Example:
        class EdgeFirewallBlock(ResponderPlugin):
            name = "edge_firewall_block"
            handles = ["alert_credential_exfil", "alert_reverse_shell"]
            def execute(self, session, action):
                requests.post("https://fw.internal/block", json={
                    "ip": session.source_ip, "reason": action["action"],
                })
    """

    handles: Sequence[str] = ()

    def execute(self, session, action: dict[str, Any]) -> None:
        raise NotImplementedError

class ConnectorPlugin(PluginBase):
    """Outbound emitter for alerts. Receives the same alert dict the
    built-in SIEM/SOAR/TI connectors do. Useful for shipping to a
    proprietary internal system."""

    def emit(self, alert: dict[str, Any]) -> None:
        raise NotImplementedError

# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

# Type alias for "factory or instance" from entry-points / directory loading.
_PluginSource = Any   # callable returning PluginBase, or PluginBase directly

class PluginRegistry:
    """Process-wide registry of loaded plugins.

    Holds four lists keyed by plugin category. Lookups in the
    orchestrator / responses / policy / connectors paths are O(1) for
    name-keyed access and O(n) for the small lists (detectors,
    connectors). `n` is typically <10, so we don't bother with smarter
    indexing.
    """

    def __init__(self) -> None:
        self.detectors:  list[DetectorPlugin] = []
        self.policies:   dict[str, PolicyPlugin] = {}
        self.responders: dict[str, list[ResponderPlugin]] = {}
        self.connectors: list[ConnectorPlugin] = []
        # Track names we've seen so a buggy plugin can't double-register
        # silently across multiple discovery passes.
        self._registered_names: set = set()

    # -- registration -------------------------------------------------------

    def register(self, plugin: PluginBase) -> str:
        """Add a plugin to the appropriate bucket; return the category.

        Raises `ValueError` if the plugin is not one of the four known
        subclasses or its `name` collides with an already-registered
        plugin of the same category.
        """
        if not isinstance(plugin, PluginBase):
            raise ValueError(f"not a PluginBase instance: {plugin!r}")

        cat = self._categorize(plugin)
        # Names are scoped per-category: a detector and a responder with
        # the same name don't collide.
        key = f"{cat}:{plugin.name}"
        if key in self._registered_names:
            raise ValueError(
                f"duplicate plugin name {plugin.name!r} in category {cat}"
            )
        self._registered_names.add(key)

        if isinstance(plugin, DetectorPlugin):
            self.detectors.append(plugin)
        elif isinstance(plugin, PolicyPlugin):
            self.policies[plugin.name] = plugin
        elif isinstance(plugin, ResponderPlugin):
            if not plugin.handles:
                raise ValueError(
                    f"responder plugin {plugin.name!r} has empty `handles`"
                )
            for action_name in plugin.handles:
                self.responders.setdefault(action_name, []).append(plugin)
        elif isinstance(plugin, ConnectorPlugin):
            self.connectors.append(plugin)
        else:   # pragma: no cover - guarded by _categorize
            raise ValueError(f"unknown plugin category for {plugin!r}")

        logger.info("plugin registered: %s (%s v%s)",
                    plugin.name, cat, plugin.version)
        return cat

    def clear(self) -> None:
        """Wipe all registrations. Mainly for tests; production code
        builds the registry once at startup."""
        self.detectors.clear()
        self.policies.clear()
        self.responders.clear()
        self.connectors.clear()
        self._registered_names.clear()

    @staticmethod
    def _categorize(plugin: PluginBase) -> str:
        if isinstance(plugin, DetectorPlugin):
            return "detector"
        if isinstance(plugin, PolicyPlugin):
            return "policy"
        if isinstance(plugin, ResponderPlugin):
            return "responder"
        if isinstance(plugin, ConnectorPlugin):
            return "connector"
        raise ValueError(f"not a recognized plugin subclass: {plugin!r}")

    # -- introspection ------------------------------------------------------

    def summary(self) -> dict[str, Any]:
        """For /metrics or operator diagnostics."""
        return {
            "detectors":  [p.name for p in self.detectors],
            "policies":   list(self.policies.keys()),
            "responders": {
                action: [p.name for p in responders]
                for action, responders in self.responders.items()
            },
            "connectors": [p.name for p in self.connectors],
            "total":      len(self._registered_names),
        }

    # -- discovery ----------------------------------------------------------

    def discover_entry_points(
        self, group: str = "plenith.plugins",
    ) -> int:
        """Load plugins published via Python entry points.

        Returns the number of plugins successfully registered. Failures
        are logged but never raised — one bad plugin in a `pip list`
        shouldn't poison startup.

        Authors register via `pyproject.toml`:

            [project.entry-points."plenith.plugins"]
            my_plugin = "my_pkg.module:plugin_factory"

        The target may be a callable (called with no args to get an
        instance) or a PluginBase instance directly.
        """
        try:
            from importlib.metadata import entry_points
        except ImportError:   # pragma: no cover - Py < 3.10
            return 0

        try:
            eps = entry_points(group=group)
        except TypeError:   # pragma: no cover - very old importlib API
            eps_all = entry_points()
            eps = eps_all.get(group, []) if isinstance(eps_all, dict) else []
        except Exception:
            logger.exception("entry-point lookup failed for group %r", group)
            return 0

        loaded = 0
        for ep in eps:
            try:
                target = ep.load()
                plugin = target() if callable(target) and not isinstance(
                    target, PluginBase) else target
                self.register(plugin)
                loaded += 1
            except Exception:
                logger.exception("entry-point plugin %r failed to load",
                                 getattr(ep, "name", "?"))
        return loaded

    def discover_path(self, plugin_dir: Path) -> int:
        """Side-load `*.py` files from `plugin_dir`.

        Each file is expected to define a module-level `PLUGIN`
        attribute that is either a PluginBase instance, a zero-arg
        factory returning one, or a list of either. Files starting with
        `_` (e.g. `__init__.py`) are skipped.

        Returns the number of plugins successfully registered.
        """
        if not plugin_dir.exists() or not plugin_dir.is_dir():
            return 0

        loaded = 0
        for py in sorted(plugin_dir.glob("*.py")):
            if py.name.startswith("_"):
                continue
            mod_name = f"_plenith_plugin_{py.stem}"
            try:
                spec = importlib.util.spec_from_file_location(mod_name, py)
                if spec is None or spec.loader is None:
                    continue
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                plugin_obj = getattr(mod, "PLUGIN", None)
                if plugin_obj is None:
                    logger.warning(
                        "plugin file %s has no module-level PLUGIN attribute", py
                    )
                    continue
                # Allow PLUGIN to be a single, a list, or a factory.
                items: Iterable[Any]
                if isinstance(plugin_obj, PluginBase):
                    items = [plugin_obj]
                elif callable(plugin_obj):
                    items = [plugin_obj()]
                elif isinstance(plugin_obj, (list, tuple)):
                    items = plugin_obj
                else:
                    logger.warning(
                        "plugin file %s exports unsupported PLUGIN type %s",
                        py, type(plugin_obj).__name__,
                    )
                    continue
                for item in items:
                    obj = item() if (callable(item) and not isinstance(
                        item, PluginBase)) else item
                    self.register(obj)
                    loaded += 1
            except Exception:
                logger.exception("plugin file %s failed to load", py)
        return loaded

# ---------------------------------------------------------------------------
# Process-global registry. Production code calls `get_registry()` to read
# or extend it. The orchestrator / policy / responses paths all consult
# this single instance.
# ---------------------------------------------------------------------------

_GLOBAL_REGISTRY: PluginRegistry | None = None

def get_registry() -> PluginRegistry:
    """Lazy-init the process-wide registry. Idempotent."""
    global _GLOBAL_REGISTRY
    if _GLOBAL_REGISTRY is None:
        _GLOBAL_REGISTRY = PluginRegistry()
    return _GLOBAL_REGISTRY

def set_registry(registry: PluginRegistry | None) -> None:
    """Replace (or clear, with None) the process-wide registry. Mainly
    a test hook — production sets up the global once at startup."""
    global _GLOBAL_REGISTRY
    _GLOBAL_REGISTRY = registry

def discover_all(
    *,
    plugin_dir: Path | None = None,
    entry_point_group: str = "plenith.plugins",
) -> dict[str, int]:
    """One-shot startup hook. Runs both discovery mechanisms against
    the global registry. Returns a dict of `{"entry_points": n, "path": n}`
    so the caller can log it."""
    reg = get_registry()
    n_ep = reg.discover_entry_points(group=entry_point_group)
    n_path = reg.discover_path(plugin_dir) if plugin_dir else 0
    return {"entry_points": n_ep, "path": n_path}

# ---------------------------------------------------------------------------
# Convenience helpers for the hot paths
# ---------------------------------------------------------------------------

def run_detectors(session, command: str) -> int:
    """Invoke every registered detector. Returns the count of detectors
    that ran successfully. Each failure is logged and isolated — one bad
    detector cannot disrupt the engagement."""
    reg = get_registry()
    ok = 0
    for d in reg.detectors:
        try:
            d.observe(session, command)
            ok += 1
        except Exception:
            logger.exception("detector plugin %r raised; ignoring", d.name)
    return ok

def run_responders(session, action: dict[str, Any]) -> int:
    """Invoke every responder registered for `action["action"]`. Returns
    the count of responders that ran successfully."""
    reg = get_registry()
    handlers = reg.responders.get(action.get("action", ""), [])
    ok = 0
    for r in handlers:
        try:
            r.execute(session, action)
            ok += 1
        except Exception:
            logger.exception("responder plugin %r raised; ignoring", r.name)
    return ok

def run_connectors(alert: dict[str, Any]) -> int:
    """Fan out an alert to every registered connector plugin. Returns
    the count that emitted successfully."""
    reg = get_registry()
    ok = 0
    for c in reg.connectors:
        try:
            c.emit(alert)
            ok += 1
        except Exception:
            logger.exception("connector plugin %r raised; ignoring", c.name)
    return ok

def policy_class_for(engine: str) -> type[PolicyPlugin] | None:
    """Return the PolicyPlugin INSTANCE for `engine`, or None.

    The policy bucket is name -> instance (not class) because plugin
    policies typically need configuration baked in. `policy.build_policy`
    treats this as "already constructed; use as-is".
    """
    reg = get_registry()
    return reg.policies.get(engine)
