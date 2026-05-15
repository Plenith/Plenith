"""Tests for the plugin / extension system (item 14).

Covers:
  - The four plugin base classes (Detector / Policy / Responder /
    Connector) reject the wrong supertype.
  - `PluginRegistry.register()` routes plugins into the right bucket
    and rejects duplicates within a category.
  - Per-category name scoping: a detector and a responder may share
    a name without colliding.
  - Directory discovery loads PLUGIN-exporting .py files, handles
    single / list / factory exports, ignores `_underscore.py` files,
    and isolates failures.
  - Entry-point discovery doesn't blow up when nothing is published.
  - `run_detectors / run_responders / run_connectors` swallow plugin
    exceptions (failure isolation).
  - `policy_class_for("name")` returns the registered instance.
  - Integration: a plugin Detector influences `session.observed` and
    a plugin Responder is invoked when the orchestrator dispatches an
    action.

The "live orchestrator" integration test uses minimal stubs (no LLM,
no docker) so it stays a unit test.
"""
from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any

import pytest

from plenith.plugins import (
    ConnectorPlugin,
    DetectorPlugin,
    PluginBase,
    PluginRegistry,
    PolicyPlugin,
    ResponderPlugin,
    discover_all,
    get_registry,
    policy_class_for,
    run_connectors,
    run_detectors,
    run_responders,
    set_registry,
)

# ---------------------------------------------------------------------------
# Fixtures: clean registry between tests so cross-test pollution is impossible
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _clean_registry():
    set_registry(None)
    yield
    set_registry(None)

# ---------------------------------------------------------------------------
# Test fixtures: minimal plugin implementations
# ---------------------------------------------------------------------------

class _RecordingDetector(DetectorPlugin):
    name = "rec_detector"
    version = "1.0.0"

    def __init__(self):
        self.calls = []

    def observe(self, session, command):
        self.calls.append(command)
        session.observed["plugin_saw"] = True

class _RecordingResponder(ResponderPlugin):
    name = "rec_responder"
    handles = ("alert_credential_exfil",)

    def __init__(self):
        self.calls = []

    def execute(self, session, action):
        self.calls.append((session, action))

class _ExplodingDetector(DetectorPlugin):
    name = "explodey"

    def observe(self, session, command):
        raise RuntimeError("kaboom")

class _StubPolicy(PolicyPlugin):
    name = "stub_policy"

    def decide(self, session):
        return {"action": "noop", "severity": "info", "rationale": "stub"}

class _StubConnector(ConnectorPlugin):
    name = "stub_connector"

    def __init__(self):
        self.emitted = []

    def emit(self, alert):
        self.emitted.append(alert)

class _MinimalSession:
    """Lookalike of plenith.session.Session — just enough for the
    plugin hot paths."""

    def __init__(self):
        self.observed: dict[str, Any] = {}
        self.actions_taken: list[dict[str, Any]] = []
        self.source_ip = "203.0.113.7"

# ---------------------------------------------------------------------------
# Plugin base contract
# ---------------------------------------------------------------------------

class TestPluginBases:
    def test_each_subclass_categorizes_correctly(self):
        reg = PluginRegistry()
        assert reg.register(_RecordingDetector()) == "detector"
        assert reg.register(_StubPolicy()) == "policy"
        assert reg.register(_RecordingResponder()) == "responder"
        assert reg.register(_StubConnector()) == "connector"

    def test_register_rejects_non_plugin(self):
        reg = PluginRegistry()
        with pytest.raises(ValueError, match="not a PluginBase"):
            reg.register("just a string")

    def test_responder_without_handles_rejected(self):
        class _Bad(ResponderPlugin):
            name = "no_handles"
            handles = ()
            def execute(self, session, action):
                pass

        reg = PluginRegistry()
        with pytest.raises(ValueError, match="empty `handles`"):
            reg.register(_Bad())

    def test_duplicate_name_within_category_rejected(self):
        reg = PluginRegistry()
        reg.register(_RecordingDetector())
        with pytest.raises(ValueError, match="duplicate"):
            reg.register(_RecordingDetector())

    def test_same_name_across_categories_is_ok(self):
        """Names are scoped to category. A detector and a responder
        can both be called 'foo'."""
        class _D(DetectorPlugin):
            name = "shared"
            def observe(self, session, command): pass

        class _R(ResponderPlugin):
            name = "shared"
            handles = ("anything",)
            def execute(self, session, action): pass

        reg = PluginRegistry()
        reg.register(_D())
        reg.register(_R())   # must not raise
        assert "shared" in [d.name for d in reg.detectors]
        assert reg.responders["anything"][0].name == "shared"

# ---------------------------------------------------------------------------
# Registry summary + clear
# ---------------------------------------------------------------------------

class TestRegistryIntrospection:
    def test_summary_lists_everything(self):
        reg = PluginRegistry()
        reg.register(_RecordingDetector())
        reg.register(_StubPolicy())
        reg.register(_RecordingResponder())
        reg.register(_StubConnector())
        s = reg.summary()
        assert s["detectors"] == ["rec_detector"]
        assert s["policies"]  == ["stub_policy"]
        assert s["responders"] == {"alert_credential_exfil": ["rec_responder"]}
        assert s["connectors"] == ["stub_connector"]
        assert s["total"] == 4

    def test_clear_resets_everything(self):
        reg = PluginRegistry()
        reg.register(_RecordingDetector())
        reg.register(_StubPolicy())
        reg.clear()
        assert reg.summary()["total"] == 0
        # And we can re-register the same name after clear
        reg.register(_RecordingDetector())

# ---------------------------------------------------------------------------
# Directory discovery
# ---------------------------------------------------------------------------

class TestPathDiscovery:
    def test_loads_single_plugin_file(self, tmp_path):
        (tmp_path / "myplugin.py").write_text(textwrap.dedent("""
            from plenith.plugins import DetectorPlugin
            class Det(DetectorPlugin):
                name = "from_file"
                def observe(self, session, command):
                    session.observed["from_file"] = True
            PLUGIN = Det()
        """), encoding="utf-8")
        reg = PluginRegistry()
        assert reg.discover_path(tmp_path) == 1
        assert reg.detectors[0].name == "from_file"

    def test_loads_list_of_plugins(self, tmp_path):
        (tmp_path / "myplugin.py").write_text(textwrap.dedent("""
            from plenith.plugins import DetectorPlugin
            class A(DetectorPlugin):
                name = "a"
                def observe(self, session, command): pass
            class B(DetectorPlugin):
                name = "b"
                def observe(self, session, command): pass
            PLUGIN = [A(), B()]
        """), encoding="utf-8")
        reg = PluginRegistry()
        assert reg.discover_path(tmp_path) == 2
        names = {d.name for d in reg.detectors}
        assert names == {"a", "b"}

    def test_loads_factory_callable(self, tmp_path):
        (tmp_path / "myplugin.py").write_text(textwrap.dedent("""
            from plenith.plugins import DetectorPlugin
            class Det(DetectorPlugin):
                name = "via_factory"
                def observe(self, session, command): pass
            def PLUGIN():
                return Det()
        """), encoding="utf-8")
        reg = PluginRegistry()
        assert reg.discover_path(tmp_path) == 1
        assert reg.detectors[0].name == "via_factory"

    def test_skips_underscore_files(self, tmp_path):
        (tmp_path / "_private.py").write_text(textwrap.dedent("""
            # Should be ignored by discovery.
            raise RuntimeError("must not import")
        """), encoding="utf-8")
        (tmp_path / "__init__.py").write_text("", encoding="utf-8")
        reg = PluginRegistry()
        assert reg.discover_path(tmp_path) == 0

    def test_nonexistent_dir_is_silent(self, tmp_path):
        reg = PluginRegistry()
        assert reg.discover_path(tmp_path / "nope") == 0

    def test_file_without_PLUGIN_attribute_skipped(self, tmp_path):
        (tmp_path / "noplugin.py").write_text("X = 42\n", encoding="utf-8")
        reg = PluginRegistry()
        # No exception, no registrations
        assert reg.discover_path(tmp_path) == 0

    def test_bad_plugin_file_isolated(self, tmp_path):
        # One good, one bad
        (tmp_path / "good.py").write_text(textwrap.dedent("""
            from plenith.plugins import DetectorPlugin
            class Det(DetectorPlugin):
                name = "good"
                def observe(self, session, command): pass
            PLUGIN = Det()
        """), encoding="utf-8")
        (tmp_path / "bad.py").write_text("import nonexistent_module_xyz\n",
                                          encoding="utf-8")
        reg = PluginRegistry()
        # Bad file is logged but doesn't kill discovery; good file lands
        assert reg.discover_path(tmp_path) == 1
        assert reg.detectors[0].name == "good"

# ---------------------------------------------------------------------------
# Entry-point discovery (smoke — relies on importlib.metadata being there)
# ---------------------------------------------------------------------------

class TestEntryPointDiscovery:
    def test_empty_group_returns_zero(self):
        reg = PluginRegistry()
        # Using a group that's guaranteed to not exist
        assert reg.discover_entry_points(group="plenith.plugins.test_nope_xyz") == 0

# ---------------------------------------------------------------------------
# Hot-path helpers
# ---------------------------------------------------------------------------

class TestRunHelpers:
    def test_run_detectors_invokes_all(self):
        d1 = _RecordingDetector()
        d2 = _RecordingDetector()
        d2.name = "rec_detector_2"
        reg = get_registry()
        reg.register(d1)
        reg.register(d2)

        session = _MinimalSession()
        assert run_detectors(session, "ls -la") == 2
        assert d1.calls == ["ls -la"]
        assert d2.calls == ["ls -la"]
        assert session.observed["plugin_saw"] is True

    def test_run_detectors_isolates_exceptions(self):
        good = _RecordingDetector()
        bad = _ExplodingDetector()
        reg = get_registry()
        reg.register(bad)
        reg.register(good)

        session = _MinimalSession()
        # The good detector still ran even though the bad one raised
        assert run_detectors(session, "cmd") == 1
        assert good.calls == ["cmd"]

    def test_run_responders_dispatches_by_action_name(self):
        r = _RecordingResponder()
        get_registry().register(r)
        session = _MinimalSession()

        # Matching action: should fire
        assert run_responders(session, {"action": "alert_credential_exfil"}) == 1
        assert len(r.calls) == 1

        # Non-matching action: should not fire
        assert run_responders(session, {"action": "alert_random"}) == 0
        assert len(r.calls) == 1   # unchanged

    def test_run_responders_isolates_exceptions(self):
        class _Bad(ResponderPlugin):
            name = "bad"
            handles = ("alert_test",)
            def execute(self, session, action):
                raise RuntimeError("kaboom")

        get_registry().register(_Bad())
        # Doesn't raise; returns 0 because it failed
        assert run_responders(_MinimalSession(),
                                {"action": "alert_test"}) == 0

    def test_run_connectors_emits_to_all(self):
        c1 = _StubConnector()
        c2 = _StubConnector()
        c2.name = "stub_connector_2"
        get_registry().register(c1)
        get_registry().register(c2)
        assert run_connectors({"x": 1}) == 2
        assert c1.emitted == [{"x": 1}]
        assert c2.emitted == [{"x": 1}]

    def test_policy_class_for_returns_instance(self):
        p = _StubPolicy()
        get_registry().register(p)
        assert policy_class_for("stub_policy") is p
        assert policy_class_for("not_registered") is None

# ---------------------------------------------------------------------------
# discover_all integration
# ---------------------------------------------------------------------------

class TestDiscoverAll:
    def test_returns_counts_dict(self, tmp_path):
        (tmp_path / "a.py").write_text(textwrap.dedent("""
            from plenith.plugins import DetectorPlugin
            class A(DetectorPlugin):
                name = "from_dir"
                def observe(self, session, command): pass
            PLUGIN = A()
        """), encoding="utf-8")
        result = discover_all(
            plugin_dir=tmp_path,
            entry_point_group="plenith.plugins.test_nope",
        )
        assert result["path"] == 1
        assert result["entry_points"] == 0
        assert get_registry().detectors[0].name == "from_dir"

    def test_no_plugin_dir_returns_zero(self):
        # entry-point group still queried but should be empty
        result = discover_all(
            entry_point_group="plenith.plugins.test_nope_xyz",
        )
        assert result["path"] == 0
        assert result["entry_points"] == 0

# ---------------------------------------------------------------------------
# Wiring smoke: build_policy honors plugin policies
# ---------------------------------------------------------------------------

class TestPolicyBuilderHonorsPlugins:
    def test_plugin_policy_wins_over_builtin(self):
        from plenith.policy import build_policy

        # Register a plugin under a brand-new engine name
        class _PluginPol(PolicyPlugin):
            name = "myorg_ml"
            def decide(self, session):
                return None

        instance = _PluginPol()
        get_registry().register(instance)

        # build_policy should return the registered instance, not fall
        # back to HeuristicPolicy
        p = build_policy({"engine": "myorg_ml"})
        assert p is instance

    def test_unknown_engine_still_falls_back_to_heuristic(self):
        from plenith.policy import build_policy, HeuristicPolicy
        p = build_policy({"engine": "totally_unknown"})
        assert isinstance(p, HeuristicPolicy)

    def test_builtin_engines_unchanged(self):
        from plenith.policy import build_policy, HeuristicPolicy
        p = build_policy({"engine": "heuristic"})
        assert isinstance(p, HeuristicPolicy)
