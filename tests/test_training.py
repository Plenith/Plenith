"""Tests for the RL training pipeline.

Covers:
  - reward.step_reward / terminal_reward / fingerprint detection
  - attacker.AttackerSim stochastic + replay
  - policy_net.PolicyNet forward / sample / greedy / update / save+load
  - env.DeceptionEnv reset/step/terminal
  - train.train: a 5-episode smoke run with a linear policy
  - evaluate.head_to_head: trained vs heuristic on a few episodes
  - policy.TrainedRLPolicy: loads a checkpoint and produces an action dict

Everything stays numpy-only and runs in seconds.
"""
import json
import random
from pathlib import Path

import numpy as np
import pytest

from plenith.policy import ACTION_SPACE, OBSERVATION_FEATURES, TrainedRLPolicy, build_policy
from plenith.training.attacker import ARCHETYPES, AttackerSim
from plenith.training.env import DeceptionEnv
from plenith.training.evaluate import (
    HeuristicAdapter,
    TrainedAdapter,
    evaluate,
    head_to_head,
)
from plenith.training.policy_net import (
    PolicyHparams,
    PolicyNet,
    returns_to_go,
)
from plenith.training.reward import (
    RewardWeights,
    something_alert_worthy,
    step_reward,
    terminal_reward,
    _detect_fingerprint,
)
from plenith.training.train import TrainConfig, train


_ROOT = Path(__file__).resolve().parent.parent
_PERSONAS_DIR = _ROOT / "personas"
_CORPUS_DIR = _ROOT / "tests" / "fixtures" / "regression-corpus"


# ---------------------------------------------------------------------------
# reward.py
# ---------------------------------------------------------------------------

class TestReward:
    def test_step_reward_credits_new_credential_reads(self):
        prev = {"credential_files_read": {"/etc/passwd"}}
        new = {"credential_files_read": {"/etc/passwd", "~/.aws/credentials"}}
        r = step_reward(
            prev_observed=prev, new_observed=new,
            action_name="noop", action_severity="info", response_preview="",
            fired_an_alert=False, something_alert_worthy_happened=True,
        )
        # +5 for one new credential read, plus -3 for missing an alert
        assert "+credential_files_read(1)" in r.components
        assert "missed_alert" in r.components
        assert r.total == 5.0 - 3.0

    def test_step_reward_decoy_swallowed_dominates(self):
        prev = {"decoys_swallowed": set()}
        new = {"decoys_swallowed": {"/etc/sudoers.d/zzz_compat"}}
        r = step_reward(
            prev_observed=prev, new_observed=new,
            action_name="alert_decoy_swallowed", action_severity="medium",
            response_preview="banner ok", fired_an_alert=True,
            something_alert_worthy_happened=True,
        )
        assert r.total == 8.0  # +8 for the swallow, no penalties

    def test_step_reward_penalizes_spurious_alert(self):
        r = step_reward(
            prev_observed={}, new_observed={},
            action_name="alert_credential_search", action_severity="medium",
            response_preview="", fired_an_alert=True,
            something_alert_worthy_happened=False,
        )
        assert r.total == -2.0
        assert "spurious_alert" in r.components

    def test_step_reward_fingerprint_penalty(self):
        r = step_reward(
            prev_observed={}, new_observed={},
            action_name="noop", action_severity="info",
            response_preview="I'm a language model, I cannot help with that.",
            fired_an_alert=False, something_alert_worthy_happened=False,
        )
        assert r.total == -10.0
        assert "fingerprint" in r.components

    def test_terminal_reward_dwell_and_bonuses(self):
        observed = {
            "reverse_shell_attempted": True,
            "ssh_persistence_attempt": True,
            "attempted_sudo_elevation": True,
        }
        r = terminal_reward(n_commands=10, observed=observed)
        # 10 * 0.3 dwell + 6 revshell + 6 ssh persist + 10 elevation
        assert r.total == pytest.approx(10 * 0.3 + 6 + 6 + 10)

    def test_fingerprint_detector(self):
        assert _detect_fingerprint("As an AI, I can't help.") is True
        assert _detect_fingerprint("I'm a language model that ...") is True
        assert _detect_fingerprint("plain shell output") is False
        assert _detect_fingerprint("") is False

    def test_alert_worthy_detects_set_growth(self):
        assert something_alert_worthy({}, {"credential_files_read": {"x"}}) is True
        assert something_alert_worthy(
            {"credential_files_read": {"x"}},
            {"credential_files_read": {"x"}},
        ) is False
        assert something_alert_worthy({}, {"reverse_shell_attempted": True}) is True


# ---------------------------------------------------------------------------
# attacker.py
# ---------------------------------------------------------------------------

class TestAttackerSim:
    def test_stochastic_episode_emits_exit(self):
        sim = AttackerSim()  # no corpus
        rng = random.Random(0)
        ep = sim.episode(rng, archetype="balanced")
        assert ep[-1] == "exit"
        assert 1 < len(ep) <= 26

    def test_unknown_archetype_falls_back_to_balanced(self):
        sim = AttackerSim()
        rng = random.Random(1)
        ep = sim.episode(rng, archetype="nonexistent")
        assert ep  # non-empty
        assert ep[-1] == "exit"

    def test_archetype_bias_recon_heavy_emits_more_recon(self):
        # smash_and_grab should produce more exfil commands than recon_heavy
        sim = AttackerSim()
        recon_cmds = []
        exfil_cmds = []
        for seed in range(20):
            rng = random.Random(seed)
            ep_recon = sim.episode(rng, archetype="recon_heavy")
            rng = random.Random(seed)
            ep_smash = sim.episode(rng, archetype="smash_and_grab")
            recon_cmds.extend(ep_recon)
            exfil_cmds.extend(ep_smash)
        # Coarse check: smash_and_grab has more curl/wget/scp than recon_heavy
        smash_exfil_n = sum("curl" in c or "wget" in c for c in exfil_cmds)
        recon_exfil_n = sum("curl" in c or "wget" in c for c in recon_cmds)
        assert smash_exfil_n > recon_exfil_n

    def test_replay_from_corpus(self):
        if not _CORPUS_DIR.exists():
            pytest.skip("regression corpus not present")
        sim = AttackerSim(corpus_dir=_CORPUS_DIR, replay_probability=1.0)
        assert sim.has_corpus
        rng = random.Random(42)
        ep = sim.episode(rng)
        assert ep[-1] == "exit"


# ---------------------------------------------------------------------------
# policy_net.py
# ---------------------------------------------------------------------------

class TestPolicyNet:
    def test_linear_forward_shapes(self):
        hp = PolicyHparams(hidden_dim=0, seed=1)
        net = PolicyNet(hp)
        obs = np.zeros(hp.obs_dim)
        logits, probs = net.forward(obs)
        assert logits.shape == (hp.n_actions,)
        assert probs.shape == (hp.n_actions,)
        assert pytest.approx(probs.sum()) == 1.0
        assert (probs >= 0).all()

    def test_mlp_forward_shapes(self):
        hp = PolicyHparams(hidden_dim=8, seed=2)
        net = PolicyNet(hp)
        obs = np.zeros(hp.obs_dim)
        logits, probs = net.forward(obs)
        assert logits.shape == (hp.n_actions,)
        assert pytest.approx(probs.sum()) == 1.0

    def test_sample_returns_valid_id(self):
        hp = PolicyHparams(seed=3)
        net = PolicyNet(hp)
        rng = np.random.default_rng(0)
        obs = np.zeros(hp.obs_dim)
        a, logp = net.sample(obs, rng)
        assert 0 <= a < hp.n_actions
        assert logp <= 0

    def test_greedy_picks_argmax(self):
        hp = PolicyHparams(seed=4)
        net = PolicyNet(hp)
        # Force W1 so a specific action dominates
        net.W1 = np.zeros_like(net.W1)
        net.b1 = np.zeros_like(net.b1)
        net.b1[3] = 10.0  # action_id=3 wins
        obs = np.zeros(hp.obs_dim)
        assert net.greedy(obs) == 3

    def test_update_runs_and_moves_weights(self):
        hp = PolicyHparams(seed=5, learning_rate=0.1)
        net = PolicyNet(hp)
        before = net.W1.copy()
        obs = np.ones(hp.obs_dim)
        traj = [(obs, 2, 1.0)] * 4
        telem = net.update(traj)
        assert telem["n_steps"] == 4
        assert not np.allclose(before, net.W1)

    def test_update_empty_traj(self):
        net = PolicyNet(PolicyHparams())
        telem = net.update([])
        assert telem == {"loss": 0.0, "entropy": 0.0, "n_steps": 0}

    def test_save_load_roundtrip(self, tmp_path):
        hp = PolicyHparams(seed=6, hidden_dim=4)
        net = PolicyNet(hp)
        # mutate a weight so we can check it survives
        net.W1[0, 0] = 1.234
        net.W2[0, 0] = -5.678
        p = tmp_path / "policy.npz"
        net.save(p)
        net2 = PolicyNet.load(p)
        assert net2.W1[0, 0] == pytest.approx(1.234)
        assert net2.W2[0, 0] == pytest.approx(-5.678)
        assert net2.hp.hidden_dim == 4

    def test_returns_to_go_discount(self):
        out = returns_to_go([1.0, 1.0, 1.0], gamma=0.9)
        # G[2]=1, G[1]=1+0.9*1=1.9, G[0]=1+0.9*1.9=2.71
        assert out == pytest.approx([2.71, 1.9, 1.0])


# ---------------------------------------------------------------------------
# env.py
# ---------------------------------------------------------------------------

@pytest.fixture
def small_env():
    sim = AttackerSim(episode_length_range=(3, 4))
    return DeceptionEnv(
        personas_dir=_PERSONAS_DIR,
        attacker_sim=sim,
        archetype="balanced",
        episode_cap=12,
    )


class TestDeceptionEnv:
    def test_reset_returns_zero_obs(self, small_env):
        obs = small_env.reset(seed=11)
        assert isinstance(obs, list)
        assert len(obs) == len(OBSERVATION_FEATURES)
        assert all(v == 0 for v in obs[:12])  # boolean prefix all False

    def test_step_advances_and_terminates(self, small_env):
        small_env.reset(seed=12)
        rewards = []
        for _ in range(20):
            res = small_env.step(0)  # always noop
            rewards.append(res.reward)
            if res.done:
                break
        assert res.done
        assert len(rewards) <= 20

    def test_step_records_chosen_action(self, small_env):
        small_env.reset(seed=13)
        res = small_env.step(5)  # alert_credential_search
        # The env must have appended exactly one action this step
        # (the noop policy was swapped in so no double-recording)
        assert any(a["action"] == "alert_credential_search"
                   for a in small_env._session.actions_taken)
        assert "reward_components" in res.info


# ---------------------------------------------------------------------------
# train.py
# ---------------------------------------------------------------------------

class TestTrainLoop:
    def test_5_episode_smoke(self, tmp_path):
        sim = AttackerSim(episode_length_range=(3, 5))
        env = DeceptionEnv(
            personas_dir=_PERSONAS_DIR,
            attacker_sim=sim,
            episode_cap=8,
        )
        policy = PolicyNet(PolicyHparams(seed=21, hidden_dim=0, learning_rate=0.05))
        cfg = TrainConfig(
            n_episodes=5,
            seed=21,
            checkpoint_every=5,
            log_every=1,
            checkpoint_dir=tmp_path / "ckpt",
        )
        stats = train(policy, env, cfg)
        assert len(stats) == 5
        # checkpoint files exist
        assert (tmp_path / "ckpt" / "policy_last.npz").exists()
        assert (tmp_path / "ckpt" / "policy_best.npz").exists()
        # JSONL log has 5 lines
        log = (tmp_path / "ckpt" / "train_log.jsonl").read_text(encoding="utf-8")
        assert len([l for l in log.splitlines() if l.strip()]) == 5


# ---------------------------------------------------------------------------
# evaluate.py
# ---------------------------------------------------------------------------

class TestEvaluation:
    def test_head_to_head_runs(self, tmp_path):
        # Use untrained policy — we just check both adapters run cleanly.
        policy = PolicyNet(PolicyHparams(seed=33))
        res = head_to_head(
            personas_dir=_PERSONAS_DIR,
            trained_policy=policy,
            n_episodes=4,
            seed=99,
            episode_cap=8,
        )
        assert set(res.keys()) == {"trained_rl", "heuristic"}
        for k, r in res.items():
            assert r.n_episodes == 4
            assert r.mean_steps > 0

    def test_heuristic_eval_records_actions(self):
        sim = AttackerSim(episode_length_range=(4, 6))
        env = DeceptionEnv(personas_dir=_PERSONAS_DIR, attacker_sim=sim, episode_cap=8)
        r = evaluate(HeuristicAdapter(), env=env, n_episodes=3, seed=77)
        # We expect at least some actions (probably alerts) to fire
        assert r.n_episodes == 3
        # Total actions is a dict; should contain noop at minimum
        assert "noop" in r.total_actions or any(
            k.startswith("alert_") or k.startswith("plant_") for k in r.total_actions
        )


# ---------------------------------------------------------------------------
# policy.TrainedRLPolicy
# ---------------------------------------------------------------------------

class TestTrainedRLPolicy:
    def _make_checkpoint(self, tmp_path, biased_action_id: int) -> Path:
        """Save an untrained PolicyNet with a bias that forces a specific
        action to win argmax. Used for deterministic decision testing."""
        hp = PolicyHparams(seed=0, hidden_dim=0)
        net = PolicyNet(hp)
        net.W1 = np.zeros_like(net.W1)
        net.b1 = np.zeros_like(net.b1)
        net.b1[biased_action_id] = 100.0
        path = tmp_path / "policy_biased.npz"
        net.save(path)
        return path

    def test_decide_returns_biased_action(self, tmp_path, session):
        path = self._make_checkpoint(tmp_path, biased_action_id=5)  # alert_credential_search
        p = TrainedRLPolicy(model_path=str(path))
        d = p.decide(session)
        assert d["action"] == "alert_credential_search"
        assert d["severity"] in ("info", "low", "medium", "high", "critical")
        assert "RL policy" in d["rationale"]

    def test_decide_returns_none_on_noop_bias(self, tmp_path, session):
        path = self._make_checkpoint(tmp_path, biased_action_id=0)
        p = TrainedRLPolicy(model_path=str(path))
        assert p.decide(session) is None

    def test_masks_already_fired_actions(self, tmp_path, session):
        path = self._make_checkpoint(tmp_path, biased_action_id=5)
        p = TrainedRLPolicy(model_path=str(path))
        session.actions_taken.append({"action": "alert_credential_search"})
        # With argmax masked, only noop is left → returns None
        assert p.decide(session) is None

    def test_build_policy_returns_trained_when_path_given(self, tmp_path):
        path = self._make_checkpoint(tmp_path, biased_action_id=1)
        eng = build_policy({"engine": "trained_rl", "model_path": str(path)})
        assert isinstance(eng, TrainedRLPolicy)

    def test_build_policy_falls_back_when_no_path(self):
        # Missing model_path → returns HeuristicPolicy
        eng = build_policy({"engine": "trained_rl"})
        # Should be a HeuristicPolicy instance (not TrainedRLPolicy)
        assert eng.__class__.__name__ == "HeuristicPolicy"
