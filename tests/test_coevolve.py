"""Tests for the co-evolutionary RL pipeline.

Covers:
  - AttackerState: vectorize / record_action / shape invariants
  - AdversaryNet: forward/sample/greedy/update + save/load round-trip
  - attacker_reward: every shaping term fires correctly
  - terminal bonus + clean-exit logic
  - sample_command: every action class produces a non-empty command
  - Elo helpers
  - coevolve(): runs end-to-end without raising, produces non-empty stats,
    and the checkpoint files exist.
"""
from pathlib import Path

import numpy as np
import pytest

from plenith.training.adversary import (
    ATTACKER_ACTIONS,
    AdversaryHparams,
    AdversaryNet,
    AttackerRewardWeights,
    AttackerState,
    attacker_reward,
    sample_command,
    terminal_attacker_reward,
)
from plenith.training.coevolve import (
    CoevolveConfig,
    IterationStat,
    _expected_score,
    _restore_policy,
    _snapshot_policy,
    _update_elo,
    coevolve,
)
import random

from plenith.training.attacker import AttackerSim
from plenith.training.env import DeceptionEnv
from plenith.training.policy_net import PolicyHparams, PolicyNet

_ROOT = Path(__file__).resolve().parent.parent
_PERSONAS_DIR = _ROOT / "personas"

# ---------------------------------------------------------------------------
# AttackerState
# ---------------------------------------------------------------------------

class TestAttackerState:
    def test_initial_vector_is_zero(self):
        s = AttackerState()
        v = s.vectorize()
        assert v.shape == (23,)
        assert v.sum() == 0.0

    def test_progress_field(self):
        s = AttackerState(max_steps=10)
        s.step_count = 4
        v = s.vectorize()
        assert v[0] == 0.4

    def test_used_mask_and_last_action(self):
        s = AttackerState()
        s.record_action(3, "cat /etc/passwd")
        s.record_action(5, "ssh db-prod-01")
        v = s.vectorize()
        # used_mask[3]=1, used_mask[5]=1
        assert v[1 + 3] == 1.0
        assert v[1 + 5] == 1.0
        # last_action one-hot at 11+5
        assert v[11 + 5] == 1.0
        # Old one-hot at 11+3 should NOT be set anymore
        assert v[11 + 3] == 0.0

    def test_credential_reads_clamped(self):
        s = AttackerState()
        s.credential_reads = 100
        v = s.vectorize()
        assert v[21] == 1.0   # clamped to /5

    def test_isolated_flag(self):
        s = AttackerState()
        s.isolated = True
        assert s.vectorize()[22] == 1.0

# ---------------------------------------------------------------------------
# Action-class → command
# ---------------------------------------------------------------------------

class TestActionToCommand:
    def test_every_action_class_yields_a_command(self):
        rng = random.Random(0)
        for idx in range(len(ATTACKER_ACTIONS)):
            cmd = sample_command(idx, rng)
            assert isinstance(cmd, str)
            assert len(cmd) > 0

    def test_leave_action_is_exit(self):
        # "leave" is action 9; should always sample to "exit"
        rng = random.Random(0)
        assert sample_command(9, rng) == "exit"

# ---------------------------------------------------------------------------
# AdversaryNet
# ---------------------------------------------------------------------------

class TestAdversaryNet:
    def test_forward_shape(self):
        net = AdversaryNet(AdversaryHparams(hidden_dim=0, seed=1))
        obs = np.zeros(23)
        logits, probs = net.forward(obs)
        assert logits.shape == (10,)
        assert probs.shape == (10,)
        assert pytest.approx(probs.sum()) == 1.0

    def test_mlp_forward_shape(self):
        net = AdversaryNet(AdversaryHparams(hidden_dim=8, seed=2))
        obs = np.zeros(23)
        logits, probs = net.forward(obs)
        assert logits.shape == (10,)

    def test_sample_returns_valid_action(self):
        net = AdversaryNet(AdversaryHparams(seed=3))
        rng = np.random.default_rng(0)
        a, logp = net.sample(np.zeros(23), rng)
        assert 0 <= a < 10
        assert logp <= 0

    def test_update_runs(self):
        net = AdversaryNet(AdversaryHparams(seed=4, learning_rate=0.1))
        obs = np.ones(23)
        traj = [(obs, 2, 1.0), (obs, 5, -0.5)]
        telem = net.update(traj)
        assert telem["n_steps"] == 2

    def test_save_load_roundtrip(self, tmp_path):
        a = AdversaryNet(AdversaryHparams(seed=5, hidden_dim=4))
        # Mutate so we can verify
        a._net.W1[0, 0] = 9.87
        p = tmp_path / "adv.npz"
        a.save(p)
        b = AdversaryNet.load(p)
        assert b._net.W1[0, 0] == pytest.approx(9.87)
        assert b.hp.hidden_dim == 4

# ---------------------------------------------------------------------------
# Attacker reward
# ---------------------------------------------------------------------------

class TestAttackerReward:
    def _state(self):
        return AttackerState(max_steps=20)

    def test_credential_read_rewards(self):
        prev = {"credential_files_read": set()}
        new  = {"credential_files_read": {"/home/jdoe/.aws/credentials"}}
        s = self._state()
        r = attacker_reward(
            prev_observed=prev, new_observed=new,
            new_alerts=[], attacker_state=s,
            action_idx=2,
        )
        # +dwell + 1 credential
        assert r >= 5.0
        # State updated
        assert s.credential_reads == 1

    def test_alert_fires_penalize(self):
        s = self._state()
        r = attacker_reward(
            prev_observed={}, new_observed={},
            new_alerts=[{"action": "alert_credential_search"}],
            attacker_state=s, action_idx=2,
        )
        # +dwell - 1.5
        assert r < 0

    def test_isolate_session_huge_penalty(self):
        s = self._state()
        r = attacker_reward(
            prev_observed={}, new_observed={},
            new_alerts=[{"action": "isolate_session"}],
            attacker_state=s, action_idx=5,
        )
        # -10 isolated + -1.5 alert + dwell
        assert r < -10
        assert s.isolated is True

    def test_counter_ai_proven_heaviest_penalty(self):
        s = self._state()
        prev = {"attacker_llm_proven_via_trap": False}
        new  = {"attacker_llm_proven_via_trap": True}
        r = attacker_reward(
            prev_observed=prev, new_observed=new,
            new_alerts=[], attacker_state=s, action_idx=4,
        )
        # -15 (proven via trap) + dwell
        assert r < -14

    def test_repeated_action_penalty(self):
        s = self._state()
        s.last_action = 2
        r = attacker_reward(
            prev_observed={}, new_observed={},
            new_alerts=[], attacker_state=s, action_idx=2,
        )
        # +dwell (0.20) - repeat (0.5)
        assert r < 0

    def test_leave_does_not_trigger_repeat_penalty(self):
        s = self._state()
        s.last_action = 9
        r = attacker_reward(
            prev_observed={}, new_observed={},
            new_alerts=[], attacker_state=s, action_idx=9,
        )
        # Exit is allowed to repeat (sticky)
        assert r > 0

class TestTerminalReward:
    def test_clean_exit_bonus(self):
        s = AttackerState(max_steps=20)
        s.credential_reads = 4
        s.isolated = False
        r = terminal_attacker_reward(
            final_state=s, final_observed={}, isolated=False,
        )
        assert r >= 8.0   # clean exit bonus

    def test_leave_too_early_penalty(self):
        s = AttackerState(max_steps=20)
        s.credential_reads = 0
        s.step_count = 2
        r = terminal_attacker_reward(
            final_state=s, final_observed={}, isolated=False,
        )
        assert r <= -2.0

# ---------------------------------------------------------------------------
# Elo helpers
# ---------------------------------------------------------------------------

class TestElo:
    def test_equal_ratings_expected_50pct(self):
        assert _expected_score(1500, 1500) == pytest.approx(0.5)

    def test_higher_rating_higher_expectation(self):
        assert _expected_score(1600, 1500) > 0.5
        assert _expected_score(1500, 1600) < 0.5

    def test_update_winner_gains(self):
        # If A (1500) wins outright against B (1500), A should gain.
        a, b = _update_elo(1500, 1500, score_a=1.0, k=24)
        assert a > 1500
        assert b < 1500
        # Symmetry — gain = loss
        assert pytest.approx(a + b) == 3000.0

# ---------------------------------------------------------------------------
# Snapshot / restore
# ---------------------------------------------------------------------------

class TestSnapshotRestore:
    def test_snapshot_captures_weights(self):
        net = PolicyNet(PolicyHparams(seed=7))
        original = net.W1.copy()
        snap = _snapshot_policy(net)
        net.W1 += 1.0   # mutate
        assert not np.allclose(net.W1, original)
        _restore_policy(net, snap)
        assert np.allclose(net.W1, original)

    def test_snapshot_works_for_adversary_net(self):
        adv = AdversaryNet(AdversaryHparams(seed=8))
        original = adv._net.W1.copy()
        snap = _snapshot_policy(adv)
        adv._net.W1 += 0.5
        _restore_policy(adv, snap)
        assert np.allclose(adv._net.W1, original)

# ---------------------------------------------------------------------------
# Coevolve smoke test (3 iterations, small episodes — should finish in ~30s)
# ---------------------------------------------------------------------------

class TestCoevolveLoop:
    def test_small_run_produces_stats(self, tmp_path):
        """End-to-end: 2 iterations × 4 episodes per side × 4 eval episodes.
        Asserts the loop runs and emits stats + checkpoints."""
        sim = AttackerSim(episode_length_range=(4, 8))
        env = DeceptionEnv(
            personas_dir=_PERSONAS_DIR,
            attacker_sim=sim,
            episode_cap=8,
        )
        defender = PolicyNet(PolicyHparams(seed=42, hidden_dim=0, learning_rate=0.05))
        attacker = AdversaryNet(AdversaryHparams(seed=43, hidden_dim=0, learning_rate=0.05))

        cfg = CoevolveConfig(
            iterations=2,
            episodes_per_side=4,
            eval_episodes=4,
            episode_cap=8,
            seed=42,
            checkpoint_dir=tmp_path / "ckpt",
        )
        stats = coevolve(env=env, defender=defender, attacker=attacker, cfg=cfg)

        assert len(stats) == 2
        for s in stats:
            assert isinstance(s, IterationStat)
            assert 0.0 <= s.attacker_undetected_rate <= 1.0
            assert 0.0 <= s.head_to_head_def_winrate <= 1.0
            # Elos start at 1500 and move
            assert abs(s.defender_elo - 1500) < 200
        # Checkpoints written
        assert (tmp_path / "ckpt" / "defender_last.npz").exists()
        assert (tmp_path / "ckpt" / "attacker_last.npz").exists()
        # JSONL log has at least 2 lines (one per iter)
        log = (tmp_path / "ckpt" / "coevolve_log.jsonl").read_text(encoding="utf-8")
        assert len([l for l in log.splitlines() if l.strip()]) == 2
