"""Numpy-only linear/MLP policy network for REINFORCE training.

Action space is small (15 discrete actions), observation space is small
(21 features). A linear layer → softmax is the smallest thing that can
learn a policy here. We make the hidden layer optional so this can scale
to a 2-layer MLP if a linear policy underfits.

No torch / jax / tensorflow. Pure numpy. Trains on CPU in seconds.
"""
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from ..policy import ACTION_SPACE, OBSERVATION_FEATURES

@dataclass
class PolicyHparams:
    obs_dim: int = len(OBSERVATION_FEATURES)
    n_actions: int = len(ACTION_SPACE)
    hidden_dim: int = 0      # 0 = linear policy; >0 = 1-hidden-layer MLP
    learning_rate: float = 0.02
    entropy_beta: float = 0.01   # entropy regularization to encourage exploration
    seed: int = 42

class PolicyNet:
    """One-hidden-layer MLP if hidden_dim>0, else a linear softmax.

    Architecture (hidden_dim > 0):
        obs (D) -> Linear(D, H) -> tanh -> Linear(H, A) -> softmax

    Architecture (hidden_dim == 0):
        obs (D) -> Linear(D, A) -> softmax
    """

    def __init__(self, hp: PolicyHparams | None = None):
        self.hp = hp or PolicyHparams()
        rng = np.random.default_rng(self.hp.seed)
        D, H, A = self.hp.obs_dim, self.hp.hidden_dim, self.hp.n_actions
        if H > 0:
            # Xavier-ish init
            self.W1 = rng.normal(0, np.sqrt(2.0 / D), size=(D, H))
            self.b1 = np.zeros(H)
            self.W2 = rng.normal(0, np.sqrt(2.0 / H), size=(H, A))
            self.b2 = np.zeros(A)
        else:
            self.W1 = rng.normal(0, np.sqrt(2.0 / D), size=(D, A))
            self.b1 = np.zeros(A)
            self.W2 = None
            self.b2 = None

    # --- inference ------------------------------------------------------

    def forward(self, obs: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """Return (logits, probs)."""
        obs = np.asarray(obs, dtype=np.float64).reshape(-1)
        if self.W2 is None:
            logits = obs @ self.W1 + self.b1
            h = None
        else:
            h = np.tanh(obs @ self.W1 + self.b1)
            logits = h @ self.W2 + self.b2
        probs = _softmax(logits)
        return logits, probs

    def sample(self, obs: np.ndarray, rng: np.random.Generator) -> tuple[int, float]:
        """Sample an action from the policy. Returns (action_id, log_prob)."""
        _logits, probs = self.forward(obs)
        a = int(rng.choice(self.hp.n_actions, p=probs))
        return a, float(np.log(probs[a] + 1e-12))

    def greedy(self, obs: np.ndarray) -> int:
        _, probs = self.forward(obs)
        return int(np.argmax(probs))

    # --- training -------------------------------------------------------

    def update(self, traj: list[tuple[np.ndarray, int, float]]) -> dict:
        """REINFORCE with returns-to-go. `traj` is a list of (obs, action, advantage).

        For a linear policy:
            grad_W1[:, a] += (1 - p[a]) * obs * adv ;  for a' != a: -p[a']*obs*adv
            grad_b1[a] += (1 - p[a]) * adv ;          for a' != a: -p[a']*adv

        For an MLP we backprop through the tanh.

        Returns telemetry dict (loss, entropy, etc.).
        """
        if not traj:
            return {"loss": 0.0, "entropy": 0.0, "n_steps": 0}

        D = self.hp.obs_dim
        A = self.hp.n_actions
        H = self.hp.hidden_dim

        gW1 = np.zeros_like(self.W1)
        gb1 = np.zeros_like(self.b1)
        gW2 = np.zeros_like(self.W2) if self.W2 is not None else None
        gb2 = np.zeros_like(self.b2) if self.b2 is not None else None

        total_loss = 0.0
        total_entropy = 0.0

        for obs, action, advantage in traj:
            obs = np.asarray(obs, dtype=np.float64).reshape(-1)
            if self.W2 is None:
                logits = obs @ self.W1 + self.b1
                h = None
            else:
                pre_h = obs @ self.W1 + self.b1
                h = np.tanh(pre_h)
                logits = h @ self.W2 + self.b2
            probs = _softmax(logits)
            entropy = -float(np.sum(probs * np.log(probs + 1e-12)))
            total_entropy += entropy

            # dL/dlogits for REINFORCE = -(one_hot(a) - probs) * advantage
            # plus entropy bonus gradient: + beta * d(entropy)/dlogits
            grad_logits = -(np.eye(A)[action] - probs) * advantage
            # entropy gradient: d/dlogit_i of -sum p_j log p_j = -p_i*(log p_i - sum p_k log p_k)
            # = p_i * (H + log p_i) where H is entropy
            ent_grad = self.hp.entropy_beta * probs * (entropy + np.log(probs + 1e-12))
            grad_logits = grad_logits - ent_grad

            if self.W2 is None:
                gW1 += np.outer(obs, grad_logits)
                gb1 += grad_logits
            else:
                gW2 += np.outer(h, grad_logits)
                gb2 += grad_logits
                grad_h = grad_logits @ self.W2.T
                grad_pre_h = grad_h * (1 - h ** 2)  # tanh'
                gW1 += np.outer(obs, grad_pre_h)
                gb1 += grad_pre_h

            total_loss += float(-np.log(probs[action] + 1e-12) * advantage)

        n = len(traj)
        lr = self.hp.learning_rate
        # Simple SGD update
        self.W1 -= lr * gW1 / n
        self.b1 -= lr * gb1 / n
        if self.W2 is not None:
            self.W2 -= lr * gW2 / n
            self.b2 -= lr * gb2 / n

        return {
            "loss": total_loss / n,
            "entropy": total_entropy / n,
            "n_steps": n,
        }

    # --- checkpointing --------------------------------------------------

    def save(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        out = {
            "hp_obs_dim": self.hp.obs_dim,
            "hp_n_actions": self.hp.n_actions,
            "hp_hidden_dim": self.hp.hidden_dim,
            "hp_learning_rate": self.hp.learning_rate,
            "hp_entropy_beta": self.hp.entropy_beta,
            "W1": self.W1,
            "b1": self.b1,
        }
        if self.W2 is not None:
            out["W2"] = self.W2
            out["b2"] = self.b2
        np.savez_compressed(path, **out)

    @classmethod
    def load(cls, path: Path) -> "PolicyNet":
        d = np.load(path)
        hp = PolicyHparams(
            obs_dim=int(d["hp_obs_dim"]),
            n_actions=int(d["hp_n_actions"]),
            hidden_dim=int(d["hp_hidden_dim"]),
            learning_rate=float(d["hp_learning_rate"]),
            entropy_beta=float(d["hp_entropy_beta"]),
        )
        net = cls(hp)
        net.W1 = d["W1"]
        net.b1 = d["b1"]
        if "W2" in d.files:
            net.W2 = d["W2"]
            net.b2 = d["b2"]
        return net

# --- helpers ----------------------------------------------------------------

def _softmax(x: np.ndarray) -> np.ndarray:
    x = x - np.max(x)
    e = np.exp(x)
    return e / np.sum(e)

def returns_to_go(rewards: list[float], gamma: float = 0.99) -> np.ndarray:
    """Compute discounted returns-to-go for each step."""
    out = np.zeros(len(rewards))
    running = 0.0
    for t in range(len(rewards) - 1, -1, -1):
        running = rewards[t] + gamma * running
        out[t] = running
    return out
