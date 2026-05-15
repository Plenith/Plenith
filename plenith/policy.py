"""V2 policy controller scaffold.

The MVP's `heuristics.py` is a hand-tuned if-ladder of 14 rules. The
production §11 vision in Plenith.md is an RL-trained policy: an agent
that watches the observation stream and picks deception actions to
maximize dwell time × intelligence yield.

This module is the abstraction layer that BOTH the current heuristic
engine AND a future trained policy plug into. The orchestrator goes
through `policy.decide(session)` instead of importing `heuristics.decide_action`
directly. Switching engines becomes a config flag, not a code change.

Today: the `HeuristicPolicy` wraps `heuristics.decide_action` 1:1 — zero
behavior change. The default in `config.yaml` is `policy.engine: heuristic`.

To plug in a trained model later:
  1. Implement `Policy.observe(session) -> np.ndarray` to vectorize state.
  2. Implement `Policy.act(obs_vec) -> action_id` (your inference call).
  3. Implement `Policy.action_dict_for(action_id) -> dict` matching the
     existing action contract (`{"action": ..., "severity": ..., "rationale": ...}`).
  4. Register the class in `_REGISTRY` under a new engine key.
  5. Set `policy.engine: rl` in config.yaml.

The observation space and action space are documented as constants below
so trained-model code has a fixed contract to bind against.
"""
from typing import Any

from .heuristics import decide_action

# ---------------------------------------------------------------------------
# Observation space contract.
#
# When we vectorize a Session for an RL agent, these are the features in
# fixed positional order. Trainers should freeze this ordering — adding
# new features goes at the END so old checkpoints stay compatible.
# ---------------------------------------------------------------------------
OBSERVATION_FEATURES: list[dict[str, Any]] = [
    # Booleans (0/1)
    {"name": "ran_sudo",                       "type": "bool"},
    {"name": "attempted_lateral",              "type": "bool"},
    {"name": "found_crown_jewel",              "type": "bool"},
    {"name": "isolated",                       "type": "bool"},
    {"name": "ssh_persistence_attempt",        "type": "bool"},
    {"name": "bash_history_inspected",         "type": "bool"},
    {"name": "credential_search_attempted",    "type": "bool"},
    {"name": "reverse_shell_attempted",        "type": "bool"},
    {"name": "dns_exfil_attempted",            "type": "bool"},
    {"name": "lateral_to_decoy",               "type": "bool"},
    {"name": "log_tampering",                  "type": "bool"},
    {"name": "attempted_sudo_elevation",       "type": "bool"},
    # Counts (clamped to [0, 50])
    {"name": "n_credential_files_read",        "type": "count", "max": 50},
    {"name": "n_honeytoken_modifications",     "type": "count", "max": 50},
    {"name": "n_payload_drops",                "type": "count", "max": 50},
    {"name": "n_decoy_targets",                "type": "count", "max": 50},
    {"name": "n_decoys_planted",               "type": "count", "max": 50},
    {"name": "n_decoys_swallowed",             "type": "count", "max": 50},
    {"name": "n_services_probed",              "type": "count", "max": 50},
    # Continuous
    {"name": "time_elapsed_sec",               "type": "scalar"},
    {"name": "connection_count",               "type": "count", "max": 100},
]

# ---------------------------------------------------------------------------
# Action space contract.
#
# This is the full set of deception actions the orchestrator knows how to
# execute. An RL policy outputs a discrete action id ∈ [0, len(ACTION_SPACE)-1].
# The mapping is fixed; never reorder, only append.
# ---------------------------------------------------------------------------
ACTION_SPACE: list[str] = [
    "noop",                          # 0
    "plant_sudo_vulnerability",      # 1
    "spawn_fake_mysql",              # 2
    "plant_aws_credentials",         # 3
    "isolate_session",               # 4
    "alert_credential_search",       # 5
    "alert_credential_exfil",        # 6
    "alert_honeytoken_tamper",       # 7
    "alert_payload_staging",         # 8
    "alert_decoy_swallowed",         # 9
    "alert_dns_exfil",               # 10
    "alert_lateral_decoy",           # 11
    "alert_log_tampering",           # 12
    "alert_ssh_persistence",         # 13
    "alert_reverse_shell",           # 14
    "alert_attacker_llm_detected",   # 15  (counter-AI; high / critical-on-proof)
]

def vectorize(session) -> list[float]:
    """Convert a Session.observed dict into a fixed-order feature vector.

    Booleans become 0/1, sets become their cardinality (clamped), and
    `time_elapsed_sec` is the session-elapsed wall time in seconds.

    This is the canonical interface a trained model binds to.
    """
    obs = session.observed
    out: list[float] = []
    for feat in OBSERVATION_FEATURES:
        name = feat["name"]
        ftype = feat["type"]
        if ftype == "bool":
            out.append(1.0 if obs.get(name) else 0.0)
        elif ftype == "count":
            key = name[2:] if name.startswith("n_") else name
            val = obs.get(key, [])
            if isinstance(val, (set, list)):
                n = len(val)
            elif isinstance(val, int):
                n = val
            else:
                n = 0
            out.append(min(float(n), float(feat.get("max", 100))))
        elif ftype == "scalar":
            if name == "time_elapsed_sec":
                out.append(float(getattr(session, "time_elapsed", 0)))
            elif name == "connection_count":
                out.append(float(getattr(session, "connection_count", 1)))
            else:
                out.append(0.0)
    # Treat connection_count as count too (handled above by lookup-by-name)
    return out

# ---------------------------------------------------------------------------
# Policy interface
# ---------------------------------------------------------------------------

class Policy:
    """Base class. Subclass and register in `_REGISTRY` to add an engine."""

    engine_name: str = "abstract"

    def decide(self, session) -> dict[str, Any] | None:
        """Return the next action dict, or None if no action this tick.

        The returned dict matches the existing contract:
            {"action": str, "severity": str, "rationale": str, ...}
        """
        raise NotImplementedError

class HeuristicPolicy(Policy):
    """V1: thin wrapper around `heuristics.decide_action`. Zero behavior
    change vs. calling `decide_action` directly. This is the default."""

    engine_name = "heuristic"

    def decide(self, session):
        return decide_action(session)

class RLPolicyStub(Policy):
    """V2 placeholder kept for back-compat: if `policy.engine: rl` is
    requested with no `model_path`, fall back to the heuristic engine so
    the platform stays functional. `TrainedRLPolicy` is the real RL engine.
    """

    engine_name = "rl"

    def __init__(self, model_path: str | None = None):
        self.model_path = model_path
        self._model = None

    def decide(self, session):
        return decide_action(session)

# ---------------------------------------------------------------------------
# Severity / rationale lookups for trained-policy action dicts.
# Kept here (not in heuristics.py) because they are part of the action
# space contract — the trained model emits action ids that we have to
# materialize into the same dict shape `heuristics.decide_action` returns.
# ---------------------------------------------------------------------------
_SEVERITY_BY_ACTION = {
    "alert_reverse_shell": "critical",
    "alert_ssh_persistence": "critical",
    "alert_attacker_llm_detected": "high",   # heuristics.py may override to critical on proof
    "alert_credential_exfil": "high",
    "alert_dns_exfil": "high",
    "alert_lateral_decoy": "high",
    "alert_log_tampering": "high",
    "alert_honeytoken_tamper": "high",
    "alert_credential_search": "medium",
    "alert_payload_staging": "medium",
    "alert_decoy_swallowed": "medium",
    "isolate_session": "medium",
    "plant_sudo_vulnerability": "info",
    "spawn_fake_mysql": "info",
    "plant_aws_credentials": "info",
}

def _rl_rationale(action_name: str, session) -> str:
    """Build a short rationale string for a trained-policy action. The
    text references session.observed so analysts can see what the model
    saw, just like the heuristic rationale does today."""
    obs = session.observed
    if action_name == "alert_reverse_shell":
        cmd = obs.get("reverse_shell_command", "?")
        return (
            f"RL policy: reverse-shell idiom detected: {cmd[:160]!r}. "
            "Active C2 establishment. Recommend immediate session isolation."
        )
    if action_name == "alert_ssh_persistence":
        return (
            "RL policy: persistence-path write detected (e.g. ~/.ssh/authorized_keys). "
            "Recommend isolate session + credential rotation."
        )
    if action_name == "alert_dns_exfil":
        cmds = sorted(obs.get("dns_exfil_commands", []))[:3] or ["?"]
        return f"RL policy: suspicious egress via curl/wget to {cmds}."
    if action_name == "alert_log_tampering":
        cmds = sorted(obs.get("log_tampering_commands", []))[:3] or ["?"]
        return f"RL policy: log/history tampering detected: {cmds}."
    if action_name == "alert_honeytoken_tamper":
        toks = sorted(obs.get("honeytoken_modifications", []))[:3] or ["?"]
        return f"RL policy: planted honeytoken(s) tampered with: {toks}."
    if action_name == "alert_lateral_decoy":
        targets = sorted(obs.get("decoy_targets", []))[:3] or ["?"]
        return f"RL policy: lateral probe to decoy host(s) {targets}."
    if action_name == "alert_credential_exfil":
        reads = sorted(obs.get("credential_files_read", []))[:3] or ["?"]
        return f"RL policy: credential file(s) read: {reads}."
    if action_name == "alert_credential_search":
        return "RL policy: credential-search heuristic fired (find / grep over secrets)."
    if action_name == "alert_decoy_swallowed":
        swallowed = sorted(obs.get("decoys_swallowed", []))[:3] or ["?"]
        return f"RL policy: attacker swallowed a planted decoy: {swallowed}."
    if action_name == "alert_payload_staging":
        drops = sorted(obs.get("payload_drops", []))[:3] or ["?"]
        return f"RL policy: payload staging detected at {drops}."
    if action_name == "isolate_session":
        return "RL policy: session-isolation recommended given current threat profile."
    if action_name == "plant_sudo_vulnerability":
        return "RL policy: planting fake sudoers misconfig to bait privilege-escalation attempt."
    if action_name == "spawn_fake_mysql":
        return "RL policy: spawning fake MySQL banner to deepen engagement."
    if action_name == "plant_aws_credentials":
        return "RL policy: planting fake AWS credentials at a likely-search path."
    return f"RL policy chose {action_name}."

class TrainedRLPolicy(Policy):
    """Inference-only engine backed by a `plenith.training.PolicyNet`
    checkpoint (.npz). Loads on first use so import-time cost is zero
    when this engine isn't selected.

    Two safety guards layered on top of the raw model output:

      1. **No-double-fire mask**: any non-noop action already in
         `session.actions_taken` is masked out before argmax, so the
         orchestrator's "loop until policy returns None" pattern
         terminates cleanly (otherwise an undertrained policy could pin
         a single action forever).

      2. **Soft fallback**: if the masked probability mass is zero
         (every non-noop has fired), return None to end the loop.

    Construction:
        TrainedRLPolicy(model_path="state/checkpoints/policy_best.npz")

    Sampling mode (default off) is useful for exploration during
    eval/red-team studies; production runs should keep greedy=True.
    """

    engine_name = "trained_rl"

    def __init__(
        self,
        model_path: str | None = None,
        *,
        sampling: bool = False,
        seed: int = 0,
    ):
        self.model_path = model_path
        self.sampling = sampling
        self._seed = seed
        self._model = None
        self._rng = None  # lazy-init numpy RNG

    def _ensure_loaded(self):
        if self._model is None:
            if not self.model_path:
                raise RuntimeError(
                    "TrainedRLPolicy requires policy.model_path in config; "
                    "set it to a .npz produced by tools/train_rl.py."
                )
            # Local import so numpy/training package isn't imported unless used.
            from .training.policy_net import PolicyNet  # noqa: WPS433
            import numpy as _np  # noqa: WPS433
            self._np = _np
            self._model = PolicyNet.load(self.model_path)
            self._rng = _np.random.default_rng(self._seed)

    def decide(self, session) -> dict[str, Any] | None:
        self._ensure_loaded()
        np = self._np
        obs_vec = np.asarray(vectorize(session), dtype=np.float64)
        _logits, probs = self._model.forward(obs_vec)

        # Mask already-fired non-noop actions so we don't spin on the
        # orchestrator's "loop until None" pattern.
        fired = {a.get("action") for a in session.actions_taken}
        masked = probs.copy()
        for i, name in enumerate(ACTION_SPACE):
            if i == 0:  # noop is always allowed
                continue
            if name in fired:
                masked[i] = 0.0
        s = float(masked.sum())
        if s <= 1e-12:
            return None
        masked = masked / s

        if self.sampling:
            action_id = int(self._rng.choice(len(ACTION_SPACE), p=masked))
        else:
            action_id = int(np.argmax(masked))

        if action_id == 0:
            return None

        action_name = ACTION_SPACE[action_id]
        return {
            "action": action_name,
            "severity": _SEVERITY_BY_ACTION.get(action_name, "info"),
            "rationale": _rl_rationale(action_name, session),
        }

_REGISTRY = {
    "heuristic": HeuristicPolicy,
    "rl": RLPolicyStub,
    "trained_rl": TrainedRLPolicy,
}

def build_policy(config: dict[str, Any] | None = None) -> Policy:
    """Construct the configured policy. Falls back to `heuristic` for any
    missing/unknown engine name.

    Recognized keys in `config`:
        engine: "heuristic" | "rl" | "trained_rl" | "<plugin_name>"
        model_path: str — path to a .npz (required for `trained_rl`)
        sampling: bool — sample from softmax instead of argmax (trained_rl)
        seed: int — RNG seed for sampling

    Plugin policies (registered via `plenith.plugins`) win over the
    built-in `_REGISTRY` when their `name` matches `engine`. This lets a
    third party ship an alternate engine without forking the codebase.
    """
    cfg = config or {}
    engine = cfg.get("engine", "heuristic")

    # First: plugin policies. They're pre-constructed instances (typically
    # configured at plugin-load time), so we just return them as-is.
    try:
        from .plugins import policy_class_for
        plugin = policy_class_for(engine)
        if plugin is not None:
            return plugin
    except Exception:
        # Plugin discovery shouldn't break policy construction.
        pass

    cls = _REGISTRY.get(engine, HeuristicPolicy)
    if cls is TrainedRLPolicy:
        # If no model_path is provided, fall back to heuristic so the
        # platform stays functional with an explicit warning at log-time.
        if not cfg.get("model_path"):
            return HeuristicPolicy()
        return cls(
            model_path=cfg.get("model_path"),
            sampling=bool(cfg.get("sampling", False)),
            seed=int(cfg.get("seed", 0)),
        )
    if cls is RLPolicyStub:
        return cls(model_path=cfg.get("model_path"))
    return cls()
