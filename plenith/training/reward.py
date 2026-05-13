"""Reward function for the deception-policy RL training loop.

Each step of an episode = one attacker command + the policy's chosen action.
The reward signal is a composite of session-level outcomes — we want the
policy to maximize attacker engagement, IoC capture, and deception success,
while penalizing fingerprint-leak signals.

The reward is computed DELTA-style: at each step, we look at what changed
in `session.observed` since the previous step, plus what action was just
taken, and emit a scalar.

Tunable weights live at the top so a future ML person can sweep them.
"""
from dataclasses import dataclass, field
from typing import Dict, Set


@dataclass
class RewardWeights:
    """Per-event weights. Positive = policy gets credit, negative = penalty."""

    # ---- session-state deltas (per new observation each step) ----
    per_credential_file_read: float = 5.0       # attacker took the bait
    per_payload_drop: float = 1.0               # they're staging — engagement deepening
    per_decoy_swallowed: float = 8.0            # they read OUR planted file
    per_new_decoy_target: float = 4.0           # tried lateral to one of our hostnames
    per_honeytoken_modification: float = 3.0    # tampering = still engaged

    # ---- terminal bonuses (computed once, at episode end) ----
    dwell_per_command: float = 0.3              # +0.3 per command in episode
    bonus_revshell: float = 6.0
    bonus_ssh_persistence: float = 6.0
    bonus_log_tampering: float = 4.0
    bonus_dns_exfil: float = 4.0
    bonus_elevation: float = 10.0               # they ran sudo -i after swallow

    # ---- penalties ----
    # If the LLM produces output that an attacker might use to identify the
    # decoy (a "fingerprint"), penalize. Detected heuristically by sentinel
    # markers in the response_preview that we caught at runtime.
    per_fingerprint_signal: float = -10.0
    # Cost of firing an alert when nothing observably new triggered it.
    # Discourages the policy from spamming high-severity alerts.
    spurious_alert_penalty: float = -2.0
    # Cost of NOT acting when something alert-worthy happened.
    missed_alert_penalty: float = -3.0


# Sentinel markers in LLM output that suggest the decoy slipped character —
# things like Chinese hallucinations, breaking-character chatbot phrases,
# obvious "I am an AI" giveaways.
_FINGERPRINT_SUBSTRINGS = (
    "as an AI", "I cannot", "I'm a language model", "I do not have access",
    "  As an assistant", "I apologize", "```python", "```bash\n",
)


def _detect_fingerprint(response_preview: str) -> bool:
    if not response_preview:
        return False
    haystack = response_preview.lower()
    return any(s.lower() in haystack for s in _FINGERPRINT_SUBSTRINGS)


@dataclass
class StepReward:
    """Reward decomposition for one step. The training loop uses the `total`,
    the rest is available for telemetry / debugging."""
    total: float = 0.0
    components: Dict[str, float] = field(default_factory=dict)

    def add(self, name: str, value: float) -> None:
        if value == 0:
            return
        self.components[name] = self.components.get(name, 0.0) + value
        self.total += value


def step_reward(
    *,
    prev_observed: Dict[str, Set[str]],
    new_observed: Dict[str, Set[str]],
    action_name: str,
    action_severity: str,
    response_preview: str,
    fired_an_alert: bool,
    something_alert_worthy_happened: bool,
    weights: RewardWeights | None = None,
) -> StepReward:
    """Reward for a single step. Inputs are diffs and meta about the action.

    `prev_observed` and `new_observed` are dicts of set-valued observations
    (e.g. payload_drops, credential_files_read) BEFORE and AFTER this step.
    We credit the policy for new entries in those sets.

    `action_name` / `action_severity` describe what the policy picked
    (or "noop" if nothing). `response_preview` is the actual stdout the
    attacker received — used for fingerprint detection.
    """
    w = weights or RewardWeights()
    r = StepReward()

    # Set-delta rewards
    for key, weight in [
        ("credential_files_read", w.per_credential_file_read),
        ("payload_drops", w.per_payload_drop),
        ("decoys_swallowed", w.per_decoy_swallowed),
        ("decoy_targets", w.per_new_decoy_target),
        ("honeytoken_modifications", w.per_honeytoken_modification),
    ]:
        old = prev_observed.get(key, set()) or set()
        new = new_observed.get(key, set()) or set()
        # Coerce list → set in case state was deserialized
        if isinstance(old, list):
            old = set(old)
        if isinstance(new, list):
            new = set(new)
        added = new - old
        if added:
            r.add(f"+{key}({len(added)})", weight * len(added))

    # Action-quality reward
    if fired_an_alert and not something_alert_worthy_happened:
        r.add("spurious_alert", w.spurious_alert_penalty)
    elif not fired_an_alert and something_alert_worthy_happened:
        r.add("missed_alert", w.missed_alert_penalty)

    # Fingerprint penalty
    if _detect_fingerprint(response_preview):
        r.add("fingerprint", w.per_fingerprint_signal)

    return r


def terminal_reward(
    *,
    n_commands: int,
    observed: Dict[str, Set[str]],
    weights: RewardWeights | None = None,
) -> StepReward:
    """One-shot bonus at episode end. Rewards "the engagement was juicy."""
    w = weights or RewardWeights()
    r = StepReward()
    r.add("dwell", n_commands * w.dwell_per_command)

    def _b(flag: str, weight: float, label: str | None = None) -> None:
        if observed.get(flag):
            r.add(label or f"bonus_{flag}", weight)

    _b("reverse_shell_attempted", w.bonus_revshell, "bonus_revshell")
    _b("ssh_persistence_attempt", w.bonus_ssh_persistence, "bonus_ssh_persist")
    _b("log_tampering", w.bonus_log_tampering, "bonus_log_tamper")
    _b("dns_exfil_attempted", w.bonus_dns_exfil, "bonus_dns_exfil")
    _b("attempted_sudo_elevation", w.bonus_elevation, "bonus_elevation")
    return r


def something_alert_worthy(
    prev_observed: Dict[str, Set[str]],
    new_observed: Dict[str, Set[str]],
) -> bool:
    """Heuristic: did the latest step produce ANY observation change that
    a sensible policy would alert on? Used for action-quality scoring."""
    keys = (
        "credential_files_read",
        "decoy_targets",
        "honeytoken_modifications",
        "payload_drops",
        "decoys_swallowed",
    )
    bool_flags = (
        "ssh_persistence_attempt",
        "reverse_shell_attempted",
        "dns_exfil_attempted",
        "log_tampering",
        "credential_search_attempted",
    )
    for k in keys:
        old = prev_observed.get(k, set()) or set()
        new = new_observed.get(k, set()) or set()
        if isinstance(old, list):
            old = set(old)
        if isinstance(new, list):
            new = set(new)
        if (new - old):
            return True
    for k in bool_flags:
        if new_observed.get(k) and not prev_observed.get(k):
            return True
    return False
