"""Gym-like environment wrapping the Plenith orchestrator for RL training.

Episodes are command sequences from `AttackerSim`. Each step runs one
attacker command through the orchestrator AND injects the policy's chosen
action into the action queue, then computes reward from the resulting
observation delta.

The env is in-memory only — no SSH, no LM Studio. For LLM-bound commands
that would normally hit the orchestrator's `_call_llm`, we use a deterministic
synthetic responder so training is fast and reproducible.

Standard gym-ish API:
    env = DeceptionEnv(...)
    obs = env.reset(seed=42)
    while True:
        action = policy.pick(obs)
        obs, reward, done, info = env.step(action)
        if done:
            break
"""
import asyncio
import copy
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..persona import load_persona
from ..policy import ACTION_SPACE, OBSERVATION_FEATURES, vectorize
from ..response_cache import ResponseCache
from ..session import Session
from .attacker import AttackerSim
from .reward import (
    RewardWeights,
    something_alert_worthy,
    step_reward,
    terminal_reward,
)

class _SyntheticLLM:
    """Stand-in for the real LMStudio client during training. Returns
    short, plausible stdout for commands the orchestrator hands us.
    Deterministic per (cmd, seed) so episodes are reproducible.
    """

    def __init__(self, rng: random.Random):
        self.rng = rng

    async def complete(self, system_prompt: str, user_prompt: str) -> str:
        # We don't try to be clever — pick a banner-ish line based on the
        # command verb. The reward function only inspects the first ~200
        # chars and looks for fingerprint markers; we'll never emit those.
        line = user_prompt.lower()
        if "sudo -l" in line:
            return "User jdoe may run the following commands:\n    (ALL) NOPASSWD: /usr/bin/apt-get\n"
        if "mysql" in line and "-p" in line:
            return "Enter password:\nERROR 1045 (28000): Access denied for user 'root'@'localhost'\n"
        if "sudo -i" in line or "sudo bash" in line or "sudo su" in line:
            return "root@host:~#\n"
        if "history" in line:
            return ""
        # Default: empty response, simulating a no-output command.
        return ""

def _build_orchestrator_for_training(persona, sim_bot, rng):
    """Construct an Orchestrator with the synthetic LLM and no real cache
    side effects. Imports are local so the training module can be imported
    without orchestrator dependencies firing in unrelated tests."""
    from ..orchestrator import Orchestrator
    return Orchestrator(
        llm_client=_SyntheticLLM(rng),
        cache=ResponseCache(Path(__file__).resolve().parent.parent.parent / "caches" / "default_responses.yaml"),
        sim_bot=sim_bot,
        # No policy injected here — we'll override decide_action via the env.
    )

@dataclass
class StepResult:
    obs: list[float]
    reward: float
    done: bool
    info: dict[str, Any] = field(default_factory=dict)

class DeceptionEnv:
    """One episode = one attacker session ending on `exit` or a hard cap.

    The env owns the Session + Orchestrator + AttackerSim. At each step:
      1. Pop the next attacker command from the sequence (or end episode).
      2. Run it through the orchestrator's _dispatch path.
      3. ALSO inject the policy's chosen action into actions_taken (if the
         action != noop), bypassing the heuristic decide_action call.
      4. Compute reward from the observation delta + action quality.
      5. Return (new_obs_vec, reward, done, info).
    """

    def __init__(
        self,
        *,
        personas_dir: Path,
        attacker_sim: AttackerSim,
        archetype: str = "balanced",
        reward_weights: RewardWeights | None = None,
        episode_cap: int = 30,
    ):
        self.personas_dir = personas_dir
        self.attacker_sim = attacker_sim
        self.archetype = archetype
        self.reward_weights = reward_weights or RewardWeights()
        self.episode_cap = episode_cap

        # Reset will populate these
        self._rng: random.Random | None = None
        self._session: Session | None = None
        self._orchestrator = None
        self._cmd_queue: list[str] = []
        self._prev_observed: dict[str, Any] = {}
        self._step_count: int = 0

    # --- gym-ish API ----------------------------------------------------

    def reset(self, seed: int | None = None, archetype: str | None = None) -> list[float]:
        self._rng = random.Random(seed)
        # Lazy import for fixtures
        from ..sim_bot import SimulationBot
        from ..persona import Persona

        personas = [Persona.from_yaml(p) for p in sorted(self.personas_dir.glob("*.yaml"))]
        persona = next(p for p in personas if p.username == "jdoe")
        sim_bot = SimulationBot(personas)
        self._session = Session("jdoe", "192.0.2.99", persona, sim_bot=sim_bot)
        self._orchestrator = _build_orchestrator_for_training(persona, sim_bot, self._rng)
        # We don't want heuristics to fire during training — the policy IS
        # the decision-maker. Swap in a no-op policy so the orchestrator
        # doesn't double-record actions.
        from ..policy import Policy
        class _NoOpPolicy(Policy):
            engine_name = "noop"
            def decide(self, session):
                return None
        self._orchestrator.policy = _NoOpPolicy()

        self._cmd_queue = self.attacker_sim.episode(
            self._rng, archetype=archetype or self.archetype
        )
        self._prev_observed = self._snapshot_observed()
        self._step_count = 0
        return vectorize(self._session)

    def step(self, action_id: int) -> StepResult:
        if not self._cmd_queue:
            # No more commands — terminal step
            return self._finalize()

        cmd = self._cmd_queue.pop(0)
        self._step_count += 1

        # Map action id to action dict. action_id 0 = noop.
        action_name = ACTION_SPACE[action_id] if 0 <= action_id < len(ACTION_SPACE) else "noop"
        action_dict = None
        if action_name != "noop":
            action_dict = {
                "action": action_name,
                "severity": _severity_for(action_name),
                "rationale": f"policy chose {action_name}",
                "ts_offset_s": round(self._session.time_elapsed, 2),
                "triggered_by": cmd,
            }

        # Run the command through the orchestrator dispatch (no heuristics)
        body, source = asyncio.get_event_loop().run_until_complete(
            self._orchestrator.handle_command(self._session, cmd)
        ) if False else _run_async(self._orchestrator.handle_command(self._session, cmd))

        # If the policy chose an action, record it (and apply real side effects)
        if action_dict is not None:
            self._session.actions_taken.append(action_dict)
            from ..responses import execute as execute_response
            try:
                execute_response(action_dict, self._session)
            except Exception:
                pass

        # Reward = step delta + maybe terminal
        new_observed = self._snapshot_observed()
        worthy = something_alert_worthy(self._prev_observed, new_observed)
        sr = step_reward(
            prev_observed=self._prev_observed,
            new_observed=new_observed,
            action_name=action_name,
            action_severity=(action_dict["severity"] if action_dict else "info"),
            response_preview=body or "",
            fired_an_alert=action_name != "noop",
            something_alert_worthy_happened=worthy,
            weights=self.reward_weights,
        )
        self._prev_observed = new_observed

        # Determine done
        done = (not self._cmd_queue) or (self._step_count >= self.episode_cap) or (cmd.strip() == "exit")
        if done:
            tr = terminal_reward(
                n_commands=self._step_count,
                observed=new_observed,
                weights=self.reward_weights,
            )
            sr.add("__terminal__", tr.total)
            for k, v in tr.components.items():
                sr.components[k] = v

        return StepResult(
            obs=vectorize(self._session),
            reward=sr.total,
            done=done,
            info={
                "cmd": cmd,
                "source": source,
                "action": action_name,
                "reward_components": sr.components,
                "step": self._step_count,
            },
        )

    # --- helpers --------------------------------------------------------

    def _snapshot_observed(self) -> dict[str, Any]:
        return copy.deepcopy(self._session.observed) if self._session else {}

    def _finalize(self) -> StepResult:
        # Pure terminal step — no command, just emit final reward
        new_observed = self._snapshot_observed()
        tr = terminal_reward(
            n_commands=self._step_count,
            observed=new_observed,
            weights=self.reward_weights,
        )
        return StepResult(
            obs=vectorize(self._session),
            reward=tr.total,
            done=True,
            info={"step": self._step_count, "reward_components": tr.components,
                  "terminal_only": True},
        )

# Map action_id -> severity heuristic. The real `responses.execute` doesn't
# strictly need it but we record it for telemetry.
_SEVERITY_BY_ACTION = {
    "alert_reverse_shell": "critical",
    "alert_ssh_persistence": "critical",
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

def _severity_for(action_name: str) -> str:
    return _SEVERITY_BY_ACTION.get(action_name, "info")

# Local event-loop helper so we can call async orchestrator methods from
# sync env.step(). We avoid asyncio.run because it creates a new loop per
# call which is slow; instead, get-or-create one.
_LOOP: asyncio.AbstractEventLoop | None = None

def _run_async(coro):
    global _LOOP
    if _LOOP is None or _LOOP.is_closed():
        _LOOP = asyncio.new_event_loop()
    return _LOOP.run_until_complete(coro)
