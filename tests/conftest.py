"""Shared pytest fixtures for the Plenith test suite."""
import sys
from pathlib import Path

import pytest

# Make the plenith package importable when running pytest from anywhere.
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from plenith.persona import Persona, load_persona  # noqa: E402
from plenith.response_cache import ResponseCache  # noqa: E402
from plenith.session import Session  # noqa: E402
from plenith.sim_bot import SimulationBot  # noqa: E402
from plenith.orchestrator import Orchestrator  # noqa: E402
from plenith.state_store import StateStore  # noqa: E402


class FakeLLM:
    """An LLM client that records every call and returns a fixed response."""
    def __init__(self, response="<<fake-llm>>"):
        self.response = response
        self.calls = []

    async def complete(self, system, user):
        self.calls.append({"system": system, "user": user})
        return self.response


@pytest.fixture
def project_root():
    return _ROOT


@pytest.fixture
def personas_dir(project_root):
    return project_root / "personas"


@pytest.fixture
def personas(personas_dir):
    """All personas in the project, sorted by username."""
    return [Persona.from_yaml(p) for p in sorted(personas_dir.glob("*.yaml"))]


@pytest.fixture
def persona_jdoe(personas_dir):
    return load_persona(personas_dir, "jdoe")


@pytest.fixture
def persona_agarcia(personas_dir):
    return load_persona(personas_dir, "agarcia")


@pytest.fixture
def persona_mwilson(personas_dir):
    return load_persona(personas_dir, "mwilson")


@pytest.fixture
def cache(project_root):
    return ResponseCache(project_root / "caches" / "default_responses.yaml")


@pytest.fixture
def sim_bot(personas):
    return SimulationBot(personas)


@pytest.fixture
def fake_llm():
    return FakeLLM()


@pytest.fixture
def session(persona_jdoe, sim_bot):
    """Fresh in-memory session with no state store."""
    return Session("jdoe", "127.0.0.1", persona_jdoe, sim_bot=sim_bot)


@pytest.fixture
def orchestrator(fake_llm, cache, sim_bot):
    return Orchestrator(fake_llm, cache, sim_bot=sim_bot)


@pytest.fixture
def state_store(tmp_path):
    """A StateStore rooted in a per-test temp dir — never touches real state."""
    return StateStore(tmp_path / "persistence")


def actions(session):
    """Helper: list of action names taken on a session."""
    return [a["action"] for a in session.actions_taken]


def severity(session, action):
    """Helper: severity of a specific action on a session, or None."""
    for a in session.actions_taken:
        if a["action"] == action:
            return a.get("severity")
    return None
