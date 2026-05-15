"""The Kill button is only real if a queued kill actually drops a live
SSH session.

`plenith/kill_queue.py` only *records* kill intent (covered by
test_kill_queue.py); the dashboard/API only *write* to it (covered by
test_api.py). This file covers the consumer half in
`plenith/ssh_server.py`:

- `_apply_kill(entry)` — connection-scoped enforcement: honor a kill
  only if it was raised after THIS connection opened (reconnects keep a
  restored engagement_id and must not inherit a predecessor's kill).
- the single process-wide poller (`_kill_poll_once`) + live-session
  registry — one queue read per interval regardless of session count
  (the per-session-poller design was a concurrency regression).
- the per-command fast path reading the poller's in-memory view (no
  file I/O per command).

connection_made() needs full cfg / personas-dir / orchestrator, so we
wire the kill-relevant attributes by hand and register sessions in the
module registry the way connection_made would.
"""
import asyncio
import time
import types

import pytest

import plenith.ssh_server as sshmod
from plenith.kill_queue import reset_default_queue_for_tests
from plenith.session import Session
from plenith.ssh_server import HoneypotSession


@pytest.fixture(autouse=True)
def _reset_kill_module_state():
    """The registry + pending view are module-level; isolate tests."""
    sshmod._LIVE_SESSIONS.clear()
    sshmod._PENDING_VIEW.clear()
    yield
    sshmod._LIVE_SESSIONS.clear()
    sshmod._PENDING_VIEW.clear()


class FakeChan:
    def __init__(self):
        self.closed = False
        self.writes = []

    def close(self):
        self.closed = True

    def write(self, data):
        self.writes.append(data)


async def _boom_handle_command(*_a, **_k):
    raise AssertionError("handle_command must NOT run once a kill is queued")


def _make_session(persona):
    server = types.SimpleNamespace(
        orchestrator=types.SimpleNamespace(
            handle_command=_boom_handle_command),
        cfg={"paths": {"logs_dir": "unused"}},
        state_store=None,
        username="jdoe",
    )
    hs = HoneypotSession(server)
    hs._session = Session("jdoe", "10.1.2.3", persona)
    hs._chan = FakeChan()
    hs._queue = asyncio.Queue()
    hs._closed = False
    # Connection opened an hour ago: a kill queued "now" is newer than
    # the connection, so it's honored (the normal case).
    hs._conn_started = time.time() - 3600
    return hs


def _register(hs):
    """What connection_made does — make hs visible to the shared poller."""
    sshmod._LIVE_SESSIONS.setdefault(hs._session.engagement_id, set()).add(hs)


# --- connection-scoped enforcement (_apply_kill via the wrapper) -----------

def test_no_pending_kill_is_noop(tmp_path, persona_jdoe):
    reset_default_queue_for_tests(tmp_path / "kill.json")
    hs = _make_session(persona_jdoe)
    assert hs._apply_kill_if_requested() is False
    assert hs._chan.closed is False
    assert hs._closed is False


def test_pending_kill_closes_and_marks_killed(tmp_path, persona_jdoe):
    q = reset_default_queue_for_tests(tmp_path / "kill.json")
    hs = _make_session(persona_jdoe)
    eid = hs._session.engagement_id
    q.request_kill(eid, requested_by="mwilson", reason="confirmed LLM attacker")

    assert hs._apply_kill_if_requested() is True
    assert hs._chan.closed is True
    assert hs._closed is True
    entry = q.get(eid)
    assert entry["status"] == "killed"
    assert "killed_at" in entry


def test_kill_only_matches_this_engagement(tmp_path, persona_jdoe):
    q = reset_default_queue_for_tests(tmp_path / "kill.json")
    hs = _make_session(persona_jdoe)
    q.request_kill("some-other-engagement", requested_by="x")
    assert hs._apply_kill_if_requested() is False
    assert hs._chan.closed is False
    assert hs._closed is False


def test_stale_kill_predating_connection_is_discarded(tmp_path, persona_jdoe):
    """engagement_id is restored across reconnects; a kill request that
    predates THIS connection targeted a previous session and must not
    guillotine the reconnect. It should also be cleaned up so it stops
    haunting every future reconnect of the same (ip,user)."""
    q = reset_default_queue_for_tests(tmp_path / "kill.json")
    hs = _make_session(persona_jdoe)
    eid = hs._session.engagement_id
    q.request_kill(eid, requested_by="operator", reason="click-and-hold")
    # This physical connection opened AFTER the kill was queued — i.e.
    # the request belonged to an earlier connection of the same identity.
    hs._conn_started = time.time() + 100

    assert hs._apply_kill_if_requested() is False
    assert hs._chan.closed is False
    assert hs._closed is False
    assert q.get(eid) is None   # stale request discarded


def test_kill_requested_during_this_connection_is_honored(tmp_path,
                                                          persona_jdoe):
    q = reset_default_queue_for_tests(tmp_path / "kill.json")
    hs = _make_session(persona_jdoe)
    eid = hs._session.engagement_id
    hs._conn_started = time.time() - 5      # opened 5s ago
    q.request_kill(eid, requested_by="operator")   # requested just now

    assert hs._apply_kill_if_requested() is True
    assert hs._chan.closed is True
    assert q.get(eid)["status"] == "killed"


# --- shared poller + registry ----------------------------------------------

def test_shared_poller_kills_registered_idle_session(tmp_path, persona_jdoe):
    """Idle session — no command ever sent, so only the poller (not the
    per-command fast path) can drop it. This is the path the original
    bug lacked entirely."""
    q = reset_default_queue_for_tests(tmp_path / "kill.json")
    hs = _make_session(persona_jdoe)
    eid = hs._session.engagement_id
    _register(hs)
    q.request_kill(eid, requested_by="dashboard")

    sshmod._kill_poll_once()       # one tick

    assert hs._chan.closed is True
    assert hs._closed is True
    assert q.get(eid)["status"] == "killed"


def test_shared_poller_kills_all_live_sessions_for_engagement(tmp_path,
                                                              persona_jdoe):
    """Concurrent connections share a restored engagement_id; a Kill on
    that engagement drops every live connection for it."""
    q = reset_default_queue_for_tests(tmp_path / "kill.json")
    a = _make_session(persona_jdoe)
    b = _make_session(persona_jdoe)
    eid = a._session.engagement_id
    b._session.engagement_id = eid          # same identity, 2 connections
    _register(a)
    _register(b)
    q.request_kill(eid, requested_by="dashboard")

    sshmod._kill_poll_once()

    assert a._chan.closed is True and a._closed is True
    assert b._chan.closed is True and b._closed is True


def test_poll_reads_queue_once_regardless_of_session_count(tmp_path,
                                                           persona_jdoe,
                                                           monkeypatch):
    """The regression this refactor fixes: the old design did one
    kill-queue file read PER SESSION PER TICK. The shared poller does
    exactly one read per tick no matter how many sessions are live."""
    q = reset_default_queue_for_tests(tmp_path / "kill.json")
    calls = {"n": 0}
    real_all = q.all

    def counting_all():
        calls["n"] += 1
        return real_all()

    monkeypatch.setattr(q, "all", counting_all)

    for i in range(50):
        hs = _make_session(persona_jdoe)
        hs._session.engagement_id = f"eng-{i}"
        _register(hs)

    sshmod._kill_poll_once()
    assert calls["n"] == 1          # one read for 50 sessions (was 50)


@pytest.mark.asyncio
async def test_shared_poller_loop_drops_idle_session_within_interval(
        tmp_path, persona_jdoe, monkeypatch):
    monkeypatch.setattr(sshmod, "_KILL_POLL_INTERVAL", 0.02)
    q = reset_default_queue_for_tests(tmp_path / "kill.json")
    hs = _make_session(persona_jdoe)
    eid = hs._session.engagement_id
    _register(hs)

    task = asyncio.create_task(sshmod._run_shared_kill_poller())
    try:
        q.request_kill(eid, requested_by="dashboard")
        # Poll every 0.02s; give it a few ticks.
        for _ in range(50):
            await asyncio.sleep(0.02)
            if hs._closed:
                break
        assert hs._chan.closed is True
        assert q.get(eid)["status"] == "killed"
    finally:
        task.cancel()


@pytest.mark.asyncio
async def test_worker_fast_path_uses_in_memory_view(tmp_path, persona_jdoe):
    """The per-command fast path must consult the poller's in-memory
    view (a dict lookup, no file read per command) and cut the session
    before the command reaches the orchestrator."""
    q = reset_default_queue_for_tests(tmp_path / "kill.json")
    hs = _make_session(persona_jdoe)
    eid = hs._session.engagement_id
    q.request_kill(eid, requested_by="dashboard")
    # Simulate the shared poller having refreshed the view.
    sshmod._PENDING_VIEW[eid] = q.get(eid)

    hs._queue.put_nowait("cat /etc/shadow")
    await asyncio.wait_for(hs._run_worker(), timeout=2.0)

    assert hs._chan.closed is True
    assert hs._closed is True
    assert q.get(eid)["status"] == "killed"
