"""The Kill button is only real if a queued kill actually drops a live
SSH session.

`plenith/kill_queue.py` only *records* kill intent (covered by
test_kill_queue.py); the dashboard/API only *write* to it (covered by
test_api.py). This file covers the half that was previously unbuilt:
`plenith/ssh_server.py`'s HoneypotSession *consuming* the queue —
per-command fast path AND the idle poller — closing the channel and
flipping the request to "killed".

connection_made() needs full cfg / personas-dir / orchestrator, so we
wire the kill-relevant attributes by hand to isolate the consumer.
"""
import asyncio
import time
import types

import pytest

from plenith.kill_queue import reset_default_queue_for_tests
from plenith.session import Session
from plenith.ssh_server import HoneypotSession


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
    # Stale request discarded so the next reconnect isn't guillotined.
    assert q.get(eid) is None


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


@pytest.mark.asyncio
async def test_idle_poller_kills_silent_session(tmp_path, persona_jdoe,
                                                monkeypatch):
    import plenith.ssh_server as ssh_server
    monkeypatch.setattr(ssh_server, "_KILL_POLL_INTERVAL", 0.02)
    q = reset_default_queue_for_tests(tmp_path / "kill.json")
    hs = _make_session(persona_jdoe)
    eid = hs._session.engagement_id

    poller = asyncio.create_task(hs._run_kill_poller())
    # Session is idle — no command ever sent. Kill arrives out-of-band
    # (as it would from the dashboard, a separate process).
    q.request_kill(eid, requested_by="dashboard")
    await asyncio.wait_for(poller, timeout=2.0)

    assert hs._chan.closed is True
    assert hs._closed is True
    assert q.get(eid)["status"] == "killed"


@pytest.mark.asyncio
async def test_worker_fast_path_cuts_before_next_command(tmp_path,
                                                         persona_jdoe):
    q = reset_default_queue_for_tests(tmp_path / "kill.json")
    hs = _make_session(persona_jdoe)
    eid = hs._session.engagement_id
    q.request_kill(eid, requested_by="dashboard")

    # Attacker sends a command with a kill already queued. The worker
    # must drop them WITHOUT dispatching to the orchestrator
    # (_boom_handle_command raises if reached).
    hs._queue.put_nowait("cat /etc/shadow")
    await asyncio.wait_for(hs._run_worker(), timeout=2.0)

    assert hs._chan.closed is True
    assert hs._closed is True
    assert q.get(eid)["status"] == "killed"
