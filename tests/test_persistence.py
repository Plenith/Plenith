"""Unit tests for StateStore + cross-session persistence."""
import pytest

from plenith.session import Session

class TestStateStoreBasic:
    def test_missing_returns_none(self, state_store):
        assert state_store.load("1.2.3.4", "anyone") is None

    def test_save_then_load(self, state_store):
        state = {"engagement_id": "abc", "claimed_user": "alice", "source_ip": "1.2.3.4"}
        state_store.save("1.2.3.4", "alice", state)
        back = state_store.load("1.2.3.4", "alice")
        assert back["engagement_id"] == "abc"
        assert "last_seen_at" in back

    def test_save_is_atomic(self, state_store, tmp_path):
        state_store.save("1.1.1.1", "u", {"engagement_id": "a"})
        # No tmp files left behind
        leftover = list((tmp_path / "persistence").glob(".tmp_*"))
        assert leftover == []

    def test_corrupt_file_treated_as_missing(self, state_store, tmp_path):
        path = tmp_path / "persistence" / "1.2.3.4__alice.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{NOT JSON")
        assert state_store.load("1.2.3.4", "alice") is None

class TestEngagementResumption:
    def test_new_session_no_state(self, persona_jdoe, state_store):
        s = Session("jdoe", "127.0.0.1", persona_jdoe, state_store=state_store)
        assert s._restored_from_state is False
        assert s.connection_count == 1

    def test_reconnect_restores_state(self, persona_jdoe, state_store, orchestrator):
        s1 = Session("jdoe", "127.0.0.1", persona_jdoe, state_store=state_store)
        original_eid = s1.engagement_id
        # Save out
        state_store.save("127.0.0.1", "jdoe", s1.to_persistent_state())

        s2 = Session("jdoe", "127.0.0.1", persona_jdoe, state_store=state_store)
        assert s2._restored_from_state is True
        assert s2.engagement_id == original_eid
        assert s2.connection_count == 2

    async def test_vfs_survives_reconnect(self, persona_jdoe, state_store, orchestrator):
        s1 = Session("jdoe", "127.0.0.1", persona_jdoe, state_store=state_store)
        await orchestrator.handle_command(s1, "echo SECRET > /tmp/data.txt")
        state_store.save("127.0.0.1", "jdoe", s1.to_persistent_state())

        s2 = Session("jdoe", "127.0.0.1", persona_jdoe, state_store=state_store)
        body = s2.vfs.read("/tmp/data.txt", cwd=None, home=None)
        assert body == "SECRET\n"

    async def test_cwd_survives_reconnect(self, persona_jdoe, state_store, orchestrator):
        s1 = Session("jdoe", "127.0.0.1", persona_jdoe, state_store=state_store)
        await orchestrator.handle_command(s1, "cd /tmp")
        state_store.save("127.0.0.1", "jdoe", s1.to_persistent_state())
        s2 = Session("jdoe", "127.0.0.1", persona_jdoe, state_store=state_store)
        assert s2.cwd == "/tmp"

    async def test_alerts_do_not_refire_after_reconnect(self, persona_jdoe, state_store, orchestrator):
        s1 = Session("jdoe", "127.0.0.1", persona_jdoe, state_store=state_store)
        await orchestrator.handle_command(s1, "cat ~/.aws/credentials")
        assert "alert_credential_exfil" in [a["action"] for a in s1.actions_taken]
        state_store.save("127.0.0.1", "jdoe", s1.to_persistent_state())

        s2 = Session("jdoe", "127.0.0.1", persona_jdoe, state_store=state_store)
        await orchestrator.handle_command(s2, "cat ~/.aws/credentials")
        assert "alert_credential_exfil" not in [a["action"] for a in s2.actions_taken]

    async def test_new_alert_still_fires_after_reconnect(self, persona_jdoe, state_store, orchestrator):
        s1 = Session("jdoe", "127.0.0.1", persona_jdoe, state_store=state_store)
        await orchestrator.handle_command(s1, "cat ~/.aws/credentials")
        state_store.save("127.0.0.1", "jdoe", s1.to_persistent_state())

        s2 = Session("jdoe", "127.0.0.1", persona_jdoe, state_store=state_store)
        # New alert not previously fired
        await orchestrator.handle_command(s2, "echo k >> ~/.ssh/authorized_keys")
        assert "alert_ssh_persistence" in [a["action"] for a in s2.actions_taken]

class TestKeyIsolation:
    def test_different_ip_gets_separate_engagement(self, persona_jdoe, state_store):
        s1 = Session("jdoe", "1.1.1.1", persona_jdoe, state_store=state_store)
        state_store.save("1.1.1.1", "jdoe", s1.to_persistent_state())

        s2 = Session("jdoe", "2.2.2.2", persona_jdoe, state_store=state_store)
        assert s2._restored_from_state is False
        assert s2.engagement_id != s1.engagement_id

    def test_same_ip_different_user_separate_engagement(self, persona_jdoe, persona_agarcia, state_store):
        s1 = Session("jdoe", "127.0.0.1", persona_jdoe, state_store=state_store)
        state_store.save("127.0.0.1", "jdoe", s1.to_persistent_state())

        s2 = Session("agarcia", "127.0.0.1", persona_agarcia, state_store=state_store)
        assert s2._restored_from_state is False
