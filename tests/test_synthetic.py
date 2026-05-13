"""Unit tests for honeytoken + system-file generators."""
import random
import re

from plenith.synthetic import (
    Honeytokens,
    gen_aws_credentials_file,
    gen_passwd_file,
    gen_group_file,
    gen_auth_log_from_logins,
    gen_bash_history,
    gen_openssh_private_key,
    persona_uid,
    persona_gid,
)


class TestAWSCredentials:
    def test_format_matches_real_aws(self):
        body = gen_aws_credentials_file(random.Random("seed"))
        # AWS access key id is "AKIA" + 16 [A-Z0-9]
        m = re.search(r"aws_access_key_id = (AKIA[A-Z0-9]{16})", body)
        assert m, body
        # AWS secret access key is 40 chars base64-style
        m = re.search(r"aws_secret_access_key = ([A-Za-z0-9+/]{40})", body)
        assert m

    def test_includes_default_and_staging(self):
        body = gen_aws_credentials_file(random.Random("seed"))
        assert "[default]" in body
        assert "[staging]" in body

    def test_deterministic_per_seed(self):
        a = gen_aws_credentials_file(random.Random("seed"))
        b = gen_aws_credentials_file(random.Random("seed"))
        assert a == b

    def test_different_seeds_differ(self):
        a = gen_aws_credentials_file(random.Random("seed-a"))
        b = gen_aws_credentials_file(random.Random("seed-b"))
        assert a != b


class TestSSHKey:
    def test_has_begin_and_end_markers(self):
        body = gen_openssh_private_key(random.Random("seed"))
        assert body.startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
        assert "-----END OPENSSH PRIVATE KEY-----" in body

    def test_body_lines_look_base64(self):
        body = gen_openssh_private_key(random.Random("seed"))
        body_lines = [l for l in body.splitlines() if "BEGIN" not in l and "END" not in l]
        for line in body_lines[:-1]:  # last line may have padding
            assert re.match(r"^[A-Za-z0-9+/]+$", line), line


class TestPasswdGroup:
    def test_passwd_includes_root_and_personas(self, personas):
        body = gen_passwd_file(personas)
        assert body.startswith("root:x:0:0:")
        for p in personas:
            uid = persona_uid(p)
            assert f"{p.username}:x:{uid}:" in body

    def test_group_includes_shared_and_persona_primary(self, personas):
        body = gen_group_file(personas)
        # sudo group should list all personas that are in `groups: [..., sudo]`
        sudo_line = next(l for l in body.splitlines() if l.startswith("sudo:"))
        for p in personas:
            if "sudo" in p.groups:
                assert p.username in sudo_line.split(":")[-1]


class TestPersonaUidGid:
    def test_parses_jdoe_uid(self, persona_jdoe):
        assert persona_uid(persona_jdoe) == 1001
        assert persona_gid(persona_jdoe) == 1001

    def test_parses_agarcia_uid(self, persona_agarcia):
        assert persona_uid(persona_agarcia) == 1002

    def test_parses_mwilson_uid(self, persona_mwilson):
        assert persona_uid(persona_mwilson) == 1003


class TestBashHistory:
    def test_uses_persona_pool_when_present(self, persona_agarcia):
        body = gen_bash_history(random.Random("seed"), persona_agarcia)
        # agarcia's pool is kubectl/terraform heavy
        assert "kubectl" in body or "terraform" in body or "helm" in body

    def test_falls_back_to_default_pool(self, persona_jdoe):
        # jdoe persona has NO bash_history_pool — uses default
        body = gen_bash_history(random.Random("seed"), persona_jdoe)
        assert "git" in body or "kubectl" in body  # default pool


class TestHoneytokensRoundTrip:
    def test_same_engagement_id_produces_identical_tokens(self, persona_jdoe):
        ht1 = Honeytokens.generate_for(persona_jdoe, random.Random("engagement-abc"))
        ht2 = Honeytokens.generate_for(persona_jdoe, random.Random("engagement-abc"))
        assert ht1.aws_credentials == ht2.aws_credentials
        assert ht1.ssh_private_key == ht2.ssh_private_key

    def test_different_engagement_ids_differ(self, persona_jdoe):
        ht1 = Honeytokens.generate_for(persona_jdoe, random.Random("a"))
        ht2 = Honeytokens.generate_for(persona_jdoe, random.Random("b"))
        assert ht1.aws_credentials != ht2.aws_credentials


class TestAuthLog:
    def test_emits_pairs_of_lines(self):
        logins = [
            {"user": "jdoe", "ip": "10.10.7.180", "start": __import__("datetime").datetime(2026, 5, 11, 22, 0, 0, tzinfo=__import__("datetime").timezone.utc), "uid": 1001},
        ]
        body = gen_auth_log_from_logins(logins, "corp-app01")
        lines = body.splitlines()
        assert len(lines) == 2  # accepted + session opened
        assert "Accepted publickey for jdoe" in lines[0]
        assert "session opened for user jdoe(uid=1001)" in lines[1]
