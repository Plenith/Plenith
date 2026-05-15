"""Unit tests for SimulationBot."""
import datetime as dt

class TestSnapshotConsistency:
    def test_same_hour_same_fleet(self, sim_bot):
        t1 = dt.datetime(2026, 5, 11, 14, 0, 0, tzinfo=dt.UTC)
        t2 = dt.datetime(2026, 5, 11, 14, 30, 0, tzinfo=dt.UTC)
        snap1 = sim_bot._snapshot(t1)
        snap2 = sim_bot._snapshot(t2)
        online1 = {s["user"] for s in snap1 if s.get("online")}
        online2 = {s["user"] for s in snap2 if s.get("online")}
        assert online1 == online2

    def test_outside_work_hours_no_one_online(self, sim_bot):
        # 3am UTC — too early for the broadest persona work-hours window
        snap = sim_bot._snapshot(dt.datetime(2026, 5, 11, 3, 0, 0, tzinfo=dt.UTC))
        online = {s["user"] for s in snap if s.get("online")}
        assert online == set()

class TestRecentLogins:
    def test_returns_list_of_dicts(self, sim_bot):
        out = sim_bot.recent_logins(n=5)
        assert isinstance(out, list)
        for r in out:
            assert {"user", "ip", "pty", "start"}.issubset(r.keys())

    def test_returns_at_most_n(self, sim_bot):
        out = sim_bot.recent_logins(n=3)
        assert len(out) <= 3

    def test_newest_first(self, sim_bot):
        out = sim_bot.recent_logins(n=15)
        starts = [r["start"] for r in out]
        assert starts == sorted(starts, reverse=True)

class TestRenderers:
    def test_who_format(self, sim_bot):
        t = dt.datetime(2026, 5, 11, 14, 0, 0, tzinfo=dt.UTC)
        out = sim_bot.who_output(now=t)
        for line in out.strip().split("\n"):
            if not line:
                continue
            assert "pts/" in line
            assert "(" in line and ")" in line  # IP in parens

    def test_uptime_format(self, sim_bot):
        out = sim_bot.uptime_output(now=dt.datetime(2026, 5, 11, 14, 0, 0, tzinfo=dt.UTC))
        assert "up" in out
        assert "load average" in out
        assert "users" in out

    def test_last_includes_reboot(self, sim_bot):
        out = sim_bot.last_output(now=dt.datetime(2026, 5, 11, 14, 0, 0, tzinfo=dt.UTC))
        assert "reboot" in out
        assert "wtmp begins" in out

    def test_w_has_header(self, sim_bot):
        out = sim_bot.w_output(now=dt.datetime(2026, 5, 11, 14, 0, 0, tzinfo=dt.UTC))
        assert "load average" in out
        assert "USER" in out and "TTY" in out
