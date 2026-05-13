"""Lazy "user simulation" bot.

Computes the apparent presence of other corporate users on the host on
demand. No background tasks, no shared mutable state across processes —
just a deterministic snapshot derived from the current wall-clock time
and the bot's seed.

Why lazy:
- No race conditions or asyncio plumbing in the SSH handler path.
- Deterministic for a given (now, persona) pair — stable enough to be
  consistent within an hour, varied enough that `who`/`w` aren't frozen
  responses an attacker could fingerprint.

What the bot renders:
- `who`   — currently-online users with their pty, login time, source IP.
- `w`     — same plus system load, idle time per session.
- `uptime`— host uptime + users-online + load average.
- `last`  — recent login history including both online users and a
            handful of synthesized historical logins.

The attacker sees these via the orchestrator's handler short-circuit, so
output is instant (no LLM hop) and consistent with whatever `who` already
returned this hour.
"""
import datetime as dt
import hashlib
import random


class SimulationBot:
    def __init__(self, personas, host_start=None):
        # All personas EXCEPT the one currently authenticated as the attacker
        # are candidates for "logged in elsewhere." We don't filter here;
        # callers pass whatever fleet they want simulated.
        self._personas = list(personas)
        # Pretend the host has been up for ~14 days. Static for the
        # process lifetime, so `uptime` increases monotonically.
        self._boot_time = (host_start or dt.datetime.now(dt.timezone.utc)) - dt.timedelta(days=14)

    # --- public renderers --------------------------------------------------

    def who_output(self, now=None):
        snap = self._snapshot(now or _utcnow())
        lines = []
        for s in snap:
            if not s["online"]:
                continue
            ts = s["since"].strftime("%Y-%m-%d %H:%M")
            lines.append(
                f"{s['user']:<8} pts/{s['pty']}        {ts} ({s['ip']})"
            )
        return "\n".join(lines) + ("\n" if lines else "")

    def w_output(self, now=None):
        now = now or _utcnow()
        snap = self._snapshot(now)
        online = [s for s in snap if s["online"]]
        header = (
            f" {now.strftime('%H:%M:%S')} up {self._uptime_str(now)},  "
            f"{len(online)} users,  load average: {self._load_avg(now)}\n"
            "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
        )
        body = []
        for s in online:
            body.append(
                f"{s['user']:<8} pts/{s['pty']}    {s['ip']:<15}  "
                f"{s['since'].strftime('%H:%M')}    "
                f"{self._idle_str(s['since'], now):<6} 0.05s  0.02s {s['what']}"
            )
        return header + "\n".join(body) + ("\n" if body else "")

    def uptime_output(self, now=None):
        now = now or _utcnow()
        snap = self._snapshot(now)
        online = sum(1 for s in snap if s["online"])
        return (
            f" {now.strftime('%H:%M:%S')} up {self._uptime_str(now)},  "
            f"{online} users,  load average: {self._load_avg(now)}\n"
        )

    def recent_logins(self, now=None, n=15):
        """Structured list of recent login events.

        Returns a list of dicts: {user, ip, pty, start, duration}.
        `duration` is None for currently-online sessions. Newest first.
        """
        now = now or _utcnow()
        snap = self._snapshot(now)
        entries = []
        for s in [x for x in snap if x["online"]]:
            entries.append({
                "user": s["user"], "pty": s["pty"], "ip": s["ip"],
                "start": s["since"], "duration": None,
            })
        for p in self._personas:
            for days_back in range(1, 6):
                day = (now - dt.timedelta(days=days_back)).date()
                day_rng = _persona_rng(p.username, day.isoformat() + ":last")
                if day_rng.random() > 0.4:
                    h = day_rng.randint(8, 18)
                    m = day_rng.randint(0, 59)
                    start = dt.datetime.combine(
                        day, dt.time(h, m), tzinfo=dt.timezone.utc
                    )
                    dur_mins = day_rng.randint(15, 240)
                    entries.append({
                        "user": p.username,
                        "pty": day_rng.randint(0, 4),
                        "ip": _office_ip(day_rng),
                        "start": start,
                        "duration": dt.timedelta(minutes=dur_mins),
                    })
        entries.sort(key=lambda e: e["start"], reverse=True)
        return entries[:n]

    def last_output(self, now=None, n=15):
        now = now or _utcnow()
        entries = self.recent_logins(now, n=n)
        lines = []
        for e in entries:
            login_s = e["start"].strftime("%a %b %d %H:%M")
            if e["duration"] is None:
                tail = "   still logged in"
            else:
                end = e["start"] + e["duration"]
                hh, mm = divmod(int(e["duration"].total_seconds() // 60), 60)
                tail = f" - {end.strftime('%H:%M')}  ({hh:02d}:{mm:02d})"
            lines.append(
                f"{e['user']:<8} pts/{e['pty']}        {e['ip']:<15}  "
                f"{login_s}{tail}"
            )
        # Footer matches real `last` output style.
        boot_line = (
            f"reboot   system boot  5.15.0-105       "
            f"{self._boot_time.strftime('%a %b %d %H:%M')}   still running"
        )
        lines.append(boot_line)
        lines.append("")
        lines.append(f"wtmp begins {self._boot_time.strftime('%a %b %d %H:%M:%S %Y')}")
        return "\n".join(lines) + "\n"

    # --- internals ---------------------------------------------------------

    def _snapshot(self, now):
        """Per-persona online/offline state at `now`. Stable within an hour."""
        states = []
        for p in self._personas:
            seed_key = f"{p.username}:{now.date().isoformat()}:{now.hour}"
            rng = _persona_rng(p.username, seed_key)
            hour = now.hour
            # Persona work-hours mask, with per-persona jitter. Generous
            # window (07:00–23:00 UTC) so the demo is alive across most
            # of a working day on either coast of the US/EU, with the
            # individual persona's preference narrowing it.
            base_seed = int(hashlib.sha256(p.username.encode()).hexdigest()[:8], 16)
            base_rng = random.Random(base_seed)
            work_start = base_rng.randint(6, 10)
            work_end = base_rng.randint(20, 23)
            in_hours = work_start <= hour < work_end
            online = in_hours and rng.random() > 0.15  # ~85% online during work hours
            if not online:
                states.append({"user": p.username, "online": False})
                continue
            # Logged in some minutes ago, current hour.
            mins_ago = rng.randint(5, 55)
            since = now.replace(minute=0, second=0, microsecond=0) + dt.timedelta(
                minutes=60 - mins_ago
            )
            # If `since` ended up in the future (close to hour boundary), pull back.
            if since > now:
                since = now - dt.timedelta(minutes=mins_ago)
            states.append({
                "user": p.username,
                "online": True,
                "pty": rng.randint(0, 4),
                "ip": _office_ip(rng),
                "since": since,
                "what": rng.choice([
                    "-bash", "vim", "kubectl", "ssh", "tail -f",
                    "python", "tmux", "htop", "less",
                ]),
            })
        return states

    def _idle_str(self, since, now):
        idle = now - since
        secs = int(idle.total_seconds())
        if secs < 60:
            return f"{secs}.00s"
        mins, secs = divmod(secs, 60)
        if mins < 60:
            return f"{mins}:{secs:02d}"
        hrs, mins = divmod(mins, 60)
        return f"{hrs}:{mins:02d}m"

    def _uptime_str(self, now):
        delta = now - self._boot_time
        days = delta.days
        hours, rem = divmod(int(delta.seconds), 3600)
        mins, _ = divmod(rem, 60)
        if days > 0:
            return f"{days} days, {hours:02d}:{mins:02d}"
        return f"{hours:02d}:{mins:02d}"

    def _load_avg(self, now):
        # Slowly-varying load avg seeded per hour.
        rng = random.Random(int(hashlib.sha256(
            (now.date().isoformat() + str(now.hour)).encode()
        ).hexdigest()[:8], 16))
        return f"{rng.uniform(0.05, 0.45):.2f}, {rng.uniform(0.08, 0.40):.2f}, {rng.uniform(0.06, 0.35):.2f}"


# --- module helpers ----------------------------------------------------------

def _utcnow():
    return dt.datetime.now(dt.timezone.utc)


def _persona_rng(username, suffix):
    """Deterministic Random for (username, suffix). Stable for the same key."""
    h = hashlib.sha256(f"{username}:{suffix}".encode()).hexdigest()
    return random.Random(int(h[:16], 16))


def _office_ip(rng):
    return f"10.10.{rng.randint(1, 20)}.{rng.randint(2, 254)}"
