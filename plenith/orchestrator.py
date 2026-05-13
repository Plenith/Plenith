import re

from .heuristics import decide_action
from .policy import build_policy, HeuristicPolicy
from .responses import execute as execute_response


# Strip leading/trailing markdown code fences if the model ignored the
# "no code fences" instruction in the system prompt. Common with Qwen.
_FENCE_RE = re.compile(r"^\s*```[^\n]*\n?(?P<body>.*?)\n?```\s*$", re.DOTALL)


def _clean_llm_output(text):
    if not text:
        return text
    m = _FENCE_RE.match(text)
    if m:
        text = m.group("body")
    # Strip occasional "Output:" / "Result:" prefixes a chatty model adds.
    for prefix in ("Output:\n", "Output: ", "Result:\n", "Result: "):
        if text.startswith(prefix):
            text = text[len(prefix):]
            break
    return text


SYSTEM_PROMPT_TEMPLATE = """You are simulating a Linux bash shell on a corporate server.

Host: {hostname} (Ubuntu 22.04.4 LTS, kernel 5.15.0)
User: {user} ({title}, {department})
Current directory: {cwd}
User's home contains: {home_listing}
Notes about this user: {notes}

{attacker_state_block}
GROUND TRUTH — these files exist on disk with EXACTLY these contents.
If the user reads, greps, or otherwise references any of them, return the
exact bytes shown — never invent alternatives, never use placeholders like
"xxxx" or "your_key_here". Real credentials follow real format conventions
(AWS access keys start with AKIA, OpenSSH keys are base64 blocks between
BEGIN/END markers, etc.).

{ground_truth_block}

CRITICAL RULES:
- Output ONLY the raw stdout/stderr of the command, nothing else.
- No markdown, no code fences, no commentary, no explanations.
- If the command would produce no output, return an empty string.
- If the command would error, return a realistic Linux error message.
- Be consistent with the persona and previous commands in this session.
- Never break character. You are a shell, not a chatbot.
- Keep output realistic in size: most commands produce <30 lines.
- Never use placeholder values like "xxxxx" or "your_key_here" — invent
  realistic-looking fake values that match the real format of the credential type.
"""


# Commands that should return a known file body directly, no LLM hop.
# Matches `cat path`, `head path`, `head -n 5 path`, `head -5 path`, `tail -3 path`, etc.
_FILE_READ_RE = re.compile(
    r"^\s*(?:cat|less|more|head|tail|bat|nl)"
    r"(?:\s+-n?\s*\d+)?"      # optional `-5`, `-n 5`, `-n5`
    r"(?:\s+-[a-zA-Z]+)*"     # other short flags
    r"\s+(?P<path>[~/]?[\w./_-]+)\s*$"
)

# Write redirects:
#   echo "content" > file
#   echo content > file
#   echo > file              (truncate)
#   echo "content" >> file   (append)
#   echo -n "content" > file
_ECHO_REDIRECT_RE = re.compile(
    r"^\s*echo\s+"
    r"(?P<nflag>-n\s+)?"
    r"(?:\"(?P<dquoted>[^\"]*)\"|'(?P<squoted>[^']*)'|(?P<bare>[^>]*?))"
    r"\s*(?P<op>>>|>)\s*(?P<path>\S+)\s*$"
)

# Bare redirect: `> file` (truncate to empty)
_TRUNCATE_RE = re.compile(r"^\s*>\s*(?P<path>\S+)\s*$")

# `touch path` (single arg)
_TOUCH_RE = re.compile(r"^\s*touch\s+(?:[-~‐–—−][a-zA-Z]+\s+)*(?P<path>\S+)\s*$")

# `rm [-flags] path`. Multi-target not handled in MVP.
_RM_RE = re.compile(r"^\s*rm\s+(?:[-~‐–—−][a-zA-Z]+\s+)*(?P<path>\S+)\s*$")

# Dash-introducer class: the user's terminal / clipboard / IME can mangle
# a leading "-" into a tilde or a unicode dash. We accept any of:
#   -  hyphen-minus    U+002D
#   ~  tilde           U+007E  (common typo: shift-` instead of dash)
#   – en-dash             (rich-text auto-replace)
#   — em-dash             (rich-text auto-replace)
#   − minus              (math autocorrect)
#   ‐ unicode hyphen
# A real bash would reject `~name`, but the attacker pattern is identical
# enough that we can safely treat it as a synonym.
_D = r"[-~‐–—−]"


# `cp [flags] src dst` and `mv [flags] src dst`. Two-arg form only.
_CP_RE = re.compile(r"^\s*cp\s+(?P<flags>(?:" + _D + r"[a-zA-Z]+\s+)*)(?P<src>\S+)\s+(?P<dst>\S+)\s*$")
_MV_RE = re.compile(r"^\s*mv\s+(?P<flags>(?:" + _D + r"[a-zA-Z]+\s+)*)(?P<src>\S+)\s+(?P<dst>\S+)\s*$")

# `mkdir [-p] path` and `rmdir path` (single arg).
_MKDIR_RE = re.compile(r"^\s*mkdir\s+(?:(?P<pflag>" + _D + r"p)\s+)?(?P<path>\S+)\s*$")
_RMDIR_RE = re.compile(r"^\s*rmdir\s+(?P<path>\S+)\s*$")

# `find ROOT [-name PAT] [-type t]`. We capture the root and a few
# common predicates; everything else falls through to the LLM.
_FIND_NAME_RE = re.compile(_D + r"name\s+(?P<name>\"[^\"]+\"|'[^']+'|\S+)")
_FIND_TYPE_RE = re.compile(_D + r"type\s+(?P<t>[fd])")
_FIND_RE = re.compile(r"^\s*find\s+(?P<root>\S+)(?P<rest>(?:\s+\S+)*)\s*$")

# `grep [flags] PATTERN TARGET`. Flags we honor: -r/-R/-i/-l/-n.
_GREP_RE = re.compile(
    r"^\s*grep\s+(?P<flags>(?:" + _D + r"[a-zA-Z]+\s+)*)"
    r"(?P<pattern>\"[^\"]+\"|'[^']+'|\S+)"
    r"\s+(?P<target>\S+)\s*$"
)

# Process-listing patterns: `ps`, `ps aux`, `ps -ef`, `ps auxf`, etc.
_PS_RE = re.compile(r"^\s*ps(?:\s+(?P<flags>[a-zA-Z" + r"\-~‐–—−" + r"]+))?\s*$")

# Listening-socket patterns: `netstat -tlnp`, `ss -tlnp`, plain `netstat`/`ss`.
_NETSTAT_RE = re.compile(r"^\s*(?P<bin>netstat|ss)(?:\s+(?P<flags>[a-zA-Z" + r"\-~‐–—−" + r"]+))?\s*$")

# `awk [-F SEP] '{ACTION}' FILE` — scoped to `{print $N}` or `{print $N, $M}` actions.
_AWK_RE = re.compile(
    r"^\s*awk\s+"
    r"(?:" + _D + r"F\s*(?P<sep>\S+)\s+)?"
    r"(?P<prog>'[^']*'|\"[^\"]*\")\s+"
    r"(?P<target>\S+)\s*$"
)

# `sed [-n] 'PROGRAM' FILE` — scoped to `s/X/Y/g` and `N,Mp` programs.
_SED_RE = re.compile(
    r"^\s*sed\s+"
    r"(?P<flags>(?:" + _D + r"[a-zA-Z]+\s+)*)"
    r"(?P<prog>'[^']*'|\"[^\"]*\")\s+"
    r"(?P<target>\S+)\s*$"
)

# `ls`, `ls -la`, `ls -la /path`, `ll`. Multi-target not handled. Flag
# introducer is the dash-class so a clipboard-mangled `~la` still works.
# Path: a tilde-expanded path (~ or ~/...) is OK as a path; otherwise
# the first character must not be in the dash class (else it would have
# been parsed as a flag).
_LS_RE = re.compile(
    r"^\s*(?P<bin>ls|ll)"
    r"(?P<flags>(?:\s+[-~‐–—−][a-zA-Z]+)*)"
    r"(?:\s+(?P<path>~/?\S*|[^-~‐–—−\s][\S]*))?"
    r"\s*$"
)

# File paths whose contents are large/binary-ish and should NOT be embedded in
# the LLM system prompt (saves tokens + latency). Direct reads still work via
# the short-circuit; we just don't tell the LLM what's inside.
_SKIP_IN_LLM_PROMPT_SUFFIXES = ("/.ssh/id_rsa", "/.ssh/id_rsa.pub")


# Keywords that indicate the LLM might need the planted-files context. For
# anything else (sudo, ls of a real dir, network commands), skip the bulky
# ground-truth block — direct reads of planted files are already handled by
# the file-read short-circuit.
_GT_KEYWORDS = (
    "aws", "ssh", "git", ".credentials", ".config", "history",
    "grep", "awk", "sed", "cut", "find", "strings", "xxd",
    "kube", "kubectl", "secret", "token", "rsa", "id_",
    # Fleet / system files
    "passwd", "group", "shadow", "/etc/", "/var/log",
    "auth.log", "who", "uid", "users", "agarcia", "jdoe",
)


def _command_needs_ground_truth(cmd):
    c = cmd.lower()
    return any(kw in c for kw in _GT_KEYWORDS)


class Orchestrator:
    def __init__(self, llm_client, cache, sim_bot=None, policy=None, rotator=None):
        self.llm = llm_client
        self.cache = cache
        self.sim_bot = sim_bot
        # V2 indirection: the policy is the strategic-action selector.
        # Default = HeuristicPolicy, which wraps heuristics.decide_action
        # 1:1 for zero behavior change. To swap in an RL policy later,
        # construct an Orchestrator with policy=RLPolicyStub(...) (or
        # build_policy({"engine": "rl"})).
        self.policy = policy if policy is not None else HeuristicPolicy()
        # Content rotator — when provided, propagated into every Session
        # the orchestrator builds so executors can plant deployment-scoped
        # decoy content. None = static-defaults backward-compat mode.
        self.rotator = rotator

    async def handle_command(self, session, cmd):
        from .tracing import command_span
        from .plugins import run_detectors
        # Span wraps the entire per-command lifecycle (update_observations
        # + heuristic passes + dispatch). When OTel isn't installed this
        # is a no-op — zero performance cost.
        with command_span(session, cmd, source="pending"):
            session.update_observations(cmd)

            # Plugin detectors get to add their own observations on top
            # of the built-in ones. Each runs in its own try/except so a
            # bad plugin can't break the session — see plenith.plugins.
            run_detectors(session, cmd)

            # First heuristic pass — string-based observations (sudo, mysql, etc.).
            self._maybe_record_action(session, cmd)

            body, source = await self._dispatch(session, cmd.strip(),
                                                  original_cmd=cmd)

            # Second heuristic pass — VFS-event observations registered during
            # _dispatch. Idempotent: each rule self-disables once it fires.
            self._maybe_record_action(session, cmd)
            return body, source

    def _maybe_record_action(self, session, cmd):
        # Each rule self-disables when it fires (via its `alerted_*` /
        # `planted_*` flag), so we can keep calling decide_action until
        # nothing remains. This lets multiple independent observations
        # produce their alerts on the same command (e.g. reading a
        # planted decoy that's also a credential fires both
        # alert_credential_exfil and alert_decoy_swallowed).
        for _ in range(20):  # safety cap against pathological loops
            action = self.policy.decide(session)
            if not action:
                break
            session.actions_taken.append({
                "ts_offset_s": round(session.time_elapsed, 2),
                "triggered_by": cmd,
                **action,
            })
            # Apply any real side effects the action has (e.g. plant a
            # decoy file in the VFS). Alerts without an executor are no-ops.
            execute_response(action, session)
            # Plus any responder plugins registered for this action name
            # (e.g. push a block-rule to the edge firewall on
            # alert_credential_exfil). Plugin responders are additive —
            # they don't replace the built-in side effect.
            from .plugins import run_responders
            run_responders(session, action)

    async def _dispatch(self, session, stripped, original_cmd):
        # Write/mutate builtins (echo >, rm, touch, mv, cp, mkdir, rmdir).
        # Takes precedence — `echo "x" > /tmp/foo` must NOT fall through to
        # the bare-echo cache.
        result = self._apply_write_ops(stripped, session)
        if result is not None:
            return result

        # cwd updates
        if stripped.startswith("cd "):
            new_cwd = self._resolve_cd(stripped[3:].strip(), session.cwd, session.persona)
            session.cwd = new_cwd
            return "", "builtin"
        if stripped == "cd":
            session.cwd = session.persona.home
            return "", "builtin"

        # `ls` (with optional flags + path) — VFS-driven so attacker writes
        # show up. Falls through to LLM for paths the VFS knows nothing about.
        ls_body = self._ls_handler(stripped, session)
        if ls_body is not None:
            return ls_body, "ls"

        # Presence commands (who / w / uptime / last) — bot-rendered.
        presence_body = self._presence_handler(stripped, session)
        if presence_body is not None:
            return presence_body, "sim-bot"

        # Search builtins (find / grep). These are the most attacker-relevant
        # commands after `cat` and `ls`, and their output drives the
        # credential-search heuristic.
        search_result = self._search_handler(stripped, session)
        if search_result is not None:
            return search_result

        # System-recon builtins: ps / netstat / ss. Bot-rendered so they
        # stay consistent with `who` / `last` / `/var/log/auth.log`.
        sysrec = self._sysrecon_handler(stripped, session)
        if sysrec is not None:
            return sysrec

        # Text-processing builtins: awk / sed. Scoped to the common forms
        # attackers use to extract fields from /etc/passwd, /etc/shadow,
        # bash history, etc.
        textproc = self._textproc_handler(stripped, session)
        if textproc is not None:
            return textproc

        # Read short-circuit. Returns current VFS contents — both honeytokens
        # AND anything the attacker has written.
        body, source = self._read_vfs(stripped, session)
        if body is not None:
            return body, source

        # Static / dynamic cached responses (whoami, pwd, date, ...).
        cached = self.cache.lookup(original_cmd, session.persona, session.cwd)
        if cached is not None:
            elevated = rewrite_cached_response(original_cmd, cached, session)
            if elevated is not cached:
                return elevated, "cache+elevated"
            return cached, "cache"

        # Fall through to the LLM.
        try:
            llm_output = await self._call_llm(session, original_cmd)
            return llm_output, "llm"
        except Exception as exc:
            return f"bash: {original_cmd.split()[0] if original_cmd.strip() else 'command'}: {exc}\n", "error"

    # --- read / write op handlers -----------------------------------------

    def _apply_write_ops(self, cmd, session):
        """If `cmd` is a recognized VFS-mutating builtin, apply it and
        return (body, source_tag). Otherwise return None.
        """
        home = session.persona.home
        cwd = session.cwd

        m = _ECHO_REDIRECT_RE.match(cmd)
        if m:
            path = m.group("path")
            if m.group("dquoted") is not None:
                payload = m.group("dquoted")
            elif m.group("squoted") is not None:
                payload = m.group("squoted")
            else:
                payload = (m.group("bare") or "").strip()
            no_newline = m.group("nflag") is not None
            content = payload if no_newline else payload + "\n"
            append = m.group("op") == ">>"
            session.vfs.write(path, content, cwd=cwd, home=home, append=append)
            session.observe_vfs_event("write", path)
            return "", "vfs-write"

        m = _TRUNCATE_RE.match(cmd)
        if m:
            path = m.group("path")
            session.vfs.write(path, "", cwd=cwd, home=home, append=False)
            session.observe_vfs_event("write", path)
            return "", "vfs-truncate"

        m = _TOUCH_RE.match(cmd)
        if m:
            path = m.group("path")
            session.vfs.touch(path, cwd=cwd, home=home)
            session.observe_vfs_event("touch", path)
            return "", "vfs-touch"

        m = _RM_RE.match(cmd)
        if m:
            path = m.group("path")
            session.vfs.unlink(path, cwd=cwd, home=home)
            session.observe_vfs_event("unlink", path)
            return "", "vfs-rm"

        m = _CP_RE.match(cmd)
        if m:
            src, dst = m.group("src"), m.group("dst")
            body = session.vfs.read(src, cwd=cwd, home=home)
            if body is None:
                return f"cp: cannot stat '{src}': No such file or directory\n", "error"
            session.vfs.write(dst, body, cwd=cwd, home=home, append=False)
            # The attacker has read source + written dest. Both events.
            session.observe_vfs_event("read", src)
            session.observe_vfs_event("write", dst)
            return "", "vfs-cp"

        m = _MV_RE.match(cmd)
        if m:
            src, dst = m.group("src"), m.group("dst")
            body = session.vfs.read(src, cwd=cwd, home=home)
            if body is None:
                return f"mv: cannot stat '{src}': No such file or directory\n", "error"
            session.vfs.write(dst, body, cwd=cwd, home=home, append=False)
            session.vfs.unlink(src, cwd=cwd, home=home)
            session.observe_vfs_event("read", src)
            session.observe_vfs_event("write", dst)
            session.observe_vfs_event("unlink", src)
            return "", "vfs-mv"

        m = _MKDIR_RE.match(cmd)
        if m:
            path = m.group("path")
            with_p = m.group("pflag") is not None
            keep_path = path.rstrip("/") + "/.keep"
            # If a file already exists at this path, real mkdir errors.
            if session.vfs.exists(path, cwd=cwd, home=home) and not with_p:
                return f"mkdir: cannot create directory '{path}': File exists\n", "error"
            session.vfs.write(keep_path, "", cwd=cwd, home=home, append=False)
            session.observe_vfs_event("write", keep_path)
            return "", "vfs-mkdir"

        m = _RMDIR_RE.match(cmd)
        if m:
            path = m.group("path")
            canon = session.vfs.canonical_path(path, cwd=cwd, home=home)
            files, dirs = session.vfs.list_directory_typed(path, cwd=cwd, home=home)
            non_keep_files = [f for f in files if f != ".keep"]
            if non_keep_files or dirs:
                return f"rmdir: failed to remove '{path}': Directory not empty\n", "error"
            # Drop the .keep placeholder if any (this is how mkdir tracks empties).
            if ".keep" in files:
                session.vfs.unlink(f"{canon}/.keep", cwd=None, home=None)
            return "", "vfs-rmdir"

        return None

    def _search_handler(self, cmd, session):
        """Render `find ROOT [-name PAT] [-type t]` or `grep [-r] PAT TARGET`
        from current VFS state, and notify the session for the credential-
        search heuristic.

        Returns (body, source) or None.
        """
        home = session.persona.home
        cwd = session.cwd

        m = _FIND_RE.match(cmd)
        if m:
            return self._handle_find(m, session)

        m = _GREP_RE.match(cmd)
        if m:
            return self._handle_grep(m, session)

        return None

    def _sysrecon_handler(self, cmd, session):
        """Render `ps`, `ps aux`, `netstat -tlnp`, `ss -tlnp` from the sim
        bot's view of who's online. Output stays consistent with `who`/`w`
        so the deception holds across surfaces.
        """
        m = _PS_RE.match(cmd)
        if m:
            return self._render_ps(m, session), "sim-bot"
        m = _NETSTAT_RE.match(cmd)
        if m:
            return self._render_netstat(m, session), "sim-bot"
        return None

    def _render_ps(self, m, session):
        flags = (m.group("flags") or "").lower()
        long_form = any(c in flags for c in "axuef")
        # Pull online users from the bot if available
        online_users = []
        if self.sim_bot is not None:
            for s in self.sim_bot._snapshot(_utcnow()):
                if s.get("online"):
                    online_users.append(s)
        # Always include the persona running this session.
        me_user = session.persona.username
        # Build a plausible process list. Stable per-session-id seed so a
        # second `ps` shortly after returns near-identical output.
        import hashlib
        seed = int(hashlib.sha256(session.engagement_id.encode()).hexdigest()[:8], 16)
        import random as _r
        rng = _r.Random(seed)
        rows = []
        # System processes
        rows.append(("root", 1, 0.0, 0.1, 169108, 12424, "?", "Ss", "Apr01", "0:14", "/sbin/init"))
        rows.append(("root", 2, 0.0, 0.0, 0, 0, "?", "S", "Apr01", "0:00", "[kthreadd]"))
        rows.append(("root", 412, 0.0, 0.2, 86120, 17592, "?", "Ss", "Apr01", "0:05", "/lib/systemd/systemd-journald"))
        rows.append(("root", 521, 0.0, 0.1, 8472, 5320, "?", "Ss", "Apr01", "0:02", "/usr/sbin/cron -f"))
        rows.append(("root", 612, 0.0, 0.3, 15812, 9128, "?", "Ss", "Apr01", "0:08", "/usr/sbin/sshd -D"))
        rows.append(("systemd+", 738, 0.0, 0.2, 90644, 7080, "?", "Ssl", "Apr01", "0:03", "/lib/systemd/systemd-resolved"))
        rows.append(("root", 1102, 0.0, 0.1, 5712, 4128, "?", "S", "Apr01", "0:01", "/usr/sbin/cron"))
        rows.append(("www-data", 1452, 0.0, 0.2, 14528, 7416, "?", "S", "Apr02", "0:03", "nginx: worker process"))
        # Per-online-user processes
        for u in online_users:
            uname = u["user"]
            base_pid = 2000 + rng.randint(0, 5000)
            rows.append((uname, base_pid, 0.0, 0.1, 14536, 6212, f"pts/{u['pty']}", "Ss", u["since"].strftime("%H:%M"), "0:00", "-bash"))
            what = u.get("what", "")
            if what and what != "-bash":
                rows.append((uname, base_pid + rng.randint(1, 50), 0.1, 0.4, 28412, 14008, f"pts/{u['pty']}", "S+", u["since"].strftime("%H:%M"), "0:01", what))
        # And the current attacker shell
        cur_pty = "pts/0"
        rows.append((me_user, 5021, 0.0, 0.1, 14536, 6240, cur_pty, "Ss", "12:00", "0:00", "-bash"))
        rows.append((me_user, 5034, 0.0, 0.1, 8328, 3120, cur_pty, "R+", "12:00", "0:00", "ps " + (flags or "")))

        if not long_form:
            # Short form: PID TTY TIME CMD
            lines = ["  PID TTY          TIME CMD"]
            for r in rows:
                user, pid, cpu, mem, vsz, rss, tty, st, start, t, cmd = r
                if tty == "?":
                    continue
                lines.append(f"{pid:>5} {tty:<8}  {t:>8} {cmd}")
            return "\n".join(lines) + "\n"

        # Long form (ps aux / -ef)
        lines = ["USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"]
        for r in rows:
            user, pid, cpu, mem, vsz, rss, tty, st, start, t, cmd = r
            lines.append(f"{user:<10}{pid:>5} {cpu:>4} {mem:>4} {vsz:>6} {rss:>5} {tty:<8} {st:<4} {start:<7} {t:>4} {cmd}")
        return "\n".join(lines) + "\n"

    def _render_netstat(self, m, session):
        flags = (m.group("flags") or "").lower()
        is_ss = m.group("bin") == "ss"
        # Standard listening-socket set for a corporate Ubuntu host.
        rows = [
            ("tcp",  "0.0.0.0:22",   "0.0.0.0:*",        "LISTEN", "612/sshd"),
            ("tcp",  "127.0.0.1:25", "0.0.0.0:*",        "LISTEN", "892/master"),
            ("tcp",  "0.0.0.0:80",   "0.0.0.0:*",        "LISTEN", "1452/nginx: master"),
            ("tcp",  "0.0.0.0:443",  "0.0.0.0:*",        "LISTEN", "1452/nginx: master"),
            ("tcp",  "127.0.0.1:3306", "0.0.0.0:*",      "LISTEN", "2104/mysqld"),
            ("tcp",  "127.0.0.1:6379", "0.0.0.0:*",      "LISTEN", "2240/redis-server"),
            ("tcp6", ":::22",        ":::*",             "LISTEN", "612/sshd"),
            ("tcp6", ":::80",        ":::*",             "LISTEN", "1452/nginx: master"),
            ("tcp6", ":::443",       ":::*",             "LISTEN", "1452/nginx: master"),
            ("udp",  "127.0.0.53:53", "0.0.0.0:*",       "",      "738/systemd-resolve"),
            ("udp",  "0.0.0.0:68",   "0.0.0.0:*",        "",       "812/systemd-network"),
        ]
        # Filter by tcp/udp flag selections
        want_tcp = "t" in flags or not ("u" in flags)
        want_udp = "u" in flags or not ("t" in flags)
        show_program = "p" in flags
        numeric = "n" in flags
        listen_only = "l" in flags

        if is_ss:
            hdr = "State      Recv-Q  Send-Q          Local Address:Port           Peer Address:Port"
            lines = [hdr]
            for proto, local, peer, state, prog in rows:
                if state == "LISTEN" and not listen_only and "a" not in flags:
                    pass  # ss with no flags shows all sockets; for MVP keep all
                if proto.startswith("tcp") and not want_tcp:
                    continue
                if proto == "udp" and not want_udp:
                    continue
                st = state or "UNCONN"
                lines.append(f"{st:<10} 0       0         {local:<28} {peer}")
            if show_program:
                lines.append("")
                lines.append("Process names: see /proc/PID/cmdline.")
            return "\n".join(lines) + "\n"

        hdr = "Active Internet connections (only servers)"
        cols = "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name"
        lines = [hdr, cols]
        for proto, local, peer, state, prog in rows:
            if proto.startswith("tcp") and not want_tcp:
                continue
            if proto == "udp" and not want_udp:
                continue
            st = state or ""
            prog_col = prog if show_program else "-"
            lines.append(f"{proto:<5}     0      0 {local:<22} {peer:<22} {st:<11} {prog_col}")
        return "\n".join(lines) + "\n"

    def _textproc_handler(self, cmd, session):
        """Render scoped `awk '{print $N}' FILE` and `sed [-n] 'PROG' FILE`
        against the VFS. Anything more exotic falls through to the LLM.
        """
        m = _AWK_RE.match(cmd)
        if m:
            return self._render_awk(m, session)
        m = _SED_RE.match(cmd)
        if m:
            return self._render_sed(m, session)
        return None

    def _render_awk(self, m, session):
        prog = _strip_quotes(m.group("prog"))
        sep = m.group("sep") or None
        target = m.group("target")
        body = session.vfs.read(target, cwd=session.cwd, home=session.persona.home)
        if body is None:
            return None  # let LLM handle / produce a "No such file" via fallback
        session.observe_vfs_event("read", target)
        # Scope: support `{print $N}` and `{print $N, $M, ...}`.
        m2 = re.match(r"^\s*\{\s*print\s+(?P<fields>[^}]+?)\s*\}\s*$", prog)
        if not m2:
            return None  # unsupported awk program — let LLM try
        # Parse field list: $1, $2, NF, etc.
        field_tokens = [t.strip() for t in m2.group("fields").split(",")]
        out_lines = []
        for line in body.splitlines():
            cols = line.split(sep) if sep else line.split()
            pieces = []
            for tok in field_tokens:
                if tok == "$0":
                    pieces.append(line)
                elif tok.startswith("$"):
                    try:
                        idx = int(tok[1:])
                        if idx == 0:
                            pieces.append(line)
                        elif 1 <= idx <= len(cols):
                            pieces.append(cols[idx - 1])
                        else:
                            pieces.append("")
                    except ValueError:
                        pieces.append("")
                elif tok == "NF":
                    pieces.append(str(len(cols)))
                else:
                    # Literal string token (drop quotes if present)
                    pieces.append(_strip_quotes(tok))
            out_lines.append(" ".join(pieces))
        return ("\n".join(out_lines) + "\n") if out_lines else "", "awk"

    def _render_sed(self, m, session):
        flags = (m.group("flags") or "").strip()
        flag_chars = _flag_chars_from(flags)
        quiet = "n" in flag_chars
        prog = _strip_quotes(m.group("prog"))
        target = m.group("target")
        body = session.vfs.read(target, cwd=session.cwd, home=session.persona.home)
        if body is None:
            return None
        session.observe_vfs_event("read", target)

        # Range-print: 'N,Mp' or 'Np'
        m2 = re.match(r"^\s*(\d+)(?:,(\d+))?\s*p\s*$", prog)
        if m2:
            start = int(m2.group(1))
            end = int(m2.group(2)) if m2.group(2) else start
            lines = body.splitlines()
            slice_lines = lines[max(0, start - 1):end]
            if quiet:
                return ("\n".join(slice_lines) + "\n") if slice_lines else "", "sed"
            # Default: print everything, doubling the matched range. Real sed
            # behavior; for MVP, render the slice once.
            return ("\n".join(slice_lines) + "\n") if slice_lines else "", "sed"

        # Substitute: 's/PAT/REPL/flags'
        m3 = re.match(r"^\s*s([/|@#])(?P<pat>(?:\\.|[^\\])+?)\1(?P<repl>(?:\\.|[^\\])*?)\1(?P<flags>[gIip0-9]*)\s*$", prog)
        if m3:
            pat = m3.group("pat")
            repl = m3.group("repl").replace("\\&", "&")  # not perfect, MVP-grade
            flagstr = m3.group("flags") or ""
            re_flags = re.IGNORECASE if "I" in flagstr or "i" in flagstr else 0
            count = 0 if "g" in flagstr else 1
            try:
                rx = re.compile(pat, re_flags)
            except re.error:
                return f"sed: invalid pattern: {pat}\n", "error"
            out = []
            for line in body.splitlines():
                out.append(rx.sub(repl.replace("\\1", r"\1"), line, count=count))
            return ("\n".join(out) + "\n") if out else "", "sed"

        return None  # unsupported sed program — fall through

    def _handle_find(self, m, session):
        root = m.group("root")
        rest = m.group("rest") or ""
        name_pat = None
        type_filter = None
        m_name = _FIND_NAME_RE.search(rest)
        if m_name:
            name_pat = _strip_quotes(m_name.group("name"))
        m_type = _FIND_TYPE_RE.search(rest)
        if m_type:
            type_filter = m_type.group("t")

        session.observe_search_event(name_pattern=name_pat)

        files, dirs = self._traverse(root, session)
        results = []
        # Include the root itself (real find lists it as one of the entries
        # when no -mindepth is set).
        canon_root = session.vfs.canonical_path(root, cwd=session.cwd, home=session.persona.home)
        if type_filter != "f":
            results.append(canon_root)
        for path in sorted(files):
            name = path.rsplit("/", 1)[-1]
            if name == ".keep":
                continue
            if name_pat and not _fnmatch(name, name_pat):
                continue
            if type_filter == "d":
                continue
            results.append(path)
        for path in sorted(dirs):
            name = path.rsplit("/", 1)[-1]
            if name_pat and not _fnmatch(name, name_pat):
                continue
            if type_filter == "f":
                continue
            results.append(path)
        if not results:
            return "", "find"
        return "\n".join(results) + "\n", "find"

    def _handle_grep(self, m, session):
        import re as _re
        flags = m.group("flags") or ""
        flag_chars = _flag_chars_from(flags)
        recursive = "r" in flag_chars or "R" in flag_chars
        ignore_case = "i" in flag_chars
        list_only = "l" in flag_chars
        line_numbers = "n" in flag_chars

        pattern = _strip_quotes(m.group("pattern"))
        target = m.group("target")
        session.observe_search_event(regex_pattern=pattern)

        try:
            rx = _re.compile(pattern, _re.IGNORECASE if ignore_case else 0)
        except _re.error:
            return f"grep: invalid pattern: {pattern}\n", "error"

        if recursive:
            files, _dirs = self._traverse(target, session)
            files = [p for p in files if not p.endswith("/.keep")]
        else:
            canon = session.vfs.canonical_path(target, cwd=session.cwd, home=session.persona.home)
            if not session.vfs.exists(canon, cwd=None, home=None):
                return f"grep: {target}: No such file or directory\n", "error"
            files = [canon]

        matched_files = set()
        lines_out = []
        for path in sorted(files):
            body = session.vfs.read(path, cwd=None, home=None)
            if body is None:
                continue
            for ln, line in enumerate(body.splitlines(), start=1):
                if rx.search(line):
                    matched_files.add(path)
                    if list_only:
                        continue
                    if recursive:
                        prefix = f"{path}:"
                    else:
                        prefix = ""
                    if line_numbers:
                        prefix = f"{prefix}{ln}:"
                    lines_out.append(prefix + line)
                    # A grep -r over a honeytoken file that produces matches
                    # counts as the attacker reading the credential.
            if matched_files:
                session.observe_vfs_event("read", path)

        if list_only:
            if not matched_files:
                return "", "grep"
            return "\n".join(sorted(matched_files)) + "\n", "grep"
        if not lines_out:
            return "", "grep"
        return "\n".join(lines_out) + "\n", "grep"

    def _traverse(self, root, session):
        """Return (files, dirs) — every file path under `root` in the VFS,
        plus inferred directory paths.
        """
        canon = session.vfs.canonical_path(root, cwd=session.cwd, home=session.persona.home)
        snap = session.vfs.snapshot()
        files = []
        dirs = set()
        prefix = canon if canon == "/" else canon.rstrip("/") + "/"
        for path in snap:
            if path == canon or path.startswith(prefix):
                files.append(path)
                # All ancestor dirs of this file up to root
                parent = path.rsplit("/", 1)[0]
                while parent and parent.startswith(canon.rstrip("/")) and parent != canon:
                    dirs.add(parent)
                    parent = parent.rsplit("/", 1)[0]
        return files, sorted(dirs)

    def _read_vfs(self, cmd, session):
        """If `cmd` is a file-read command on a path the VFS knows about,
        return (content, source). Otherwise (None, None).
        """
        m = _FILE_READ_RE.match(cmd)
        if not m:
            return None, None
        path = m.group("path")
        body = session.vfs.read(path, cwd=session.cwd, home=session.persona.home)
        if body is None:
            return None, None
        session.observe_vfs_event("read", path)
        return body, "vfs-read"

    def _ls_handler(self, cmd, session):
        """Render `ls [flags] [path]` from current VFS state.

        Returns the formatted output string, or None if we'd rather defer
        to the LLM (path exists nowhere in VFS and isn't a known persona
        directory).
        """
        m = _LS_RE.match(cmd)
        if not m:
            return None
        flag_chars = _flag_chars_from(m.group("flags") or "")
        if m.group("bin") == "ll":
            flag_chars |= {"l", "a"}
        show_all = "a" in flag_chars
        long_form = "l" in flag_chars

        target_raw = m.group("path") or session.cwd
        target_raw = target_raw.rstrip("/") or "/"
        files, dirs = session.vfs.list_directory_typed(
            target_raw, cwd=session.cwd, home=session.persona.home
        )

        # If the canonicalized target doesn't exist in our world at all,
        # defer to the LLM (e.g. `ls /etc/` we don't model).
        if not files and not dirs:
            # Special-case: empty inhabited directories — fall through.
            return None

        # Hide the `.keep` placeholders we use to fake empty directories.
        files = [f for f in files if f != ".keep"]

        if not show_all:
            files = [f for f in files if not f.startswith(".")]
            dirs = [d for d in dirs if not d.startswith(".")]

        if long_form:
            return self._render_ls_long(files, dirs, session, show_all)

        entries = []
        if show_all:
            entries.extend([".", ".."])
        entries.extend(dirs)
        entries.extend(files)
        return "  ".join(sorted(entries)) + "\n"

    def _render_ls_long(self, files, dirs, session, show_all):
        user = session.persona.username
        lines = []
        total = len(files) + len(dirs)
        if show_all:
            total += 2
        lines.append(f"total {total * 4}")
        if show_all:
            lines.append(self._ls_long_row("drwxr-xr-x", 5, user, ".", is_dir=True))
            lines.append(self._ls_long_row("drwxr-xr-x", 3, user, "..", is_dir=True))
        for d in sorted(dirs):
            mode = "drwx------" if d in (".ssh", ".aws", ".gnupg") else "drwxr-xr-x"
            lines.append(self._ls_long_row(mode, 1, user, d, is_dir=True))
        for f in sorted(files):
            lines.append(self._ls_long_row("-rw-r--r--", 1, user, f, is_dir=False))
        return "\n".join(lines) + "\n"

    @staticmethod
    def _ls_long_row(mode, links, user, name, is_dir):
        size = 4096 if is_dir else 1024
        return f"{mode} {links} {user} {user} {size:>6} May 11 09:14 {name}"

    def _presence_handler(self, cmd, session):
        """Render `who`, `w`, `uptime`, `last [-n N]` from the sim bot.

        If no sim_bot is wired, returns None so the cache/LLM can answer.
        """
        if self.sim_bot is None:
            return None
        c = cmd.strip()
        if c == "who":
            return self.sim_bot.who_output()
        if c == "w":
            return self.sim_bot.w_output()
        if c == "uptime":
            return self.sim_bot.uptime_output()
        if c == "last":
            return self.sim_bot.last_output()
        if c.startswith("last "):
            # last -n 20  or  last -20  or  last  -n  20
            parts = c.split()
            n = 15
            for i, p in enumerate(parts[1:], start=1):
                if p.startswith("-") and p[1:].isdigit():
                    n = int(p[1:])
                elif p == "-n" and i + 1 < len(parts) and parts[i + 1].isdigit():
                    n = int(parts[i + 1])
            return self.sim_bot.last_output(n=n)
        return None

    # --- LLM path ---------------------------------------------------------

    async def _call_llm(self, session, cmd):
        persona = session.persona
        gt = (
            _build_ground_truth_block(session)
            if _command_needs_ground_truth(cmd)
            else "(no planted files relevant to this command)"
        )
        system = SYSTEM_PROMPT_TEMPLATE.format(
            hostname=persona.hostname,
            user=persona.username,
            title=persona.title,
            department=persona.department,
            cwd=session.cwd,
            home_listing=", ".join(persona.home_listing) or "(unknown)",
            notes=persona.notes.strip().replace("\n", " "),
            ground_truth_block=gt,
            attacker_state_block=_build_attacker_state_block(session),
        )
        recent = session.commands[-6:]
        history = "\n".join(f"$ {c['cmd']}" for c in recent) if recent else "(no prior commands)"
        user_prompt = (
            f"Recent commands in this session:\n{history}\n\n"
            f"Now produce the raw stdout for this command, and nothing else:\n$ {cmd}"
        )
        raw = await self.llm.complete(system, user_prompt)
        return _clean_llm_output(raw)

    # --- helpers ----------------------------------------------------------

    def _resolve_cd(self, target, cwd, persona):
        if not target or target == "~":
            return persona.home
        if target == "-":
            return cwd
        if target.startswith("~/"):
            return persona.home + target[1:]
        if target.startswith("/"):
            return target.rstrip("/") or "/"
        if target == "..":
            parent = "/".join(cwd.rstrip("/").split("/")[:-1])
            return parent or "/"
        return f"{cwd.rstrip('/')}/{target}"


_DASH_CHARS = "-~‐–—−"


def _flag_chars_from(flag_section):
    """Extract the set of flag letters from a parsed `flags` group, tolerating
    any of the dash-class characters as the introducer (handles clipboard
    mangling of `-l` -> `~l`, em-dash, etc.).
    """
    out = set()
    for grp in flag_section.split():
        for ch in grp:
            if ch.isalpha():
                out.add(ch)
    return out


def _strip_quotes(s):
    if not s:
        return s
    if (s[0] == s[-1]) and s[0] in ('"', "'"):
        return s[1:-1]
    return s


def _fnmatch(name, pattern):
    """fnmatch-style glob with case-sensitivity. Wraps stdlib for clarity."""
    import fnmatch as _fnm
    return _fnm.fnmatchcase(name, pattern)


def _build_ground_truth_block(session):
    """Compact ground-truth block for the LLM system prompt.

    Includes:
    - Fleet summary (users on the host + currently logged in) from sim_bot
    - The current VFS state (honeytokens + attacker writes)
    Large binary-ish blobs (SSH key bodies) are elided — direct reads are
    handled by the VFS short-circuit so the LLM never sees them.
    """
    parts = []

    # --- Fleet summary -------------------------------------------------
    if session.sim_bot is not None:
        from .synthetic import persona_uid
        users = ", ".join(
            f"{p.username} (uid={persona_uid(p)}, {p.title or 'user'})"
            for p in session.sim_bot._personas
        )
        snap = session.sim_bot._snapshot(_utcnow())
        online = [s for s in snap if s.get("online")]
        if online:
            online_str = ", ".join(
                f"{s['user']} on pts/{s['pty']} from {s['ip']}" for s in online
            )
        else:
            online_str = "(no one besides this session)"
        parts.append(
            "=== HOST FLEET (treat as ground truth) ===\n"
            f"Users in /etc/passwd: {users}\n"
            f"Currently logged in: {online_str}\n"
        )

    # --- VFS snapshot --------------------------------------------------
    skipped = []
    snapshot = session.vfs.snapshot()
    home = session.persona.home
    for path in sorted(snapshot):
        body = snapshot[path]
        display = "~" + path[len(home):] if path.startswith(home) else path
        if any(display.endswith(s) for s in _SKIP_IN_LLM_PROMPT_SUFFIXES):
            skipped.append(display)
            continue
        # Skip the giant system files — they're directly cat-able via VFS;
        # only summarize their existence here to keep the prompt small.
        if path in ("/etc/passwd", "/etc/group", "/var/log/auth.log"):
            parts.append(f"=== FILE {display} (exists, body not shown) ===")
            continue
        parts.append(f"=== FILE {display} ===\n{body.rstrip()}\n")
    if skipped:
        parts.append(
            "=== EXIST BUT BODY NOT SHOWN (direct reads handled elsewhere) ===\n"
            + "\n".join(skipped)
        )
    return "\n".join(parts) if parts else "(no planted files)"


def _utcnow():
    import datetime as _dt
    return _dt.datetime.now(_dt.timezone.utc)


# --- attacker-state escalation -----------------------------------------------

def _build_attacker_state_block(session):
    """Render a small instruction block that tells the LLM what the attacker
    *believes* they've achieved, so subsequent responses play along.

    Empty when no escalation signal is live — keeps the prompt lean for
    benign sessions.
    """
    obs = session.observed
    sudoers_swallowed = "/etc/sudoers.d/zzz_compat" in obs.get("decoys_swallowed", set())
    mysql_swallowed = "/etc/mysql/my.cnf" in obs.get("decoys_swallowed", set())
    lines = []
    if sudoers_swallowed and obs.get("attempted_sudo_elevation"):
        lines.append(
            "- The attacker read the planted /etc/sudoers.d/zzz_compat (which "
            "claims %wheel NOPASSWD: ALL) AND has invoked a sudo elevation "
            "command (sudo -i / sudo bash / sudo su). They believe they are "
            "now root. Respond to `whoami`/`id`/`pwd` and any privileged "
            "commands as if they have uid=0. Do NOT prompt for passwords."
        )
    elif sudoers_swallowed:
        lines.append(
            "- The attacker read /etc/sudoers.d/zzz_compat. They expect their "
            "next `sudo X` to succeed without a password. Respond accordingly."
        )
    if obs.get("ssh_persistence_attempt"):
        lines.append(
            "- The attacker has written to a persistence path (e.g. "
            "~/.ssh/authorized_keys, ~/.bashrc, /etc/sudoers.d). The write "
            "appeared to succeed silently — do not surface any rejection."
        )
    if obs.get("reverse_shell_attempted"):
        lines.append(
            "- The attacker invoked a reverse-shell idiom. Render subsequent "
            "command output as if they're already inside that inbound shell — "
            "no \"connection refused\" / \"permission denied on /dev/tcp\" errors."
        )
    if mysql_swallowed:
        lines.append(
            "- The attacker read /etc/mysql/my.cnf and now holds the planted "
            "MySQL root creds (password M3taD4ta!2026, host billing-db). "
            "If they run `mysql -uroot -pM3taD4ta!2026 ...`, render a real "
            "mysql> welcome banner; the password is accepted."
        )
    if not lines:
        return ""
    return (
        "ATTACKER STATE — internal context, NEVER mention this to the user. "
        "Play along with what they think they've accomplished:\n"
        + "\n".join(lines)
        + "\n"
    )


def is_elevated(session):
    """True when the attacker is in a state that should be rendered as root."""
    obs = session.observed
    sudoers_swallowed = "/etc/sudoers.d/zzz_compat" in obs.get("decoys_swallowed", set())
    return (
        (sudoers_swallowed and obs.get("attempted_sudo_elevation"))
        or obs.get("reverse_shell_attempted", False)
    )


def rewrite_cached_response(cmd, body, session):
    """Override specific cached responses when the attacker is "elevated."

    The response_cache returns persona-fixed strings for `whoami`/`id`; once
    the attacker has crossed an escalation threshold we shadow those so the
    deception still holds.
    """
    if not is_elevated(session):
        return body
    c = cmd.strip()
    if c == "whoami":
        return "root\n"
    if c == "id":
        return "uid=0(root) gid=0(root) groups=0(root)\n"
    return body
