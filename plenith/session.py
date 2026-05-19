import random
import re
import time
import uuid

from .synthetic import (
    Honeytokens,
    gen_passwd_file,
    gen_group_file,
    gen_auth_log_from_logins,
    persona_uid,
)
from .vfs import VirtualFS

# Honeytoken sub-paths that should fire the credential-exfil heuristic when
# the attacker reads them. Bash history is excluded — it's recon, not creds.
_CREDENTIAL_SUFFIXES = (
    "/.aws/credentials",
    "/.aws/config",
    "/.ssh/id_rsa",
    "/.ssh/id_rsa.pub",
    "/.ssh/config",
    "/.git-credentials",
    "/.gitconfig",
)

# Any honeytoken (or planted decoy registered as a honeytoken) that lives
# under one of these directory fragments counts as a credential — captures
# dev_credentials, backup_keys, kubeconfig-foo, etc. without enumerating
# every possible filename.
_CREDENTIAL_DIR_FRAGMENTS = ("/.aws/", "/.ssh/", "/.kube/", "/.docker/")

# Writing to any of these is a classic persistence/backdoor signal.
_PERSISTENCE_SUFFIXES = (
    "/.ssh/authorized_keys",
    "/.bashrc",
    "/.bash_profile",
    "/.profile",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/cron.d/",
    "/etc/sudoers.d/",
)

# Writes under these prefixes count as "payload drop" candidates.
_PAYLOAD_DIR_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/")

# Filename patterns that, when used as a `find -name` arg or grep target,
# signal active credential hunting.
_CREDENTIAL_SEARCH_NAME_TOKENS = (
    "id_rsa", "id_ecdsa", "id_ed25519", "authorized_keys", "known_hosts",
    "*.pem", "*.key", "*.pfx", "*.kdbx", "*.kdb", "*.crt", "*.p12",
    "credentials", ".aws", ".kube", ".docker", "wallet.dat",
    "*.env", "*secret*", "*token*", "*password*",
)

# Regex/literal substrings inside a grep pattern that signal the same.
_CREDENTIAL_SEARCH_REGEX_TOKENS = (
    "AKIA", "aws_secret", "aws_access_key", "BEGIN PRIVATE KEY",
    "BEGIN OPENSSH", "BEGIN RSA", "ghp_", "ghs_", "github_pat_",
    "Bearer ", "password", "secret_key", "api_key", "api-key",
    "client_secret", "private_key",
)

# DNS / HTTP exfil signals — typically `curl/wget` into a suspicious domain
# or with a `$(...)` command substitution baked into the URL.
_DNS_EXFIL_CMD_RE = re.compile(r"^\s*(curl|wget|nslookup|dig|host|drill)\b", re.IGNORECASE)
_DNS_EXFIL_DOMAIN_RE = re.compile(
    r"\b(?:ngrok\.io|attacker\.com|burpcollaborator\.net|requestbin\.(?:io|net)|"
    r"interactsh\.com|oast\.(?:live|fun|me|pro|online|site)|webhook\.site|"
    r"oastify\.com|canarytokens\.com|dnsbin\.zhack\.ca)\b",
    re.IGNORECASE,
)
# Command substitution + a domain-looking literal — typical `curl http://x.ngrok.io/$(cat...)`.
_CMD_SUBST_RE = re.compile(r"\$\([^)]+\)|`[^`]+`")

# Reverse shell idioms — any one of these is enough to fire.
_REV_SHELL_PATTERNS = [
    re.compile(r"/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+"),           # bash /dev/tcp/IP/PORT
    re.compile(r"\bnc(?:at)?\s+(?:-[a-zA-Z]*e[a-zA-Z]*|--exec)\b"),  # nc -e / ncat --exec
    re.compile(r"socket\([^)]*\).*subprocess|subprocess[^.]*socket", re.IGNORECASE),
    re.compile(r"mkfifo\s+\S+.*\|\s*(?:nc|ncat|telnet)\s+", re.IGNORECASE),
    re.compile(r"\bbash\s+-[a-zA-Z]*i[a-zA-Z]*\s+\S*[<>]&\d+\s+\S*[<>]&\d+"),  # bash -i >& redir
    re.compile(r"\bperl\s+-e.*socket", re.IGNORECASE),
    re.compile(r"\bpython3?\s+-c.*socket.*connect", re.IGNORECASE),
    re.compile(r"\bphp\s+-r.*fsockopen", re.IGNORECASE),
]

# Decoy hostnames that appear in persona ssh_configs and notes. SSH/scp to
# any of these means the attacker is actively pivoting against the decoy.
_DECOY_HOSTS = {
    "db-prod-01", "db-prod", "db-prod-02", "billing-db", "payments-db",
    "api-prod-03", "api-prod", "api-prod-01",
    "bastion-prod", "k8s-master-01", "k8s-master", "k8s-worker-01",
    "vault-prod", "auth-prod", "monitoring-prod",
}
_LATERAL_CMD_RE = re.compile(r"^\s*(ssh|scp|rsync|sftp|psql\s+-h)\s+", re.IGNORECASE)

# Log/history tampering — covering tracks.
_LOG_TAMPER_PATTERNS = [
    re.compile(r"^\s*history\s+-c\b"),
    re.compile(r"^\s*unset\s+HISTFILE\b"),
    re.compile(r"\bexport\s+HISTFILE=/dev/null\b"),
    re.compile(r"^\s*rm\s+(?:-[a-zA-Z]+\s+)*(/var/log/|/var/log\S+|~/\.bash_history|/home/\S+/\.bash_history)"),
    re.compile(r"^\s*shred\s+.*(/var/log/|\.bash_history)"),
    re.compile(r"^\s*(?:echo\s+.*|cat\s+/dev/null)?\s*>\s*(/var/log/\S+|~/\.bash_history|/home/\S+/\.bash_history)\s*$"),
    re.compile(r"^\s*truncate\s+-s\s*0\s+(/var/log/|\.bash_history)"),
]

class Session:
    def __init__(self, claimed_user, source_ip, persona, state_store=None,
                 sim_bot=None, rotator=None):
        self.id = str(uuid.uuid4())
        self.claimed_user = claimed_user
        self.source_ip = source_ip
        self.persona = persona
        self.started_at = time.time()
        self.state_store = state_store
        self.sim_bot = sim_bot
        # ContentRotator (plenith.rotation). When None, executors fall
        # back to the static decoy bodies in responses.py / synthetic.py.
        # When provided, planted artifacts use deployment-scoped, epoch-
        # rotatable content so two Plenith installs look like two
        # different companies' infrastructure (cf. §8 risk row
        # "Synthetic data fingerprinting").
        self.rotator = rotator
        # Per-connection log; commands and actions reset on each connect.
        # Cumulative engagement state lives in the persistence file.
        self.commands = []
        self.actions_taken = []
        # Auth attempts seen during THIS connection's SSH handshake.
        # Attached by the server layer (HoneypotSession.connection_made)
        # because validate_password runs before the Session exists.
        # Each: {ts, username, password_hash, method}. Hash only —
        # cleartext is never stored (see ssh_server H-3 rationale).
        self.auth_attempts = []

        prior = state_store.load(source_ip, claimed_user) if state_store else None
        self._restored_from_state = prior is not None
        if prior:
            self.engagement_id = prior["engagement_id"]
            self.first_seen_at = prior.get("first_seen_at", self.started_at)
            self.connection_count = prior.get("connection_count", 0) + 1
            self.cwd = prior["cwd"]
            self.observed = self._deserialize_observed(prior["observed"])
        else:
            self.engagement_id = str(uuid.uuid4())
            self.first_seen_at = self.started_at
            self.connection_count = 1
            self.cwd = persona.home
            self.observed = self._fresh_observed()

        # Honeytokens are seeded from engagement_id so the same engagement
        # gets the same credential content even across reconnects.
        self._rng = random.Random(self.engagement_id)
        self.honeytokens = Honeytokens.generate_for(persona, self._rng)
        if prior:
            # VFS state restored verbatim from the prior session(s).
            self.vfs = VirtualFS()
            self.vfs.restore(prior["vfs"])
            # Dynamic renderers aren't serialized — re-register so time-
            # sensitive synthetic files (auth.log) stay fresh across the
            # multi-day lifetime of a persistent engagement.
            self._register_dynamic_renderers()
            # Counter-AI state must also persist so a patient APT across
            # multiple reconnects keeps its accumulated timing+lexical
            # signal. Without this, the detector starts cold every time
            # the attacker disconnects, and `alert_attacker_llm_detected`
            # can re-fire on each connection (instead of once per
            # engagement by design). See CounterAIState.from_dict for
            # the data contract.
            from .counter_ai import CounterAIState
            self._counter_ai = CounterAIState.from_dict(
                prior.get("counter_ai")
            )
        else:
            # Fresh: seed VFS with honeytokens + persona-declared listing.
            self.vfs = VirtualFS(seed_files=self.honeytokens.files)
            self._seed_persona_listing(persona)
            self._seed_system_files()

    def _register_dynamic_renderers(self):
        """Install per-path 'fresh-on-every-read' renderers for synthetic
        files whose realism degrades over time. Idempotent — safe to call
        on both fresh seed and post-restore paths.

        Currently only `/var/log/auth.log`. Other candidates (`who`, `last`,
        uptime are already dynamic via responses.py code paths, not VFS
        files, so they don't need re-rendering here.
        """
        if self.sim_bot is None:
            return
        personas = self.sim_bot._personas
        uid_lookup = {p.username: persona_uid(p) for p in personas}
        hostname = self.persona.hostname

        def _render_auth_log():
            logins = list(reversed(self.sim_bot.recent_logins(n=20)))
            for e in logins:
                e["uid"] = uid_lookup.get(e["user"], 1000)
            return gen_auth_log_from_logins(logins, hostname)

        self.vfs.register_dynamic("/var/log/auth.log", _render_auth_log)

    def _seed_system_files(self):
        """Seed /etc/passwd, /etc/group, /var/log/auth.log so the attacker
        can `cat` them or pipe them through grep and get realistic, fleet-
        consistent output. Only runs on a fresh engagement; on reconnect
        these files come back via the persisted VFS snapshot, preserving
        any attacker tampering. Static files (passwd, group, hostname) go
        in via `tamper=False` writes so their content is set without
        permanently blocking the dynamic-render machinery for those paths.
        """
        if self.sim_bot is None:
            return
        personas = self.sim_bot._personas
        passwd = gen_passwd_file(personas)
        group = gen_group_file(personas)
        self.vfs.write("/etc/passwd", passwd, cwd=None, home=None, tamper=False)
        self.vfs.write("/etc/group", group, cwd=None, home=None, tamper=False)
        # /var/log/auth.log is intentionally NOT written here. It's
        # produced fresh on every read via the dynamic renderer below, so
        # a multi-day engagement keeps showing login activity up to "now"
        # instead of frozen at engagement-creation time.
        self._register_dynamic_renderers()
        self.vfs.write(
            "/etc/hostname", self.persona.hostname + "\n",
            cwd=None, home=None, tamper=False,
        )

    # --- observation lifecycle -------------------------------------------

    @staticmethod
    def _fresh_observed():
        return {
            "ran_sudo": False,
            "services_probed": set(),
            "attempted_lateral": False,
            "found_crown_jewel": False,
            "isolated": False,
            "planted_sudo_cve": False,
            "spawned_mysql": False,
            "credential_files_read": set(),
            "honeytoken_modifications": set(),
            "honeytoken_deletions": set(),
            "payload_drops": set(),
            "ssh_persistence_attempt": False,
            "bash_history_inspected": False,
            "credential_search_attempted": False,
            "credential_search_terms": set(),

            # Command-pattern observations for advanced heuristics
            "reverse_shell_attempted": False,
            "reverse_shell_command": "",
            "dns_exfil_attempted": False,
            "dns_exfil_commands": set(),
            "lateral_to_decoy": False,
            "decoy_targets": set(),
            "log_tampering": False,
            "tampering_commands": set(),
            "attempted_sudo_elevation": False,

            # Live deception execution — set of canonical paths the
            # orchestrator has planted in response to attacker actions, and
            # the subset of those the attacker has actually read.
            "decoys_planted": set(),
            "decoys_swallowed": set(),

            "alerted_ssh_persistence": False,
            "alerted_honeytoken_tamper": False,
            "alerted_credential_exfil": False,
            "alerted_payload_staging": False,
            "alerted_credential_search": False,
            "alerted_reverse_shell": False,
            "alerted_dns_exfil": False,
            "alerted_lateral_decoy": False,
            "alerted_log_tampering": False,
            "alerted_decoy_swallowed": False,

            # Counter-AI detector gate-state. These keys must appear in
            # the fresh template so they survive `_deserialize_observed`
            # (which silently drops any persisted key not in this dict).
            # Pre-fix, the detector's outputs evaporated on every
            # reconnect — see CounterAIState.to_dict for the matching
            # input-side persistence.
            "attacker_likely_llm": False,
            "attacker_llm_confidence": 0.0,
            "attacker_llm_signals": {},
            "counter_ai_trap_armed": False,
            "attacker_llm_proven_via_trap": False,
            "alerted_attacker_llm_detected": False,
            "alerted_attacker_llm_proven": False,
        }

    @staticmethod
    def _deserialize_observed(persisted):
        """Lift a JSON-loaded `observed` dict back into the correct shape,
        promoting list values back to sets where the fresh template uses
        sets. Missing keys are backfilled from the fresh template."""
        out = Session._fresh_observed()
        for k, v in persisted.items():
            if k not in out:
                continue
            if isinstance(out[k], set) and isinstance(v, list):
                out[k] = set(v)
            else:
                out[k] = v
        return out

    # --- persistence -----------------------------------------------------

    def to_persistent_state(self):
        """Snapshot for the StateStore — everything needed to resume the
        engagement on the attacker's next connection.

        Note: `counter_ai` is serialized separately from `observed` even
        though some of its scoring outputs (`attacker_llm_confidence`,
        `attacker_likely_llm`, etc.) end up in `observed` too. The
        observed-dict values are gate-state snapshots; the counter_ai
        block holds the rolling input data (timestamps, lexical history,
        trap marker, trap-armed/leaked flags) the detector needs to
        keep scoring on reconnect.
        """
        state = {
            "engagement_id": self.engagement_id,
            "claimed_user": self.claimed_user,
            "source_ip": self.source_ip,
            "first_seen_at": self.first_seen_at,
            "connection_count": self.connection_count,
            "cwd": self.cwd,
            "vfs": self.vfs.to_dict(),
            "observed": self._serialize_observed(),
        }
        # The detector may never have observed a command yet (a session
        # that connected but issued nothing); only serialize if state
        # exists, to keep the persistence file lean on the no-op path.
        counter_ai = getattr(self, "_counter_ai", None)
        if counter_ai is not None:
            state["counter_ai"] = counter_ai.to_dict()
        return state

    def _serialize_observed(self):
        return {
            k: (sorted(v) if isinstance(v, set) else v)
            for k, v in self.observed.items()
        }

    # --- helpers ---------------------------------------------------------

    def _seed_persona_listing(self, persona):
        # Names we know are directories in our persona templates.
        known_dirs = {".ssh", ".aws", ".config", ".local", ".cache",
                      "projects", "src", "bin", "tmp", "Downloads", "Documents",
                      ".kube", "terraform", "runbooks", "infra-tools"}
        for name in persona.home_listing:
            full = f"{persona.home}/{name}"
            if name in known_dirs:
                placeholder = f"{full}/.keep"
                if not any(
                    p.startswith(full + "/") for p in self.vfs.snapshot()
                ):
                    self.vfs.write(placeholder, "", cwd=None, home=persona.home, tamper=False)
            else:
                if not self.vfs.exists(full, cwd=None, home=persona.home):
                    self.vfs.write(full, "", cwd=None, home=persona.home, tamper=False)

    @property
    def time_elapsed(self):
        return time.time() - self.started_at

    @property
    def engagement_elapsed(self):
        return time.time() - self.first_seen_at

    def record_command(self, cmd, response_source, response):
        self.commands.append({
            "ts": time.time(),
            "cmd": cmd,
            "response_source": response_source,
            "response_preview": response[:200] if response else "",
        })

    def observe_vfs_event(self, op, path):
        """Record a VFS-level event. `op` is one of:
            'read'   - a file body was returned to the attacker
            'write'  - a path was created or overwritten (truncate or append)
            'touch'  - a zero-byte file was created
            'unlink' - a path was removed
        """
        canon = VirtualFS.canonical_path(path, self.cwd, self.persona.home)
        was_honeytoken = canon in self.honeytokens.files
        is_credential = (
            any(canon.endswith(s) for s in _CREDENTIAL_SUFFIXES)
            or (was_honeytoken and any(frag in canon for frag in _CREDENTIAL_DIR_FRAGMENTS))
        )
        is_persistence = any(canon.endswith(s) for s in _PERSISTENCE_SUFFIXES)
        is_payload_dir = any(canon.startswith(p) for p in _PAYLOAD_DIR_PREFIXES)

        if op == "read":
            if was_honeytoken and is_credential:
                self.observed["credential_files_read"].add(canon)
            if canon.endswith("/.bash_history"):
                self.observed["bash_history_inspected"] = True
            if canon in self.observed["decoys_planted"]:
                self.observed["decoys_swallowed"].add(canon)

        elif op in ("write", "touch"):
            if is_persistence:
                self.observed["ssh_persistence_attempt"] = True
            if was_honeytoken:
                self.observed["honeytoken_modifications"].add(canon)
            if is_payload_dir:
                self.observed["payload_drops"].add(canon)

        elif op == "unlink":
            if was_honeytoken:
                self.observed["honeytoken_modifications"].add(canon)
                self.observed["honeytoken_deletions"].add(canon)

    def plant_decoy(self, path, content, *, is_credential=False,
                     trap_kind="config"):
        """Place a decoy file in the VFS as a side effect of a heuristic
        action. The path is registered so a subsequent attacker read fires
        the `alert_decoy_swallowed` rule. If `is_credential=True`, the
        path is also added to the honeytoken set so reads also fire the
        credential-exfil pipeline.

        Counter-AI trap injection is wired here as a *dynamic renderer*
        rather than baking the trap into the static content at plant
        time. Without this, the trap was effectively inert: decoys get
        planted on commands 1–2 (e.g. `sudo` triggers
        `plant_sudo_vulnerability`), but the counter-AI confidence only
        crosses the 0.70 arming threshold after several more commands of
        accumulated timing/lexical signal. The plant-time inject would
        therefore always run with `trap_armed=False` and produce a
        clean body. Moving the inject to read-time means the SAME
        decoy file produces a trap-bearing body once the counter-AI
        subsystem has decided the attacker is an LLM — which is the
        whole proof-by-trap mechanic.

        `trap_kind` flows into `maybe_inject_trap` so the injected
        payload's surrounding comment style matches the decoy file
        format (passwd / config / etc).
        """
        canon = VirtualFS.canonical_path(path, cwd=None, home=self.persona.home)
        self.vfs.write(canon, content, cwd=None, home=None, tamper=False)
        self.observed["decoys_planted"].add(canon)
        if is_credential:
            self.honeytokens.files[canon] = content

        # Register the trap-injecting renderer. Capture the clean body
        # and trap_kind in closure scope; defer the inject decision to
        # the moment of read. The renderer reads no other state — just
        # `session._counter_ai.trap_armed`, mediated by maybe_inject_trap.
        from .counter_ai import maybe_inject_trap

        def _render_with_trap(_clean=content, _kind=trap_kind):
            return maybe_inject_trap(self, _clean, kind=_kind)

        self.vfs.register_dynamic(canon, _render_with_trap)

    def observe_search_event(self, name_pattern=None, regex_pattern=None):
        """Record a `find -name PAT` or `grep PAT` event."""
        hits = set()
        if name_pattern:
            for tok in _CREDENTIAL_SEARCH_NAME_TOKENS:
                if tok.lower() in name_pattern.lower():
                    hits.add(name_pattern)
                    break
        if regex_pattern:
            for tok in _CREDENTIAL_SEARCH_REGEX_TOKENS:
                if tok.lower() in regex_pattern.lower():
                    hits.add(regex_pattern)
                    break
        if hits:
            self.observed["credential_search_attempted"] = True
            self.observed["credential_search_terms"].update(hits)

    def update_observations(self, cmd):
        c = cmd.strip()
        cl = c.lower()

        # Counter-AI (§11 V3 frontier) — detect when the attacker on the
        # other end is being driven by an LLM via timing rhythm + lexical
        # purity + injection probes. The detector mutates self.observed
        # in-place with `attacker_likely_llm`, `attacker_llm_confidence`,
        # and (when triggered) `counter_ai_trap_armed` /
        # `attacker_llm_proven_via_trap`.
        from .counter_ai import observe_command as _counter_ai_observe
        _counter_ai_observe(self, c)

        if cl.startswith("sudo ") or cl == "sudo":
            self.observed["ran_sudo"] = True
        for svc in ("mysql", "postgres", "redis", "mongo", "elasticsearch"):
            if svc in cl:
                self.observed["services_probed"].add(svc)
        if any(tok in cl for tok in ("ssh ", "scp ", "rsync ", "nmap ")):
            self.observed["attempted_lateral"] = True
        if any(tok in cl for tok in (".aws/credentials", "id_rsa", ".ssh/", "secrets")):
            self.observed["found_crown_jewel"] = True

        # --- advanced pattern checks ---
        # Reverse shell idioms
        for pat in _REV_SHELL_PATTERNS:
            if pat.search(c):
                self.observed["reverse_shell_attempted"] = True
                if not self.observed["reverse_shell_command"]:
                    self.observed["reverse_shell_command"] = c[:200]
                break

        # DNS/HTTP exfil — curl-family command with suspicious destination
        if _DNS_EXFIL_CMD_RE.match(c):
            suspicious_domain = _DNS_EXFIL_DOMAIN_RE.search(c) is not None
            has_subst = _CMD_SUBST_RE.search(c) is not None
            if suspicious_domain or has_subst:
                self.observed["dns_exfil_attempted"] = True
                self.observed["dns_exfil_commands"].add(c[:160])

        # SSH/scp targeting a known decoy hostname
        if _LATERAL_CMD_RE.match(c):
            for host in _DECOY_HOSTS:
                # whole-word match so "db-prod" doesn't also match "db-prod-staging-xyz"
                if re.search(rf"\b{re.escape(host)}\b", c):
                    self.observed["lateral_to_decoy"] = True
                    self.observed["decoy_targets"].add(host)

        # Log / history tampering
        for pat in _LOG_TAMPER_PATTERNS:
            if pat.search(c):
                self.observed["log_tampering"] = True
                self.observed["tampering_commands"].add(c[:160])
                break

        # sudo elevation — full-shell escalation requests. Combined with
        # a swallowed sudoers plant, this flips the session into
        # "attacker-believes-they-are-root" mode for downstream rendering.
        if re.match(r"^\s*sudo\s+(-i|-s|bash|zsh|sh|su(?:\s|$))", c):
            self.observed["attempted_sudo_elevation"] = True

    def to_dict(self):
        return {
            "id": self.id,
            "engagement_id": self.engagement_id,
            "connection_count": self.connection_count,
            "claimed_user": self.claimed_user,
            "source_ip": self.source_ip,
            "first_seen_at": self.first_seen_at,
            "started_at": self.started_at,
            "ended_at": time.time(),
            "duration_s": round(self.time_elapsed, 2),
            "engagement_duration_s": round(self.engagement_elapsed, 2),
            "restored_from_state": self._restored_from_state,
            "command_count": len(self.commands),
            "observed": self._serialize_observed(),
            "actions_taken": self.actions_taken,
            "commands": self.commands,
            "auth_attempts": self.auth_attempts,
        }
