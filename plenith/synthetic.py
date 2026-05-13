"""Synthetic credential and artifact generators.

Each function takes a `random.Random` instance so output is deterministic per
session (we seed from the session id), giving us cross-turn consistency: a
second `cat ~/.aws/credentials` in the same session returns the same bytes.

Format conventions match real-world examples closely enough that pattern-based
attacker tooling (TruffleHog, gitleaks, etc.) will fingerprint them as the
real credential type — which is exactly what we want for the deception.
"""
import re
import string
from dataclasses import dataclass, field


_UID_RE = re.compile(r"uid=(\d+)")
_GID_RE = re.compile(r"gid=(\d+)")


def persona_uid(persona):
    """Extract numeric uid from persona.id_output, default 1000."""
    m = _UID_RE.search(persona.id_output)
    return int(m.group(1)) if m else 1000


def persona_gid(persona):
    m = _GID_RE.search(persona.id_output)
    return int(m.group(1)) if m else 1000


# --- low-level value generators -------------------------------------------------

def _rand_chars(rng, alphabet, n):
    return "".join(rng.choices(alphabet, k=n))


def gen_aws_access_key_id(rng):
    """20 chars, AKIA prefix + 16 [A-Z0-9]. Matches real AWS access key format."""
    return "AKIA" + _rand_chars(rng, string.ascii_uppercase + string.digits, 16)


def gen_aws_secret_access_key(rng):
    """40 chars, base64-style alphabet. Matches real AWS secret format."""
    return _rand_chars(rng, string.ascii_letters + string.digits + "+/", 40)


def gen_github_pat(rng):
    """`ghp_` + 36 alphanumeric. Matches real GitHub PAT format."""
    return "ghp_" + _rand_chars(rng, string.ascii_letters + string.digits, 36)


def gen_db_password(rng, hint=None):
    """Plausible-looking ops password. Mix of cases, digits, occasional special."""
    base_words = ["spring", "winter", "autumn", "summer", "rotate", "deploy", "vault", "infra"]
    word = rng.choice(base_words).capitalize()
    year = rng.choice(["2024", "2025", "2026"])
    sep = rng.choice(["!", "#", "$", "@"])
    return f"{word}{year}{sep}"


def gen_openssh_private_key(rng):
    """A multi-line OpenSSH private key block.

    The body is random base64-shaped data, not a real key — but it parses as
    structurally similar to `ssh-keygen` output (right line length, base64
    alphabet, BEGIN/END markers, trailing `==` padding). Realistic enough that
    a casual inspection or a grep-based scanner will treat it as one.
    """
    alphabet = string.ascii_letters + string.digits + "+/"
    n_lines = rng.randint(36, 40)
    body = [_rand_chars(rng, alphabet, 70) for _ in range(n_lines)]
    body.append(_rand_chars(rng, alphabet, 56) + "==")
    return (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + "\n".join(body)
        + "\n-----END OPENSSH PRIVATE KEY-----\n"
    )


def gen_openssh_public_key(rng, comment):
    """Single-line `ssh-rsa AAAA... comment`."""
    alphabet = string.ascii_letters + string.digits + "+/"
    body = _rand_chars(rng, alphabet, 372) + "=="
    return f"ssh-rsa {body} {comment}\n"


# --- full file bodies -----------------------------------------------------------

def gen_aws_credentials_file(rng, region="us-east-1"):
    akid = gen_aws_access_key_id(rng)
    secret = gen_aws_secret_access_key(rng)
    staging_akid = gen_aws_access_key_id(rng)
    staging_secret = gen_aws_secret_access_key(rng)
    return (
        f"[default]\n"
        f"aws_access_key_id = {akid}\n"
        f"aws_secret_access_key = {secret}\n"
        f"region = {region}\n"
        f"\n"
        f"[staging]\n"
        f"aws_access_key_id = {staging_akid}\n"
        f"aws_secret_access_key = {staging_secret}\n"
        f"region = {region}\n"
    )


def gen_aws_config_file(rng, region="us-east-1"):
    return (
        f"[default]\n"
        f"region = {region}\n"
        f"output = json\n"
        f"\n"
        f"[profile staging]\n"
        f"region = {region}\n"
        f"output = json\n"
    )


def gen_gitconfig_file(rng, persona):
    email = f"{persona.username}@acme.corp"
    return (
        f"[user]\n"
        f"\tname = {persona.full_name}\n"
        f"\temail = {email}\n"
        f"[init]\n"
        f"\tdefaultBranch = main\n"
        f"[core]\n"
        f"\teditor = vim\n"
        f"[push]\n"
        f"\tdefault = simple\n"
        f"[credential]\n"
        f"\thelper = store\n"
    )


def gen_git_credentials_file(rng, persona):
    pat = gen_github_pat(rng)
    return f"https://{persona.username}:{pat}@github.com\n"


_DEFAULT_BASH_HISTORY_POOL = [
    "ls",
    "cd projects",
    "git status",
    "git pull",
    "git checkout -b fix/payments-retry",
    "vim README.md",
    "sudo apt update",
    "sudo apt install -y jq",
    "ssh db-prod-01",
    "ssh api-prod-03",
    "kubectl get pods -n payments",
    "kubectl logs payments-api-7d9f -f",
    "docker ps",
    "docker compose up -d",
    "aws s3 ls s3://acme-billing-exports/",
    "aws sts get-caller-identity",
    "psql -h db-prod-01 -U {user} billing",
    "tail -f /var/log/nginx/access.log",
    "htop",
    "df -h",
    "free -h",
    "history",
    "cd ~/projects/payments-api",
    "source venv/bin/activate",
    "pytest tests/unit -q",
    "python manage.py migrate",
    "curl https://api.acme.corp/health",
    "cat notes.md",
    "vim ~/.bashrc",
    "exit",
]


def gen_bash_history(rng, persona):
    """A persona-consistent recent shell history. If the persona declares a
    `bash_history_pool` in its YAML, sample from that; otherwise fall back
    to the generic developer pool.
    """
    pool = list(persona.bash_history_pool or _DEFAULT_BASH_HISTORY_POOL)
    rng.shuffle(pool)
    chosen = pool[: rng.randint(18, 26)]
    return "\n".join(line.replace("{user}", persona.username) for line in chosen) + "\n"


def gen_passwd_file(personas):
    """Synthesize a plausible /etc/passwd for the host given a list of
    `Persona` objects. Includes standard system entries plus one line per
    persona at their declared UID."""
    lines = [
        "root:x:0:0:root:/root:/bin/bash",
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin",
        "sys:x:3:3:sys:/dev:/usr/sbin/nologin",
        "sync:x:4:65534:sync:/bin:/bin/sync",
        "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin",
        "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin",
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
        "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin",
        "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
        "systemd-network:x:101:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin",
        "systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin",
        "messagebus:x:103:106::/nonexistent:/usr/sbin/nologin",
        "sshd:x:108:65534::/run/sshd:/usr/sbin/nologin",
    ]
    for p in personas:
        uid = persona_uid(p)
        gid = persona_gid(p)
        gecos = p.full_name or p.username
        lines.append(f"{p.username}:x:{uid}:{gid}:{gecos},,,:{p.home}:{p.shell}")
    return "\n".join(lines) + "\n"


def gen_group_file(personas):
    """Synthesize /etc/group with persona memberships in standard groups."""
    # Known shared groups -> GID. Unknown groups land at >=1000.
    known_gid = {
        "root": 0, "daemon": 1, "bin": 2, "sys": 3, "adm": 4,
        "tty": 5, "disk": 6, "lp": 7, "mail": 8, "www-data": 33,
        "backup": 34, "sudo": 27, "kvm": 999, "docker": 998,
        "nogroup": 65534, "ssh": 117,
    }
    members = {g: set() for g in known_gid}
    extra_groups = {}  # username -> uid for primary group rows
    for p in personas:
        primary_gid = persona_gid(p)
        extra_groups[p.username] = primary_gid
        for g in p.groups:
            if g == p.username:
                continue
            members.setdefault(g, set()).add(p.username)

    lines = []
    # Standard groups first, sorted by GID
    for g in sorted(known_gid, key=lambda x: known_gid[x]):
        gid = known_gid[g]
        m = ",".join(sorted(members.get(g, set())))
        lines.append(f"{g}:x:{gid}:{m}")
    # Per-persona primary groups
    for user, gid in sorted(extra_groups.items(), key=lambda kv: kv[1]):
        lines.append(f"{user}:x:{gid}:")
    return "\n".join(lines) + "\n"


def gen_auth_log_from_logins(login_entries, hostname, n_pairs=12):
    """Render N most recent SSH login pairs as auth.log-style lines.

    `login_entries` is an iterable of dicts with keys: user, ip, start (datetime).
    Each login becomes two lines (Accepted publickey + session opened).
    """
    entries = list(login_entries)[-n_pairs:]
    lines = []
    pid = 12041
    for e in entries:
        ts = e["start"].strftime("%b %e %H:%M:%S").replace("  ", " ")
        # Ensure month-day has consistent spacing like real syslog
        user = e["user"]
        ip = e["ip"]
        uid = e.get("uid", 1000)
        lines.append(f"{ts} {hostname} sshd[{pid}]: Accepted publickey for {user} from {ip} port 49001 ssh2: RSA SHA256:nKvxe1Jh/N1Wq8h9yLW0+sGpYj7iWGfJ+u8z0XlMnzc")
        lines.append(f"{ts} {hostname} sshd[{pid}]: pam_unix(sshd:session): session opened for user {user}(uid={uid}) by (uid=0)")
        pid += 13
    return "\n".join(lines) + "\n"


def gen_ssh_config_file(rng, persona):
    return (
        f"Host db-prod-01\n"
        f"    HostName 10.20.30.41\n"
        f"    User {persona.username}\n"
        f"    IdentityFile ~/.ssh/id_rsa\n"
        f"\n"
        f"Host api-prod-03\n"
        f"    HostName 10.20.30.83\n"
        f"    User {persona.username}\n"
        f"    IdentityFile ~/.ssh/id_rsa\n"
        f"\n"
        f"Host github.com\n"
        f"    User git\n"
        f"    IdentityFile ~/.ssh/id_rsa\n"
    )


# --- top-level honeytoken set --------------------------------------------------

@dataclass
class Honeytokens:
    """Pre-rendered file bodies the orchestrator treats as ground truth for
    this session. The LLM is shown these as facts in its system prompt so any
    `cat` / `grep` / `head` on them returns consistent bytes.
    """
    aws_credentials: str = ""
    aws_config: str = ""
    gitconfig: str = ""
    git_credentials: str = ""
    bash_history: str = ""
    ssh_config: str = ""
    ssh_private_key: str = ""
    ssh_public_key: str = ""

    files: dict = field(default_factory=dict)

    @classmethod
    def generate_for(cls, persona, rng):
        ht = cls(
            aws_credentials=gen_aws_credentials_file(rng),
            aws_config=gen_aws_config_file(rng),
            gitconfig=gen_gitconfig_file(rng, persona),
            git_credentials=gen_git_credentials_file(rng, persona),
            bash_history=gen_bash_history(rng, persona),
            ssh_config=gen_ssh_config_file(rng, persona),
            ssh_private_key=gen_openssh_private_key(rng),
            ssh_public_key=gen_openssh_public_key(rng, f"{persona.username}@{persona.hostname}"),
        )
        # Canonical absolute POSIX paths only. The VFS handles ~ expansion
        # and relative-path resolution at the call site.
        home = persona.home
        ht.files = {
            f"{home}/.aws/credentials": ht.aws_credentials,
            f"{home}/.aws/config": ht.aws_config,
            f"{home}/.gitconfig": ht.gitconfig,
            f"{home}/.git-credentials": ht.git_credentials,
            f"{home}/.bash_history": ht.bash_history,
            f"{home}/.ssh/config": ht.ssh_config,
            f"{home}/.ssh/id_rsa": ht.ssh_private_key,
            f"{home}/.ssh/id_rsa.pub": ht.ssh_public_key,
        }
        return ht
