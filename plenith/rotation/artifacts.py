"""Rotated artifact bodies.

For every static decoy artifact in the codebase, we expose a generator
here that produces a deployment-and-epoch-specific variant. Callers pass
a `DeploymentSeed` + `CorpIdentity`; this module returns ready-to-plant
file bodies referencing the right corp identity.

Each generator is deterministic per (seed, purpose) — calling it twice
with the same inputs returns byte-identical output, which is critical
for the orchestrator's stateful filesystem: an attacker who `cat`s a
file twice must see the same bytes.
"""
import datetime as _dt
from dataclasses import dataclass
from typing import List

from .corp import CorpIdentity
from .seeds import DeploymentSeed


# ---------------------------------------------------------------------------
# Templates. Each has multiple "variants" we pick between via the seeded
# RNG. More variants = more divergence between deployments.
# ---------------------------------------------------------------------------

_SUDOERS_TEMPLATES = [
    # variant 1 — ansible-flavored
    """# Compat overrides for legacy services. Do not edit by hand.
# Generated {date} by ansible role ops.{role_name} v{version}.

Defaults  !syslog
Defaults  targetpw
%wheel    ALL=(ALL) NOPASSWD: ALL
{deploy_user}    ALL=(ALL) NOPASSWD: /usr/bin/apt-get, /usr/bin/dpkg, /bin/systemctl
""",
    # variant 2 — terraform-flavored
    """# Managed by Terraform — see {corp_domain}/iac/sudoers.tf
# DO NOT EDIT. Last applied {date} by tfops@{corp_domain}.

Defaults env_reset
Defaults timestamp_timeout=120
%ops    ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart {app_name}, /usr/bin/journalctl
{deploy_user}    ALL=(ALL) NOPASSWD: ALL
""",
    # variant 3 — puppet-flavored
    """# This file is under Puppet management. Local edits will be overwritten.
# Source: puppet:///modules/{corp_short}_compat/sudoers/legacy
# Updated: {date} (catalog run {run_id}).

Defaults  !syslog
%{corp_short}_ops  ALL=(ALL) NOPASSWD: /usr/bin/{app_name}-control
{deploy_user}      ALL=(ALL) NOPASSWD: /usr/bin/apt-get
""",
]

_MYSQL_TEMPLATES = [
    """[client]
user     = root
password = {db_password}
host     = {db_host}
port     = 3306
database = {db_database}

[mysqldump]
user     = backup_admin
password = {backup_password}

[mysqld]
bind-address    = 127.0.0.1
skip-name-resolve
log-bin         = /var/log/mysql/mysql-bin.log
""",
    """# {corp_name} primary database config — DO NOT distribute.
[client]
host       = {db_host}
port       = 3306
user       = svc_app
password   = {db_password}
database   = {db_database}
default-character-set = utf8mb4

[mysql]
prompt     = "{corp_short} \\d> "

[mysqldump]
user       = svc_backup
password   = {backup_password}
single-transaction = true
""",
    """[client]
user     = root
password = {db_password}
socket   = /var/run/mysqld/mysqld.sock

[mysqld]
datadir = /var/lib/mysql
log-error = /var/log/mysql/error.log
bind-address = 127.0.0.1

[{corp_short}_replication]
user     = repl_admin
password = {backup_password}
host     = {db_host}
""",
]

_BANNER_TEMPLATES = [
    "{corp_name} - {os_ver}\n{motd_tagline}\n",
    "*** {corp_name} ({industry_long}) ***\n{motd_tagline}\n",
    "Welcome to {corp_name}.\n{motd_tagline}\n\nLast login: {last_login}\n",
    "{corp_name} {os_ver}\n--\n{motd_tagline}\n",
]

_ROLE_NAMES = ["legacy-compat", "platform-base", "ops-toolkit", "appfleet-core", "sec-baseline"]
_OS_VERSIONS = [
    "Ubuntu 22.04.4 LTS", "Ubuntu 22.04.5 LTS",
    "Debian GNU/Linux 12 (bookworm)",
    "Rocky Linux 9.3 (Blue Onyx)",
    "Amazon Linux 2023.4.20240916",
]
_DEPLOY_USERS = ["deploy", "ansible", "tfops", "puppet", "ops-bot", "ci-runner"]


# ---------------------------------------------------------------------------
# Top-level artifacts
# ---------------------------------------------------------------------------

@dataclass
class RotatedArtifacts:
    """Bundle of all rotated bodies for one (deployment_id, epoch) pair."""
    sudoers_compat: str
    mysql_my_cnf: str
    ssh_banner: str
    motd: str
    bash_history_pool_extras: List[str]
    ssh_config: str

    @classmethod
    def generate(cls, seed: DeploymentSeed, corp: CorpIdentity) -> "RotatedArtifacts":
        return cls(
            sudoers_compat=gen_sudoers(seed, corp),
            mysql_my_cnf=gen_mysql_cnf(seed, corp),
            ssh_banner=gen_ssh_banner(seed, corp),
            motd=gen_motd(seed, corp),
            bash_history_pool_extras=gen_bash_history_pool(seed, corp),
            ssh_config=gen_rotated_ssh_config(seed, corp),
        )


# ---------------------------------------------------------------------------
# Generators — each takes (seed, corp), returns a string body.
# ---------------------------------------------------------------------------

def gen_sudoers(seed: DeploymentSeed, corp: CorpIdentity) -> str:
    """Rotated /etc/sudoers.d/zzz_compat. Used by
    responses._plant_sudo_vulnerability when rotation is enabled."""
    rng = seed.rng_for("sudoers_compat")
    template = rng.choice(_SUDOERS_TEMPLATES)
    role_name = rng.choice(_ROLE_NAMES)
    version = f"{rng.randint(1, 6)}.{rng.randint(0, 14)}.{rng.randint(0, 30)}"
    deploy_user = rng.choice(_DEPLOY_USERS)
    date = _stable_date(rng)
    return template.format(
        date=date,
        role_name=role_name,
        version=version,
        deploy_user=deploy_user,
        corp_domain=corp.corp_domain,
        corp_short=corp.corp_short,
        app_name=corp.db_database_name.split("_")[0],
        run_id=f"{rng.randrange(10**8, 10**9):x}",
    )


def gen_mysql_cnf(seed: DeploymentSeed, corp: CorpIdentity) -> str:
    """Rotated /etc/mysql/my.cnf. Used by responses._spawn_fake_mysql."""
    rng = seed.rng_for("mysql_my_cnf")
    template = rng.choice(_MYSQL_TEMPLATES)
    backup_password = corp.db_admin_password + rng.choice(["_backup", ".bak", "Backup"])
    return template.format(
        db_password=corp.db_admin_password,
        backup_password=backup_password,
        db_host=corp.decoy_hosts[0],  # the "db" host
        db_database=corp.db_database_name,
        corp_short=corp.corp_short,
        corp_name=corp.corp_name,
    )


def gen_ssh_banner(seed: DeploymentSeed, corp: CorpIdentity) -> str:
    """Rotated SSH login banner. Drop this into config.yaml `ssh.banner`
    at deploy time, or query at runtime."""
    rng = seed.rng_for("ssh_banner")
    template = rng.choice(_BANNER_TEMPLATES)
    return template.format(
        corp_name=corp.corp_name,
        industry_long=corp.industry_long,
        motd_tagline=corp.motd_tagline,
        os_ver=rng.choice(_OS_VERSIONS),
        last_login=_stable_date(rng, fmt="%a %b %d %H:%M:%S %Y"),
    )


def gen_motd(seed: DeploymentSeed, corp: CorpIdentity) -> str:
    """Rotated /etc/motd."""
    rng = seed.rng_for("motd")
    return (
        f"=== {corp.corp_name} ===\n"
        f"{corp.motd_tagline}\n"
        f"\n"
        f"Production subnet: {corp.prod_subnet}\n"
        f"For ops escalations: it-ops@{corp.corp_domain}\n"
    )


def gen_bash_history_pool(seed: DeploymentSeed, corp: CorpIdentity) -> List[str]:
    """A handful of corp-flavored history entries, merged into the
    default pool in synthetic.gen_bash_history when rotation is enabled."""
    rng = seed.rng_for("bash_history_pool")
    out: List[str] = []
    out.append(f"ssh {corp.decoy_hosts[0]}")  # ssh db host
    out.append(f"ssh {corp.decoy_hosts[1]}")  # ssh api host
    out.append(
        f"mysql -h {corp.decoy_hosts[0]} -u root -p {corp.db_database_name}"
    )
    out.append(
        f"psql -h {corp.decoy_hosts[0]} {corp.db_database_name}"
    )
    out.append(f"curl https://api.{corp.corp_domain}/health")
    out.append(f"git clone git@github.com:{corp.corp_short}/{corp.industry_short}-ops.git")
    out.append(f"vim ~/projects/{corp.industry_short}-{corp.corp_short}/notes.md")
    # Some idle utility lines for realism
    for _ in range(rng.randint(2, 4)):
        out.append(rng.choice([
            "df -h", "free -m", "uptime", "htop", "tail -f /var/log/syslog",
        ]))
    return out


def gen_rotated_ssh_config(seed: DeploymentSeed, corp: CorpIdentity) -> str:
    """Rotated ~/.ssh/config — Host blocks reference the corp's decoy
    hostnames with IPs from the corp's prod subnet. Replaces
    synthetic.gen_ssh_config_file when rotation is enabled.

    No `User` directive per host — typical corp ssh_configs rely on the
    default user (current OS user); pinning would just leak the username
    into the rotated artifact and complicate per-session re-templating.
    """
    rng = seed.rng_for("ssh_config")
    lines: List[str] = []
    for i, host in enumerate(corp.decoy_hosts):
        lines.append(f"Host {host}")
        lines.append(f"    HostName {corp.prod_ip(i)}")
        lines.append(f"    IdentityFile ~/.ssh/id_rsa")
        # Optional Port jitter — half the corps use a non-standard SSH port
        if rng.random() < 0.4:
            lines.append(f"    Port {rng.choice([22, 2222, 2200, 2022])}")
        lines.append("")
    # GitHub block is universal; pin to corp's GH org
    lines.append("Host github.com")
    lines.append("    User git")
    lines.append(f"    HostName github.com")
    lines.append(f"    IdentityFile ~/.ssh/id_rsa_{corp.corp_short}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _stable_date(rng, fmt: str = "%Y-%m-%d") -> str:
    """A plausible recent date, deterministic per RNG state. We bias
    toward "this quarter" but jitter by ±90 days so different artifacts
    don't all share one date."""
    # Today is 2026-05-12 per the project memory; we sample within a
    # ±120 day window around 2026-04-01 (Q2 start) to look "recent."
    base = _dt.date(2026, 4, 1)
    offset = rng.randint(-120, 30)
    d = base + _dt.timedelta(days=offset)
    if fmt == "%Y-%m-%d":
        return d.isoformat()
    return d.strftime(fmt)
