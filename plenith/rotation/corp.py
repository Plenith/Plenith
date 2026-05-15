"""Synthetic corp identity — the "company" the decoys belong to.

Every persona, hostname, ssh_config IP, gitconfig email, mysql database
name, and SSH banner derives from this CorpIdentity object. Two
Plenith deployments with different `deployment_id`s look like two
genuinely different companies' infrastructure, not two copies of the
same honeypot.

The identity is generated DETERMINISTICALLY from a DeploymentSeed, so
the same seed always produces the same corp — no surprise drift between
restarts, and the content manifest is reproducible.
"""
import random
from dataclasses import asdict, dataclass, field

from .seeds import DeploymentSeed

# ---------------------------------------------------------------------------
# Lexicons. These are intentionally bland — the goal is "looks like a normal
# enterprise corp," not "guess the real company." If a deployer wants more
# realistic names they can override the lexicon via `CorpIdentity.from_seed(
# seed, lexicon=...)`.
# ---------------------------------------------------------------------------

_INDUSTRIES = [
    ("fin",     "financial-services"),  # short prefix, long name
    ("med",     "healthcare"),
    ("mfg",     "manufacturing"),
    ("ret",     "retail"),
    ("log",     "logistics"),
    ("ins",     "insurance"),
    ("trv",     "travel"),
    ("med",     "media"),
    ("edu",     "education"),
    ("ene",     "energy"),
]

_SUFFIXES = ["corp", "io", "tech", "labs", "systems", "industries", "global", "group"]
_PREFIXES = [
    "atlas", "nexus", "vertex", "summit", "ridge", "lattice", "vector",
    "axiom", "helio", "luna", "delta", "vega", "kestrel", "harbor",
    "boreal", "aurora", "meridian", "polaris", "obsidian", "cypress",
]

_APP_BASES = [
    "payments", "billing", "auth", "search", "checkout", "analytics",
    "reports", "ledger", "messaging", "fulfilment", "catalog", "inventory",
    "settlement", "compliance", "ingest",
]

_ENV_TIERS = ["prod", "stage", "dev", "qa", "int"]

# A short pool of internal hostname patterns. Each deployment picks ONE
# pattern so all decoy hostnames share a style — real corps don't mix
# `db-prod-01` with `prd-db.01` randomly.
_HOSTNAME_PATTERNS = [
    "{app}-{env}-{num:02d}",       # payments-prod-01
    "{env}-{app}-{num:02d}",       # prod-payments-01
    "{app}{num:02d}.{env}",        # payments01.prod
    "{env}{num:02d}-{app}",        # prod01-payments
]

# Reserved RFC1918 ranges — we sample a /16 inside 10.0.0.0/8 for the
# corp's "production" network. Two deployments will land on different
# /16s with overwhelming probability, defeating IP-based fingerprinting.
_PRIVATE_PREFIX = "10"  # we stay in 10.0.0.0/8

# ---------------------------------------------------------------------------
# Generated identity
# ---------------------------------------------------------------------------

@dataclass
class CorpIdentity:
    """All the strings a single Plenith deployment pretends to belong to.

    These propagate into:
      * persona.full_name, persona.username (when generated)
      * gitconfig user.email   → {username}@{corp_domain}
      * mysql my.cnf database  → {industry_short}_billing or similar
      * ssh_config Host lines  → {hostname_a}, {hostname_b}, ...
      * ssh banner             → "Welcome to {corp_name} - {os_ver}"
      * /etc/issue, motd       → corp_name + an industry-flavored tagline
      * fake-mysql banner      → "{corp_short}-mysql"
    """
    industry_short: str          # "fin"
    industry_long: str           # "financial-services"
    corp_short: str              # "atlas"
    corp_suffix: str             # "corp"
    corp_name: str               # "Atlas Corp"
    corp_domain: str             # "atlas.corp"
    prod_subnet: str             # "10.42.0.0/16"
    hostname_pattern: str        # "{app}-{env}-{num:02d}"
    decoy_hosts: list[str] = field(default_factory=list)  # 3 generated names
    db_database_name: str = ""   # "fin_billing"
    db_admin_password: str = ""  # rotated decoy password
    ssh_host_fingerprint: str = ""
    auth_log_fingerprint: str = ""
    motd_tagline: str = ""

    # --- factory ----------------------------------------------------------

    @classmethod
    def from_seed(cls, seed: DeploymentSeed) -> "CorpIdentity":
        rng = seed.rng_for("corp_identity")

        industry_short, industry_long = rng.choice(_INDUSTRIES)
        corp_short = rng.choice(_PREFIXES)
        corp_suffix = rng.choice(_SUFFIXES)
        corp_name = f"{corp_short.capitalize()} {corp_suffix.capitalize()}"
        # Domain stays lowercase, suffix-less to look natural ("atlas.corp"
        # not "atlas.corp.corp").
        domain_tld = "corp" if corp_suffix != "corp" else rng.choice(["co", "io", "net"])
        corp_domain = f"{corp_short}.{domain_tld}"

        # Sample a /16 inside 10.0.0.0/8.
        net_octet = rng.randint(1, 254)
        prod_subnet = f"{_PRIVATE_PREFIX}.{net_octet}.0.0/16"

        pattern = rng.choice(_HOSTNAME_PATTERNS)

        # Three rotating decoy hosts. We keep "db" / "api" / "bastion"
        # roles because the orchestrator's heuristics key off them.
        envs_pool = list(_ENV_TIERS)
        rng.shuffle(envs_pool)
        env = envs_pool[0]  # one consistent env tier
        hosts = []
        for app in ("db", "api", "bastion"):
            n = rng.randint(1, 9)
            hosts.append(pattern.format(app=app, env=env, num=n))

        db_database_name = f"{industry_short}_{rng.choice(['billing', 'ledger', 'core', 'ops'])}"
        db_admin_password = _gen_password(rng)

        return cls(
            industry_short=industry_short,
            industry_long=industry_long,
            corp_short=corp_short,
            corp_suffix=corp_suffix,
            corp_name=corp_name,
            corp_domain=corp_domain,
            prod_subnet=prod_subnet,
            hostname_pattern=pattern,
            decoy_hosts=hosts,
            db_database_name=db_database_name,
            db_admin_password=db_admin_password,
            ssh_host_fingerprint=_gen_ssh_fp(seed.rng_for("ssh_host_fingerprint")),
            auth_log_fingerprint=_gen_ssh_fp(seed.rng_for("auth_log_fingerprint")),
            motd_tagline=_gen_motd_tagline(rng, industry_long, corp_name),
        )

    # --- queries used by the orchestrator -------------------------------

    def prod_ip(self, host_index: int) -> str:
        """Stable per-host /32 inside the corp's prod subnet. host_index
        is just the position in `decoy_hosts` (0 = db, 1 = api, 2 = bastion)."""
        base = self.prod_subnet.split("/")[0]  # "10.42.0.0"
        octets = base.split(".")
        last = (host_index * 17 + 41) % 254 + 1  # arbitrary stable offset
        return f"{octets[0]}.{octets[1]}.20.{last}"

    def to_dict(self) -> dict:
        return asdict(self)

# ---------------------------------------------------------------------------
# Helpers — kept module-local because they're only useful when paired
# with a CorpIdentity context. Each takes its own rng so callers control
# determinism.
# ---------------------------------------------------------------------------

def _gen_password(rng: random.Random) -> str:
    """A rotated decoy password — placed in fake my.cnf / shell history /
    etc. Strong-looking format (the goal is to look juicy, not actually
    BE secure; nothing in Plenith is reachable with this password)."""
    words = ["Vault", "Backup", "Nightly", "Vault", "Rotate", "Failover",
             "Tunnel", "Audit", "Phoenix", "Cascade", "Tempo", "Hangar"]
    year = rng.choice(["2024", "2025", "2026"])
    sym = rng.choice(["!", "#", "$", "@", "%"])
    suffix = rng.choice(["", "x", "9", "Z", "_v2"])
    return f"{rng.choice(words)}{year}{sym}{suffix}"

_SSH_FP_ALPHABET = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)

def _gen_ssh_fp(rng: random.Random) -> str:
    """43-char base64-shaped SHA256 fingerprint suffix. Real format is
    `SHA256:<43 chars>`; we return only the trailing 43 since callers
    prepend the algorithm label in the right context."""
    return "".join(rng.choices(_SSH_FP_ALPHABET, k=43))

_MOTD_TAGLINES = [
    "internal use only — see {corp_domain}/security",
    "authorized {industry} personnel only — log out when done",
    "{corp_name} {industry} operations — handled with care",
    "session monitored under {corp_name} acceptable-use policy",
    "{corp_name} internal — escalations to it-ops@{corp_domain}",
]

def _gen_motd_tagline(rng: random.Random, industry: str, corp_name: str) -> str:
    template = rng.choice(_MOTD_TAGLINES)
    return template.format(
        industry=industry,
        corp_name=corp_name,
        corp_domain=f"{corp_name.split()[0].lower()}.corp",
    )
