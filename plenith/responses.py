"""Side-effecting executors for heuristic actions.

When `decide_action` (in heuristics.py) returns an action, the orchestrator
calls `responses.execute(action, session)` to apply real side effects in
the VFS — drop a decoy file, plant a hint, etc. This closes the deception
loop: an observed attacker behavior produces a visible response on the
honeypot that the attacker may then engage with (the "swallow" signal).

Actions without an executor here are no-ops (alerts that are purely SOC-
visible, not deception-visible).
"""
import random

from .synthetic import gen_aws_credentials_file


def execute(action, session):
    """Dispatch to the right executor based on action name. Idempotent —
    each rule only fires once per engagement (via its `alerted_*` flag),
    so this is invoked at most once per action.
    """
    name = action.get("action", "")
    fn = _REGISTRY.get(name)
    if fn is None:
        return
    try:
        fn(session, action)
    except Exception:
        # Best-effort. A failed response shouldn't kill the session.
        import logging
        logging.getLogger("plenith.responses").exception(
            "executor failed for action %r", name
        )


# --- individual executors ---------------------------------------------------

def _plant_sudo_vulnerability(session, action):
    """Drop a misconfigured-looking sudoers file the attacker may follow.

    A real attacker after `sudo -l` will often check /etc/sudoers.d. We
    seed a deliberately suspicious file there. Reading it fires the
    decoy-swallowed alert (medium) — we now know they're following the trail.

    When a ContentRotator is attached to the session, the body is a
    deployment-scoped variant; otherwise we fall back to a static body
    for backward-compat. Counter-AI trap (if armed) is embedded last
    so it sees the final, rotation-aware body.
    """
    from .counter_ai import maybe_inject_trap
    rotator = getattr(session, "rotator", None)
    if rotator is not None and rotator.is_enabled:
        body = rotator.artifacts.sudoers_compat
    else:
        body = (
            "# Compat overrides for legacy services. Do not edit by hand.\n"
            "# Generated 2026-03-14 by ansible role ops.legacy-compat v1.7.3.\n"
            "\n"
            "Defaults  !syslog\n"
            "Defaults  targetpw\n"
            "%wheel    ALL=(ALL) NOPASSWD: ALL\n"
            "deploy    ALL=(ALL) NOPASSWD: /usr/bin/apt-get, /usr/bin/dpkg, /bin/systemctl\n"
        )
    body = maybe_inject_trap(session, body, kind="config")
    session.plant_decoy("/etc/sudoers.d/zzz_compat", body)


def _spawn_fake_mysql(session, action):
    """Drop a /etc/mysql/my.cnf with juicy connection details.

    Real attackers, after probing for MySQL, look for ambient config in
    /etc/mysql/. Planting a my.cnf with admin creds is a classic decoy.

    Rotation-aware: when the session has a ContentRotator, the body
    references the deployment's corp hostnames and a rotated password.
    Counter-AI trap (if armed) is appended as a fake mysqld comment.
    """
    from .counter_ai import maybe_inject_trap
    rotator = getattr(session, "rotator", None)
    if rotator is not None and rotator.is_enabled:
        body = rotator.artifacts.mysql_my_cnf
    else:
        body = (
            "[client]\n"
            "user     = root\n"
            "password = M3taD4ta!2026\n"
            "host     = billing-db\n"
            "port     = 3306\n"
            "database = billing\n"
            "\n"
            "[mysqldump]\n"
            "user     = backup_admin\n"
            "password = nightly_backup_2026!\n"
            "\n"
            "[mysqld]\n"
            "bind-address    = 127.0.0.1\n"
            "skip-name-resolve\n"
            "log-bin         = /var/log/mysql/mysql-bin.log\n"
        )
    body = maybe_inject_trap(session, body, kind="config")
    session.plant_decoy("/etc/mysql/my.cnf", body)


def _plant_aws_credentials(session, action):
    """Drop a second, more attractive AWS credentials file.

    The original ~/.aws/credentials is the bait. After enough idle time
    we plant ~/.aws/dev_credentials with a different region (eu-west-1)
    so it looks like a developer's secondary account — more tempting than
    the primary because it suggests broader access.
    """
    rng = random.Random(session.engagement_id + ":dev")
    body = gen_aws_credentials_file(rng, region="eu-west-1")
    # Sweeten with a comment hinting at dev/staging privileges
    sweetened = "# dev-account creds — broader IAM than [default], use sparingly\n" + body
    session.plant_decoy(
        f"{session.persona.home}/.aws/dev_credentials",
        sweetened,
        is_credential=True,
    )


_REGISTRY = {
    "plant_sudo_vulnerability": _plant_sudo_vulnerability,
    "spawn_fake_mysql": _spawn_fake_mysql,
    "plant_aws_credentials": _plant_aws_credentials,
}
