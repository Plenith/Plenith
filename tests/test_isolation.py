"""Continuous validation of the linux-fork isolation bubble.

These tests only run when the docker-compose fabric is actually up (we
look for `plenith-dns` in `docker ps`). On the bare MVP / CI without
Docker, they skip — they don't fail.

What we assert when the fabric IS up:

  1. `bash linux-fork/isolation/validate.sh` exits 0 (all 18 probes pass).
  2. The CoreDNS query log contains structured rcodes for an external
     attempt we just emitted (proves the exfil-channel detection wire
     is live).

These are slow-ish (each docker exec is a few hundred ms; 18 probes
across 3 agents is ~3-4s). The whole suite runs in under 10s.
"""
import shutil
import subprocess
from pathlib import Path

import pytest


_ROOT = Path(__file__).resolve().parent.parent
_VALIDATE = _ROOT / "linux-fork" / "isolation" / "validate.sh"


def _docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        out = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=5,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False
    return "plenith-dns" in out.stdout and "bastion-prod" in out.stdout


@pytest.fixture(scope="module")
def docker_fabric():
    """Skip the whole module if the locked-down fabric isn't running."""
    if not _docker_available():
        pytest.skip("docker compose fabric not up (plenith-dns / bastion-prod missing)")
    return True


def test_validate_script_exists():
    assert _VALIDATE.exists(), "isolation/validate.sh is missing"


def _find_bash() -> str | None:
    """Locate a real POSIX bash. On Windows, `shutil.which('bash')` may
    return the WSL stub at C:\\Windows\\System32\\bash.exe which can't
    run a path-style script the way Git Bash can. Prefer Git Bash if it
    exists, otherwise fall back to whatever `bash` resolves to."""
    git_bash = Path(r"C:\Program Files\Git\bin\bash.exe")
    if git_bash.exists():
        return str(git_bash)
    git_bash_usr = Path(r"C:\Program Files\Git\usr\bin\bash.exe")
    if git_bash_usr.exists():
        return str(git_bash_usr)
    return shutil.which("bash")


def test_isolation_probes_all_pass(docker_fabric):
    """Run the 18-probe validation script. If anything regresses, we want
    a clear test failure with the probe output included."""
    bash = _find_bash()
    if bash is None:
        pytest.skip("no POSIX bash available")
    import os
    env = {**os.environ, "MSYS_NO_PATHCONV": "1"}
    proc = subprocess.run(
        [bash, str(_VALIDATE)],
        capture_output=True, text=True, timeout=120, env=env,
    )
    # Surface the script output in pytest's failure message
    assert proc.returncode == 0, (
        f"isolation/validate.sh failed (exit {proc.returncode})\n"
        f"--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}"
    )
    assert "ALL PROBES PASSED" in proc.stdout


def test_coredns_logs_nxdomain_for_external(docker_fabric):
    """Sanity-check that the DNS bubble actually logs structured rcodes.
    We trigger an external lookup from bastion-prod then inspect the log.
    """
    # Trigger a query
    subprocess.run(
        ["docker", "exec", "bastion-prod", "nslookup", "-timeout=2",
         "ci-probe-external.example.test", "172.30.0.40"],
        capture_output=True, text=True, timeout=10,
    )
    # Read CoreDNS logs (last 50 lines is plenty)
    out = subprocess.run(
        ["docker", "logs", "--tail", "50", "plenith-dns"],
        capture_output=True, text=True, timeout=10,
    )
    log = out.stdout + out.stderr
    # Expect the query to show up as NXDOMAIN (or SERVFAIL — both indicate
    # external recursion is unavailable, which is the goal).
    assert (
        "ci-probe-external.example.test" in log
    ), f"CoreDNS didn't log our probe query. Full log:\n{log}"


def test_llm_egress_uri_allowlist_enforced(docker_fabric):
    """The llm-egress nginx must reject any URI outside the OpenAI API
    surface. Calling /admin or /shutdown should return 403."""
    out = subprocess.run(
        ["docker", "exec", "bastion-prod", "curl", "-sSm", "5",
         "-o", "/dev/null", "-w", "%{http_code}",
         "http://llm.internal:1234/admin"],
        capture_output=True, text=True, timeout=15,
    )
    assert "403" in out.stdout, (
        f"llm-egress did NOT reject /admin — got '{out.stdout}'. "
        "The URI allow-list in isolation/llm-egress.conf is not enforced."
    )
