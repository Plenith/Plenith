"""After-action report for an attacker session on the linux-fork fabric.

Run this after you've SSH'd through the proxy (`ssh -p 22000 jdoe@127.0.0.1`)
and exited. It reads the docker fabric's shared state + log dirs and prints:

  1. The audit-tool narrative for your engagement (analyst view)
  2. Every alert that fired, by severity
  3. Bytes-on-disk proof that the ROTATED decoys (not the static defaults)
     were planted in your VFS
  4. The CoreDNS log slice that captured covert DNS-exfil queries from
     inside the bubble (everything matching oast/burpcollab/interactsh)
  5. The §4.2 isolation status (re-runs the 18 breakout probes)

No arguments. The locations are hard-coded for the dev-machine fabric.
"""
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_STATE_DIR = _ROOT / "state-docker" / "persistence"
_LOGS_BASE = _ROOT / "state-docker" / "logs"
_PERSONAS  = _ROOT / "personas"
_DEPLOYMENT_ID = "mc-demo-installation-001"
_EPOCH         = "2026Q2"

# Force UTF-8 so terminal output works on Windows cp1252
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError, OSError):
    pass


def color(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m"


def banner(s: str) -> None:
    print()
    print(color("1;36", s))
    print(color("36", "─" * len(s)))


def _load_audit():
    spec = importlib.util.spec_from_file_location("audit", _ROOT / "tools" / "audit.py")
    audit = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(audit)
    return audit


def main() -> int:
    sys.path.insert(0, str(_ROOT))
    audit = _load_audit()

    # --- 1. Engagement narrative ----------------------------------
    banner("[1] Audit-tool narrative for your engagement")
    # Walk every per-host logs dir and aggregate
    logs_dirs = [d for d in _LOGS_BASE.iterdir() if d.is_dir()] if _LOGS_BASE.exists() else []
    all_eng = []
    for d in logs_dirs:
        all_eng.extend(audit.load_engagements(_STATE_DIR, d, _PERSONAS))
    if not all_eng:
        print(color("31", "  no engagements found yet — connect first."))
    for e in all_eng:
        print(f"  {audit.build_narrative(e)}")

    # --- 2. Alerts fired ------------------------------------------
    banner("[2] Alerts the policy fired during your session")
    counts, sev = {}, {}
    for d in logs_dirs:
        for log_file in sorted(d.glob("*.json")):
            try:
                data = json.loads(log_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            for a in data.get("actions_taken", []):
                counts[a["action"]] = counts.get(a["action"], 0) + 1
                sev[a["action"]] = a.get("severity", "?")
    if not counts:
        print(color("33", "  (none — your session didn't trigger any heuristic)"))
    else:
        sev_rank = {"critical": 0, "high": 1, "medium": 2, "info": 3}
        for action in sorted(counts, key=lambda k: (sev_rank.get(sev[k], 9), k)):
            bar = "*" * min(counts[action], 6)
            tag = sev[action]
            color_for_sev = {"critical": "31", "high": "33", "medium": "36", "info": "90"}.get(tag, "0")
            print(f"  [{color(color_for_sev, tag.rjust(8))}]  {action:<28s}  {bar}  ({counts[action]}x)")

    # --- 3. Rotation proof ----------------------------------------
    banner(f"[3] Rotated decoy bytes-on-disk ({_DEPLOYMENT_ID} / {_EPOCH})")
    # Re-derive what rotated content SHOULD be planted, and grep for it
    # in the persisted VFS snapshot.
    from plenith.rotation import ContentRotator, DeploymentSeed
    r = ContentRotator.from_seed(DeploymentSeed(_DEPLOYMENT_ID, _EPOCH))
    expected_corp = r.corp.corp_domain  # "vertex.corp"
    expected_pw   = r.corp.db_admin_password  # "Audit2026@_v2"

    # Read the persistence file (VFS snapshot)
    vfs_blobs = []
    for f in _STATE_DIR.glob("*.json"):
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for path, body in d.get("vfs", {}).get("files", {}).items():
            if isinstance(body, str):
                vfs_blobs.append((path, body))

    sudoers_planted = any(
        path.endswith("/zzz_compat") and expected_corp in body
        for path, body in vfs_blobs
    )
    mysql_planted = any(
        path.endswith("/my.cnf") and (expected_pw[:8] in body or r.corp.db_database_name in body)
        for path, body in vfs_blobs
    )
    static_marker_absent = not any(
        "M3taD4ta!2026" in body or "v1.7.3" in body
        for _, body in vfs_blobs
    )

    def line(label, ok):
        icon = color("32", "[ok]") if ok else color("31", "[!!]")
        print(f"  {icon}  {label}")
    line(f"sudoers planted with rotated {expected_corp!r} marker", sudoers_planted)
    line(f"my.cnf planted with rotated password {expected_pw!r}", mysql_planted)
    line("no static M3taD4ta!2026 / v1.7.3 leakage", static_marker_absent)

    # --- 4. CoreDNS exfil log -------------------------------------
    banner("[4] CoreDNS exfil log (SIEM-tailable covert-channel detector)")
    out = subprocess.run(
        ["docker", "logs", "--tail", "200", "plenith-dns"],
        capture_output=True, text=True, timeout=10,
    )
    log_lines = (out.stdout + out.stderr).splitlines()
    interesting = [
        l for l in log_lines
        if "oast" in l or "burpcoll" in l or "interactsh" in l
        or l.endswith("NXDOMAIN") or l.endswith("SERVFAIL")
    ]
    if not interesting:
        print(color("90", "  (no exfil queries hit CoreDNS — try `nslookup x.oast.live` "
                          "from inside the container)"))
    for l in interesting[-12:]:
        if any(s in l for s in ("oast", "burpcoll", "interactsh")):
            print(color("33", f"  > {l}"))
        else:
            print(f"    {l}")

    # --- 5. Isolation re-check ------------------------------------
    banner("[5] §4.2 isolation — re-running 18 breakout probes")
    bash = "C:\\Program Files\\Git\\bin\\bash.exe"
    if not Path(bash).exists():
        bash = "bash"
    validate = _ROOT / "linux-fork" / "isolation" / "validate.sh"
    out = subprocess.run(
        [bash, str(validate)], capture_output=True, text=True, timeout=120,
    )
    # Just show the last 2 lines (verdict)
    for l in out.stdout.splitlines()[-2:]:
        print(f"  {l}")

    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
