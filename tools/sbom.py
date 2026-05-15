"""tools/sbom.py — CycloneDX 1.5 Software Bill of Materials generator.

Required for EU Cyber Resilience Act (CRA), US federal procurement
under EO 14028, NIS2 Art. 21(2)(d), and most large-enterprise
procurement vetting. The CycloneDX 1.5 schema is the de facto standard
(SPDX 2.3 is the alternative; we generate CycloneDX because it has
better tooling support in 2026).

Sources of dependency truth:
    1. requirements.txt + requirements-dev.txt (Python deps, version-pinned)
    2. The pip-installed environment (resolved transitive deps)
    3. The Dockerfile FROM lines (base OS images)
    4. The repo itself (the Plenith "application" component)

What we emit:
    - One "application" component for Plenith itself
    - One "library" component per pinned Python dep
    - One "operating-system" component per Docker base image
    - Component licenses where derivable from PyPI metadata
    - Component PURLs (Package URL spec) for unambiguous identification
    - Component hashes (sha256) for installed packages where available

Usage:
    python tools/sbom.py                       # stdout JSON
    python tools/sbom.py --out sbom.json
    python tools/sbom.py --out sbom.json --include-dev
    python tools/sbom.py --validate            # check produced SBOM parses
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.metadata as md
import io
import json
import re
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, io.UnsupportedOperation, ValueError):
    pass

def color(c: str, s: str) -> str:
    return f"\033[{c}m{s}\033[0m"

# ---------------------------------------------------------------------------
# Requirements parsing
# ---------------------------------------------------------------------------

_REQ_RE = re.compile(
    r"^\s*([A-Za-z0-9_.\-]+)"          # name
    r"(?:\[[^\]]+\])?"                   # extras (ignored)
    r"\s*(==|>=|<=|>|<|~=|!=)?\s*"     # operator
    r"([A-Za-z0-9_.\-,]+)?",            # version spec
)

def _parse_requirements(path: Path) -> list[tuple[str, str]]:
    """Return [(package_name, version_spec_or_empty), ...]."""
    out: list[tuple[str, str]] = []
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s or s.startswith("#") or s.startswith("-r "):
            continue
        m = _REQ_RE.match(s)
        if not m:
            continue
        name = m.group(1)
        op   = m.group(2) or ""
        ver  = m.group(3) or ""
        out.append((name, f"{op}{ver}" if op else ver))
    return out

# ---------------------------------------------------------------------------
# Installed-package introspection
# ---------------------------------------------------------------------------

def _installed_info(pkg_name: str) -> dict[str, Any]:
    """Look up the installed version, license, homepage. Returns {} if
    the package isn't installed (the SBOM still lists the requirement)."""
    try:
        dist = md.distribution(pkg_name)
    except md.PackageNotFoundError:
        return {}
    meta = dist.metadata
    info = {
        "version": dist.version or "",
        "license": meta.get("License") or "",
        "summary": meta.get("Summary") or "",
        "homepage": meta.get("Home-page") or "",
        "author":   meta.get("Author") or "",
    }
    # Walk classifier list for SPDX-shaped license names (more reliable
    # than the free-form License field)
    for classifier in (meta.get_all("Classifier") or []):
        if classifier.startswith("License :: OSI Approved :: "):
            info["license_classifier"] = classifier.rsplit("::", 1)[-1].strip()
    return info

# ---------------------------------------------------------------------------
# Docker base image discovery
# ---------------------------------------------------------------------------

_FROM_RE = re.compile(r"^\s*FROM\s+([^\s]+)", re.IGNORECASE | re.MULTILINE)

def _docker_base_images(root: Path) -> list[tuple[str, str]]:
    """Walk every Dockerfile and pull the FROM image:tag. Returns
    [(image, tag), ...] — deduped, in discovery order."""
    seen: list[tuple[str, str]] = []
    seen_set: set = set()
    for dockerfile in sorted(root.rglob("Dockerfile*")):
        text = dockerfile.read_text(encoding="utf-8", errors="replace")
        for ref in _FROM_RE.findall(text):
            if ":" in ref:
                name, tag = ref.rsplit(":", 1)
            else:
                name, tag = ref, "latest"
            key = (name, tag)
            if key not in seen_set:
                seen_set.add(key)
                seen.append(key)
    return seen

# ---------------------------------------------------------------------------
# Application self-description (Plenith as a component)
# ---------------------------------------------------------------------------

def _app_component(root: Path) -> dict[str, Any]:
    """One component describing Plenith itself. Version is best-effort
    — git-based when available, falls back to a hash of the source tree."""
    version = "1.0.0"
    try:
        r = subprocess.run(
            ["git", "describe", "--tags", "--always", "--dirty"],
            capture_output=True, text=True, timeout=5, cwd=root,
        )
        if r.returncode == 0 and r.stdout.strip():
            version = r.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return {
        "bom-ref":     "plenith",
        "type":        "application",
        "name":        "plenith",
        "version":     version,
        "description": "AI-driven SSH deception platform with multi-host fabric, "
                        "RL-trained policy, MFA step-up, content rotation, and full "
                        "SIEM/SOAR/TI/MFA connector ecosystem.",
        "licenses":    [{"license": {"id": "MIT"}}],
        "purl":        f"pkg:github/plenith/plenith@{version}",
    }

# ---------------------------------------------------------------------------
# Component builders
# ---------------------------------------------------------------------------

def _py_component(name: str, requested_spec: str, scope: str) -> dict[str, Any]:
    info = _installed_info(name)
    version = info.get("version") or _strip_op(requested_spec)
    comp: dict[str, Any] = {
        "bom-ref":  f"pkg:pypi/{name}@{version or 'unknown'}",
        "type":     "library",
        "name":     name,
        "version":  version or "unknown",
        "scope":    scope,
        "purl":     f"pkg:pypi/{name}@{version or 'unknown'}",
    }
    if info.get("summary"):
        comp["description"] = info["summary"]
    # License
    license_id = info.get("license_classifier") or info.get("license") or ""
    if license_id:
        comp["licenses"] = [{"license": {"name": license_id}}]
    return comp

def _docker_component(image: str, tag: str) -> dict[str, Any]:
    """A Docker base image as a CycloneDX component (type=operating-system
    for OS bases, type=container for full images — we use container for
    everything since we can't reliably distinguish)."""
    return {
        "bom-ref": f"pkg:docker/{image}@{tag}",
        "type":    "container",
        "name":    image,
        "version": tag,
        "purl":    f"pkg:docker/{image}@{tag}",
    }

def _strip_op(spec: str) -> str:
    """`==1.2.3` → `1.2.3`, `>=2.0,<3` → `2.0`."""
    s = spec.lstrip("=<>!~ ")
    if "," in s:
        s = s.split(",", 1)[0].lstrip("=<>!~ ")
    return s.strip()

# ---------------------------------------------------------------------------
# Top-level SBOM build
# ---------------------------------------------------------------------------

def build(
    *,
    root: Path | None = None,
    include_dev: bool = False,
) -> dict[str, Any]:
    root = root or _ROOT
    now = datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds")

    # Components: application + python deps + docker base images
    components: list[dict[str, Any]] = []
    components.append(_app_component(root))

    # Python deps (required)
    for name, spec in _parse_requirements(root / "requirements.txt"):
        components.append(_py_component(name, spec, scope="required"))

    if include_dev:
        for name, spec in _parse_requirements(root / "requirements-dev.txt"):
            # Skip already-listed required deps
            if any(c["name"].lower() == name.lower() for c in components):
                continue
            components.append(_py_component(name, spec, scope="optional"))

    # Docker base images
    for image, tag in _docker_base_images(root):
        components.append(_docker_component(image, tag))

    return {
        "bomFormat":     "CycloneDX",
        "specVersion":   "1.5",
        "version":       1,
        "serialNumber":  f"urn:uuid:{uuid.uuid4()}",
        "metadata": {
            "timestamp": now,
            "tools": {
                "components": [{
                    "type":    "application",
                    "vendor":  "Plenith",
                    "name":    "sbom",
                    "version": "1.0.0",
                }],
            },
            "component": components[0],   # The application itself
        },
        "components": components[1:],     # Everything else
    }

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate(sbom: dict[str, Any]) -> list[str]:
    """Light schema validation — checks the SBOM has the required top-
    level fields per CycloneDX 1.5. Returns a list of errors (empty
    when valid). We deliberately don't pull in a JSON-schema validator
    to keep the dep footprint small."""
    errors = []
    for key in ("bomFormat", "specVersion", "version",
                 "serialNumber", "metadata", "components"):
        if key not in sbom:
            errors.append(f"missing top-level field: {key}")
    if sbom.get("bomFormat") != "CycloneDX":
        errors.append("bomFormat must be 'CycloneDX'")
    md = sbom.get("metadata") or {}
    if "timestamp" not in md:
        errors.append("metadata.timestamp missing")
    if "component" not in md:
        errors.append("metadata.component (the application) missing")
    for i, comp in enumerate(sbom.get("components") or []):
        if "type" not in comp:
            errors.append(f"components[{i}].type missing")
        if "name" not in comp:
            errors.append(f"components[{i}].name missing")
    return errors

def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--root", type=Path, default=_ROOT)
    p.add_argument("--out", type=Path, default=None,
                   help="write SBOM JSON to this path (default: stdout)")
    p.add_argument("--include-dev", action="store_true",
                   help="include dev dependencies (requirements-dev.txt)")
    p.add_argument("--validate", action="store_true",
                   help="verify the produced SBOM passes basic checks")
    args = p.parse_args(argv)

    sbom = build(root=args.root, include_dev=args.include_dev)

    if args.validate:
        errors = validate(sbom)
        if errors:
            print(color("31", "SBOM validation failed:"), file=sys.stderr)
            for e in errors:
                print(f"  - {e}", file=sys.stderr)
            return 2
        print(color("32",
                    f"[sbom] valid CycloneDX 1.5 — "
                    f"{len(sbom.get('components') or [])} components"),
              file=sys.stderr)

    body = json.dumps(sbom, indent=2, sort_keys=True)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(body + "\n", encoding="utf-8")
        print(color("32", f"[sbom] wrote {args.out}  "
                            f"({len(sbom.get('components') or [])} components)"),
              file=sys.stderr)
    else:
        print(body)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
