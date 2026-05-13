# Security Policy

Plenith is a security product. It runs on the same network as real
production assets and processes hostile inputs by design. We take
vulnerability reports seriously and aim to make reporting one of them
as low-friction as possible.

## Supported versions

| Version line | Status | Patches |
| :--- | :--- | :--- |
| `1.x` (current) | Supported | Security + bug fixes |
| `0.x` (MVP)     | End of life as of 2026-05-12 | No further patches |
| pre-MVP commits | Unsupported | — |

`1.x` is the first line with a stable plugin API, multi-tenant tokens,
hash-chained audit logs, and Dependabot upgrade flow. Earlier branches
should not be deployed in production.

## Reporting a vulnerability

**Please do not open a public GitHub issue for a security report.**

Three channels, in order of preference:

1. **GitHub Private Vulnerability Reporting.** Open
   `https://github.com/Plenith/Plenith/security/advisories/new`. This
   keeps the report and triage in one place and lets us issue a CVE +
   GitHub Security Advisory at fix-time.
2. **Encrypted email.** `security@plenith.io`. Our public key fingerprint
   is published in `docs/security-pgp.txt` — please verify before
   sending sensitive proof-of-concept material.
3. **Anonymous tip.** If you cannot identify yourself for legal /
   employer / safety reasons, drop a report into the Signal account
   linked from the security page above. We will still triage; we cannot
   credit you in the advisory without contact details.

### What to include

- A description of the issue and the impact (what an attacker can do).
- Affected version(s) — commit SHA or release tag.
- Steps to reproduce (minimal PoC preferred over a full exploit).
- Whether the issue is publicly known (e.g. referenced in a CVE,
  another project's advisory, a blog post).
- How you would like to be credited in the advisory (name, handle,
  affiliation, or "anonymous").

### What to expect

| Stage | Target |
| :--- | :--- |
| Acknowledgement of receipt | 2 business days |
| Triage + severity assessment | 5 business days |
| Fix in `main` | 30 days for high/critical, 90 days for medium/low |
| Coordinated disclosure (CVE + advisory + release) | 90 days from initial report, or sooner if the fix ships earlier |

We follow CVSS v3.1 for severity scoring and the OWASP Vulnerability
Disclosure Cheat Sheet for process. If you disagree with our
assessment, push back — we'd rather have the argument before disclosure
than after.

### Safe-harbour

We will not pursue legal action against researchers who:

- Make a good-faith effort to report through the channels above before
  going public.
- Avoid exfiltrating data beyond the minimum necessary to demonstrate
  the issue.
- Do not degrade service availability for other users while testing.
- Refrain from social-engineering or phishing our staff to find issues.

This commitment is binding on the project maintainers. We cannot
extend it to downstream commercial vendors who package Plenith in
their own products; please consult their disclosure policy.

## Out of scope

The following are intentionally part of the design and will not be
treated as vulnerabilities:

- **The deception fabric is reachable from the public internet.**
  That's the point. SSH on `:22000` is the attacker's intended entry
  point; exposing it is not a vulnerability.
- **Planted credentials are valid in the decoy environment.** They
  exist to be stolen. The vulnerability would be if they ALSO worked
  against the real network — please report that.
- **The dashboard is unauthenticated on `127.0.0.1`.** See
  ADR 010. The dashboard is an operator UI; production deployments
  must front it with a reverse proxy + auth, documented in
  `docs/QUICKSTART.md`.
- **The LLM may produce hallucinated content for an attacker.** That
  is the LLM's role in the architecture. Mismatched ground-truth
  consistency (where the LLM contradicts a planted file) IS a bug, just
  not a security one — open a regular issue.
- **Plugins run with full process privileges.** See ADR 011. Plugin
  authors are part of the trust boundary; install third-party plugins
  the same way you'd install any other Python package — with care.

## Out-of-scope of THIS policy (in scope for upstream)

- Bugs in the **Linux kernel**, **gVisor**, or **Firecracker** — report
  upstream.
- Bugs in **asyncssh**, **fastapi**, **uvicorn**, **httpx**, **pyyaml**,
  **numpy** — report upstream. If the bug is exploitable specifically
  via Plenith's use of the library, please also tell us so we can
  pin or work around it pending the upstream fix.
- Bugs in **LM Studio / Ollama / llama.cpp** — report upstream.

## Hardening guide

The fastest way to harden a fresh Plenith deployment:

1. Run agents in a dedicated VRF / VLAN with default-DROP egress;
   allowlist only `:22000` ingress and the LLM endpoint.
2. Front the REST API (`plenith/api/server.py`) with an
   authenticating reverse proxy. The included token auth is the
   second line of defense, not the first.
3. Rotate the `tenants.json` secrets file out of `config.yaml` into
   your secrets manager (Vault / AWS SM / SOPS). The orchestrator reads
   the path; it doesn't care where the secret lives.
4. Enable hash-chained audit logging (default on in 1.x) and add a
   nightly job that runs `python tools/verify_chain.py` against the
   shipped engagement-log directory.
5. Subscribe to GitHub security advisories for this repo so Dependabot
   PRs aren't your first signal that a dependency CVE landed.

## Hall of fame

We credit reporters in `docs/CREDITS.md`. Reports that result in a CVE
will additionally be cited in the GitHub Security Advisory.

---

Last updated: 2026-05-12.
This policy follows the [securitytxt.org draft](https://securitytxt.org)
conventions where applicable.
