# Verifying a Plenith release

Every Plenith release is signed with [sigstore/cosign][cosign]
keyless signing. This document shows you how to verify, in under two
minutes, that the artifact you downloaded was built by THIS repo at THE
tagged commit, by GitHub's official runners.

If verification fails, **do not run the artifact.** Open an issue (or
private report — see [`SECURITY.md`](../SECURITY.md)).

---

## What's signed

Each GitHub Release ships the following for each artifact:

```
plenith-vX.Y.Z.tar.gz             ← the artifact
plenith-vX.Y.Z.tar.gz.sig         ← detached cosign signature
plenith-vX.Y.Z.tar.gz.pem         ← the ephemeral certificate used
plenith-vX.Y.Z.tar.gz.sigstore    ← bundle (preferred — single file)
```

Plus the CycloneDX SBOM and a `SHA256SUMS` file, all signed the same
way.

---

## Why keyless signing?

A long-lived signing key creates two problems:

1. The key has to live somewhere. Either it's in a CI secret (one
   compromise of the org → forged releases) or on a maintainer's
   laptop (one stolen laptop → forged releases).
2. Key rotation is operational pain. People miss the rotation, the
   key stays in service for years, the threat model erodes.

Keyless signing solves this by using a **short-lived certificate** tied
to the OIDC identity of the GitHub Actions run that produced the
artifact. The certificate is valid for ~10 minutes — useless to an
attacker after the workflow ends. The proof you're verifying is rooted
in the [Rekor transparency log][rekor], which is append-only and
auditable.

What this gives you:

- Provenance: *this artifact was produced by `<repo>` workflow `<file>`
  at tag `<vX.Y.Z>`, run by GitHub-Actions.*
- Tamper-evidence: changing the bytes invalidates the signature.
- Auditability: the signing event is in Rekor — anyone can look up the
  certificate and confirm the workflow that issued it.

What it does NOT give you:

- An assurance that the *source code* is benign. You still have to
  read it.
- An assurance that the maintainers' GitHub account isn't compromised.
  That's the residual risk of any code-supply-chain mechanism.

---

## Verifying — the 90-second path

### Prerequisites

- `cosign` ≥ v2.2 — install from [sigstore/cosign releases][cosign-rel]
  or your package manager (Homebrew: `brew install cosign`, Debian/
  Ubuntu: `sudo apt install cosign`).

Download the artifact and its `.sigstore` bundle from the release page.

```bash
gh release download v1.0.0 \
  --repo Plenith/Plenith \
  --pattern '*.tar.gz' \
  --pattern '*.sigstore' \
  --pattern 'SHA256SUMS*'
```

### One-step verify

```bash
cosign verify-blob \
  --bundle plenith-v1.0.0.tar.gz.sigstore \
  --certificate-identity-regexp \
    "https://github.com/Plenith/Plenith/.github/workflows/release.yml@refs/tags/v1.0.0" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  plenith-v1.0.0.tar.gz
```

Substitute `Plenith` and `v1.0.0` as appropriate.

**Expected output:**

```
Verified OK
```

If you see `Verified OK`, three things are simultaneously true:

1. The artifact's bytes are exactly what was signed.
2. The signature was made by a sigstore certificate issued to the
   `release.yml` workflow in this repo, running on tag `v1.0.0`.
3. That signing event is recorded in Rekor and can be looked up by
   anyone, forever.

### Verifying the SBOM and checksums

Same command, different file:

```bash
cosign verify-blob --bundle plenith-v1.0.0.sbom.json.sigstore \
  --certificate-identity-regexp "...release.yml@refs/tags/v1.0.0" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  plenith-v1.0.0.sbom.json
```

And cross-check the tarball's hash against `SHA256SUMS`:

```bash
sha256sum -c SHA256SUMS
# plenith-v1.0.0.tar.gz: OK
# plenith-v1.0.0.sbom.json: OK
```

---

## Verifying — without bundles (older cosign)

If your cosign is < 2.0 or you prefer detached files:

```bash
cosign verify-blob \
  --signature plenith-v1.0.0.tar.gz.sig \
  --certificate plenith-v1.0.0.tar.gz.pem \
  --certificate-identity-regexp "...release.yml@refs/tags/v1.0.0" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  plenith-v1.0.0.tar.gz
```

Same expected output.

---

## Verifying SLSA build provenance (independent layer)

The release workflow also emits a SLSA build-provenance attestation —
a separate proof that the artifact was built by a specific workflow
run. Verify with the GitHub CLI:

```bash
gh attestation verify plenith-v1.0.0.tar.gz \
  --owner Plenith
```

**Expected output:**

```
✓ Verification succeeded!
```

The provenance includes the workflow file, the commit SHA, the
runner — useful when you need to demonstrate to an auditor that an
artifact was built by a known process.

---

## What if verification fails?

| Failure | Likely cause | Action |
| :--- | :--- | :--- |
| `signature is invalid` | Artifact was modified, or wrong .sig pair | Re-download. If it fails again, treat as compromised. |
| `no matching signatures` | Wrong certificate identity (typo in `--certificate-identity-regexp`) | Check the regex; the tag must match. |
| `certificate is expired` | You're verifying an old artifact and Rekor record was pruned | Cosign falls back to offline verification with the Rekor public key bundle — make sure your cosign is recent. |
| `Verified OK` but binary still flagged | Verification only proves provenance, not benign-ness | Read the code; check the SBOM; consult the issue tracker. |

For any unexpected failure, please **do not run the binary** and open
a [private security report](../SECURITY.md).

---

## Verifying inside a Docker build

To pin a verified release inside a Dockerfile:

```dockerfile
FROM alpine:3 AS verify
RUN apk add --no-cache cosign curl tar
ARG PLENITH_VERSION=v1.0.0
RUN curl -fsSL "https://github.com/Plenith/Plenith/releases/download/${PLENITH_VERSION}/plenith-${PLENITH_VERSION}.tar.gz" -o /tmp/m.tar.gz \
 && curl -fsSL "https://github.com/Plenith/Plenith/releases/download/${PLENITH_VERSION}/plenith-${PLENITH_VERSION}.tar.gz.sigstore" -o /tmp/m.sigstore \
 && cosign verify-blob \
      --bundle /tmp/m.sigstore \
      --certificate-identity-regexp ".+release\\.yml@refs/tags/${PLENITH_VERSION}$" \
      --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
      /tmp/m.tar.gz \
 && tar -xzf /tmp/m.tar.gz -C /opt/

FROM python:3.13-slim
COPY --from=verify /opt/plenith-* /opt/plenith
WORKDIR /opt/plenith
RUN pip install -r requirements.txt
CMD ["python", "run.py"]
```

The `--from=verify` pattern keeps cosign out of the final image while
still rejecting unsigned/modified artifacts at build time.

---

## Why bother?

- **Procurement / compliance**: federal contracts and the EU Cyber
  Resilience Act increasingly require verifiable provenance for
  vendor software. Cosign + SBOM ticks both boxes.
- **Supply-chain attacks**: Codecov, SolarWinds, xz-utils. All three
  would have been caught (or at least slowed down) by signed-release
  verification at the consumer side.
- **Forensics**: when something goes wrong, the Rekor entry is a
  fixed-in-time record of exactly when and by whom the artifact was
  produced. You can answer "what version was running on the night of
  X" without having to trust someone's memory.

If you're integrating Plenith into a regulated environment and
need additional verification controls (HSM-signed releases, in-toto
provenance, etc.), open an issue describing the requirement.

---

[cosign]: https://github.com/sigstore/cosign
[cosign-rel]: https://github.com/sigstore/cosign/releases
[rekor]: https://github.com/sigstore/rekor
