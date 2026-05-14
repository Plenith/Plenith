# ADR 007: gVisor as the microVM substitute (over Firecracker)

**Status:** Accepted
**Date:** 2026-05

## Context

§4.2 of the blueprint specifies microVM-grade compute isolation for
high-risk decoys: Firecracker, Kata Containers, or equivalent. The dev
fabric runs on Docker Desktop / WSL2, which doesn't expose nested KVM
to containers. Production targets a real Linux host with KVM.

## Decision

The Helm chart and `docker-compose.gvisor.yml` use **gVisor (runsc)
runtime** by default. Firecracker is documented as the production
target but not the dev default.

## Why gVisor

1. **No nested KVM required.** Runs as a userspace kernel; intercepts
   syscalls. Works under any host that supports `seccomp` and
   `ptrace` — Docker Desktop, WSL2, native Linux, ARM Macs.
2. **Same threat-model story.** gVisor intercepts every syscall before
   the host kernel sees it. A successful kernel exploit (CVE-2022-0185,
   dirty pipe) hits gVisor's filter long before the host. Same
   intent as Firecracker's `vmexit` boundary.
3. **Performance acceptable.** ~3% CPU overhead, ~15-20% memory.
   Plenith is async-IO-bound, not CPU-bound — overhead invisible.
4. **Drop-in.** `runtime: runsc` in the Helm values is all it takes.
5. **OSS, Apache 2.0.** Compatible with the project's license (also
   Apache 2.0; this ADR was originally written when the project was
   tentatively MIT — see LICENSE for current).

## Considered alternatives

- **Firecracker** — gold standard, needs KVM, doesn't run inside Docker
  Desktop's WSL2 VM. **Production-only substitute.**
- **Kata Containers** — Firecracker- or QEMU-backed; same KVM
  requirement as Firecracker.
- **Plain runc** — no extra isolation. Acceptable on the dev fabric;
  unacceptable for production handling actively-attacking traffic.
- **Bottlerocket / immutable OS** — orthogonal — host-side hardening,
  not container-runtime isolation.

## Consequences

- **WSL2 / Docker Desktop dev fabric:** `runsc` isn't trivially
  installable inside the docker-desktop VM. Default dev runtime is
  `runc`. Documented in `linux-fork/docker-compose.gvisor.yml`.
- **A few syscalls are unsupported by gVisor** — KEYCTL, complex
  IOCTLs, some perf events. For a deception-shell workload (asyncio
  SSH server) these never come up.
- **Production deployments wanting Firecracker** can use Kata or
  direct Firecracker — Helm chart accepts any `runtimeClassName`.

## File pointers

- `linux-fork/docker-compose.gvisor.yml`
- `deploy/helm/plenith/values.yaml` (`runtime.runtimeClassName`)
- `linux-fork/isolation/README.md` (compute-isolation section)
