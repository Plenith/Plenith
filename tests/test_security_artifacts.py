"""Validate the shape / sanity of the hardening artifacts in `deploy/`.

We can't truly test seccomp / AppArmor / nftables without a Linux
kernel and root — those need a separate integration job (out of scope
for unit tests). But we CAN catch the failure modes that bite hardest:

  - Files exist where the docs say they exist.
  - The seccomp JSON parses, has the required top-level fields, has
    `defaultAction: SCMP_ACT_ERRNO`, and the allowlist isn't
    suspiciously short (would mean someone gutted it).
  - The seccomp allowlist DOES contain syscalls Python actually needs.
  - The seccomp allowlist does NOT contain dangerous syscalls our
    threat model bans.
  - The AppArmor profile has the expected sections and explicit denies
    for capabilities that must never be granted.
  - The nftables ruleset has a default-DROP policy + REJECT/log on
    egress + binds the variables operators must edit.
  - All artifact paths referenced in docs/HARDENING.md actually exist.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# File presence
# ---------------------------------------------------------------------------

class TestFilesExist:
    @pytest.mark.parametrize("relpath", [
        "deploy/security/seccomp-agent.json",
        "deploy/security/apparmor-agent.profile",
        "deploy/network/decoy-bubble-egress.nft",
        "docs/HARDENING.md",
        "docs/DPIA.md",
        "docs/DATA_HANDLING.md",
    ])
    def test_artifact_present(self, relpath):
        p = _ROOT / relpath
        assert p.exists(), (
            f"{relpath} is missing; docs/HARDENING.md and the DPIA assume "
            f"it exists. Either restore the file or update the docs."
        )
        # Non-empty
        assert p.stat().st_size > 100, (
            f"{relpath} exists but is suspiciously small "
            f"({p.stat().st_size} bytes)."
        )

# ---------------------------------------------------------------------------
# Seccomp profile structure
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def seccomp_profile():
    return json.loads(
        (_ROOT / "deploy/security/seccomp-agent.json").read_text(encoding="utf-8")
    )

@pytest.fixture(scope="module")
def seccomp_allowed(seccomp_profile):
    """Flatten every allowed syscall name in the profile."""
    allowed = set()
    for entry in seccomp_profile["syscalls"]:
        if entry["action"] == "SCMP_ACT_ALLOW":
            allowed.update(entry["names"])
    return allowed

class TestSeccompProfile:
    def test_top_level_shape(self, seccomp_profile):
        assert seccomp_profile.get("defaultAction") == "SCMP_ACT_ERRNO", (
            "Seccomp default action must be ERRNO (deny). Anything else "
            "defeats the point of having a profile."
        )
        assert isinstance(seccomp_profile.get("syscalls"), list)

    def test_arch_map_covers_x86_64_and_aarch64(self, seccomp_profile):
        archs = {a["architecture"] for a in seccomp_profile.get("archMap", [])}
        assert "SCMP_ARCH_X86_64" in archs, "x86_64 must be in archMap"
        assert "SCMP_ARCH_AARCH64" in archs, "aarch64 must be in archMap"

    def test_allowlist_not_suspiciously_small(self, seccomp_allowed):
        """A Python process needs lots of syscalls — under ~150 means
        someone gutted the list and we'll see weird failures."""
        assert len(seccomp_allowed) >= 150, (
            f"Allowlist has only {len(seccomp_allowed)} syscalls — "
            "Python + asyncssh + httpx need more than that to work. "
            "Did someone accidentally strip the list?"
        )

    def test_critical_syscalls_for_python_runtime(self, seccomp_allowed):
        """Without these, Python literally can't run."""
        required = {
            "read", "write", "openat", "close", "mmap", "mprotect",
            "munmap", "brk", "rt_sigaction", "futex", "execve",
        }
        missing = required - seccomp_allowed
        assert not missing, (
            f"Seccomp profile missing required syscalls: {sorted(missing)}. "
            f"Python won't start."
        )

    def test_critical_syscalls_for_networking(self, seccomp_allowed):
        """asyncssh needs these."""
        required = {
            "socket", "bind", "listen", "accept", "accept4", "connect",
            "recvfrom", "sendto", "setsockopt", "getsockopt",
            "epoll_create1", "epoll_ctl", "epoll_pwait",
        }
        missing = required - seccomp_allowed
        assert not missing, (
            f"Seccomp profile missing network syscalls: {sorted(missing)}. "
            f"asyncssh won't accept connections."
        )

    def test_dangerous_syscalls_excluded(self, seccomp_allowed):
        """These syscalls MUST NOT be in the allowlist — they're the
        primary kernel-level privilege-escalation paths our threat
        model bans."""
        banned = {
            "kexec_load", "kexec_file_load",
            "init_module", "finit_module", "delete_module",
            "swapon", "swapoff",
            "reboot",
            "ptrace",
            "perf_event_open",
            "process_vm_readv", "process_vm_writev",
            "bpf",
            "keyctl", "add_key", "request_key",
            "clock_settime", "settimeofday", "adjtimex",
            "mount", "umount", "umount2", "pivot_root",
            "_sysctl",
            "ioperm", "iopl",
        }
        accidentally_allowed = banned & seccomp_allowed
        assert not accidentally_allowed, (
            f"Seccomp profile allows banned syscalls: "
            f"{sorted(accidentally_allowed)}. These are kernel-level "
            f"privilege-escalation paths and must be denied."
        )

# ---------------------------------------------------------------------------
# AppArmor profile
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def apparmor_text():
    return (_ROOT / "deploy/security/apparmor-agent.profile").read_text(
        encoding="utf-8"
    )

class TestAppArmorProfile:
    def test_declares_profile_with_correct_name(self, apparmor_text):
        assert re.search(r"^profile plenith-agent\b", apparmor_text,
                          re.MULTILINE), (
            "AppArmor profile must declare `profile plenith-agent`; "
            "the docker security_opt references that exact name."
        )

    def test_includes_required_abstractions(self, apparmor_text):
        for ab in ("abstractions/base", "abstractions/python"):
            assert f"#include <{ab}>" in apparmor_text, (
                f"AppArmor profile missing #include for {ab}"
            )

    @pytest.mark.parametrize("capability", [
        "sys_admin",
        "sys_module",
        "sys_ptrace",
        "sys_rawio",
        "sys_boot",
        "mac_admin",
        "mac_override",
    ])
    def test_critical_capabilities_explicitly_denied(self, apparmor_text, capability):
        """The agent must never need these. Explicit `deny` is more
        defensible than relying on the default."""
        pattern = rf"\bdeny\s+capability\s+{capability}\b"
        assert re.search(pattern, apparmor_text), (
            f"AppArmor profile should explicitly `deny capability "
            f"{capability}` — it's currently relying on the default."
        )

    def test_denies_mount_namespace_ops(self, apparmor_text):
        for op in ("mount", "umount", "pivot_root"):
            # Match `deny <op>` with any leading whitespace (the profile
            # indents inside the `profile { ... }` block).
            assert re.search(rf"^\s*deny {op}\b", apparmor_text, re.MULTILINE), (
                f"AppArmor profile must `deny {op}` — these are "
                f"filesystem-namespace escape paths."
            )

    def test_denies_writes_to_sensitive_host_paths(self, apparmor_text):
        for path in ("/etc/shadow", "/etc/sudoers"):
            # rwx or w means write-allowed; we want explicit deny.
            assert re.search(rf"deny .*{re.escape(path)}", apparmor_text), (
                f"AppArmor profile must deny writes to {path}"
            )

    def test_network_raw_denied(self, apparmor_text):
        assert "deny network raw" in apparmor_text, (
            "AppArmor profile must `deny network raw` — the agent doesn't "
            "craft raw packets, and allowing it enables L2/L3 attacks."
        )

# ---------------------------------------------------------------------------
# nftables ruleset
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def nft_text():
    return (_ROOT / "deploy/network/decoy-bubble-egress.nft").read_text(
        encoding="utf-8"
    )

class TestNftablesRuleset:
    def test_starts_with_shebang(self, nft_text):
        first = nft_text.splitlines()[0]
        assert first.startswith("#!/usr/sbin/nft") or first.startswith("#!"), (
            "nftables file should be executable; missing shebang"
        )

    def test_defines_required_variables(self, nft_text):
        """Operators MUST edit these. We don't enforce their values but
        we DO enforce they're defined so an empty deployment fails fast."""
        required = [
            "BUBBLE_IFACE",
            "BUBBLE_NET",
            "LLM_HOST",
            "LLM_PORT",
            "SIEM_HOST",
            "SIEM_PORT",
            "MFA_HOST",
            "MFA_PORT",
            "DNS_RESOLVER",
            "SSH_PROXY_PORT",
        ]
        for var in required:
            assert re.search(rf"^define {var}\s*=", nft_text, re.MULTILINE), (
                f"nftables ruleset must `define {var}` — operators need it "
                f"to scope the allowlist for their deployment."
            )

    def test_input_default_drop(self, nft_text):
        """The input chain MUST drop by default."""
        m = re.search(r"chain input\s*\{[^}]*?policy\s+(\w+)", nft_text, re.DOTALL)
        assert m, "couldn't locate the input chain policy declaration"
        assert m.group(1) == "drop", (
            f"input chain policy is {m.group(1)!r}; must be `drop`. "
            f"Anything else defeats the firewall."
        )

    def test_forward_default_drop(self, nft_text):
        m = re.search(r"chain forward\s*\{[^}]*?policy\s+(\w+)", nft_text, re.DOTALL)
        assert m, "couldn't locate the forward chain policy declaration"
        assert m.group(1) == "drop"

    def test_rfc1918_protection(self, nft_text):
        """The bubble must NOT be able to reach the production RFC1918
        space arbitrarily — the rule must scope to the explicit allowlist."""
        for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"):
            assert cidr in nft_text, (
                f"nftables ruleset must explicitly handle {cidr} — without "
                f"that, a pivot from the bubble onto the production LAN "
                f"is allowed."
            )

    def test_logs_denied_egress(self, nft_text):
        """A silent drop is forensically worse than a logged drop."""
        assert "plenith-egress-deny" in nft_text, (
            "nftables ruleset must log denied egress with a recognizable "
            "prefix so the SOC can pick it up."
        )

    def test_allows_ssh_proxy_port(self, nft_text):
        assert "$SSH_PROXY_PORT accept" in nft_text or "SSH_PROXY_PORT accept" in nft_text, (
            "nftables ruleset must accept inbound on $SSH_PROXY_PORT "
            "— that's the attacker's only legitimate entry."
        )

# ---------------------------------------------------------------------------
# Cross-reference: every artifact mentioned in HARDENING.md must exist
# ---------------------------------------------------------------------------

class TestHardeningDocReferences:
    def test_references_resolve(self):
        text = (_ROOT / "docs/HARDENING.md").read_text(encoding="utf-8")
        # Match `deploy/...` paths only when followed by a non-word character
        # or end-of-string — avoids matching `deploy/security/something` as
        # `deploy/security` plus stray text.
        references = set(re.findall(
            r"deploy/[a-zA-Z0-9_\-/.]+\b",
            text,
        ))
        # Files we genuinely ship — these must exist
        for ref in references:
            # Skip generic patterns
            if ref.endswith("/"):
                continue
            target = _ROOT / ref
            assert target.exists(), (
                f"docs/HARDENING.md references `{ref}` but the file "
                f"doesn't exist."
            )
