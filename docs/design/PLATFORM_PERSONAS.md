# Multi-OS Persona Support — Gap Analysis & Plan

This document scopes what it would take for Plenith to convincingly
impersonate **non-Linux Unix** hosts (Oracle Solaris, IBM AIX, and to a
lesser extent HP-UX) — the platforms financial institutions, insurers,
and other large enterprises still run core systems on.

The guiding principle is the same as the rest of the project: *nothing
ships that an attacker who knows the platform can trivially unmask.* A
Solaris decoy whose `uname` says SunOS but whose `ps`, `svcs`,
`/etc/passwd`, and `netstat` are GNU/Linux is worse than no decoy — it
actively burns the deception and trains the attacker.

Scope note: Plenith is **network-side**. It is never installed on the
real production Solaris/AIX box (an endpoint agent is explicitly out of
scope — see `MISSION.md`). "Supporting Solaris" means *impersonating* it
from the deception fabric, not *running on* it. Plenith itself continues
to run on Linux/containers.

---

## Status

- A scaffolded persona exists: `personas/solaris-dba.yaml` (Oracle
  Solaris 11.4, SPARC sun4v, Oracle DBA). Its identity fields are
  accurate; the layers below the persona are not yet OS-aware, so deep
  recon still leaks Linux.
- Forward-looking `os_family` / `os_variant` keys are present in that
  persona. `Persona.__init__` ignores unknown keys, so they are inert
  until the work below threads them through.

---

## Keystone finding

`personas/*.yaml` already carries OS identity as **data** (`uname`,
`os_release`, `id_output`, `shell`, `home`, `groups`). The problem is
that almost nothing downstream consumes it. The single highest-leverage
gap:

**`plenith/orchestrator.py:24-26`** — the LLM system prompt hardcodes the
OS and ignores the persona entirely:

```
You are simulating a Linux bash shell on a corporate server.
Host: {hostname} (Ubuntu 22.04.4 LTS, kernel 5.15.0)
```

Every LLM-generated response is conditioned on "Linux / Ubuntu / bash"
no matter which persona is loaded. `{uname}` and `{os_release}` already
exist as persona template vars but are not referenced in this template.
Fixing this one block is roughly 70% of perceived fidelity.

---

## File-by-file inventory

| Surface | Location | Linux-hardcoded today | Solaris reality |
|---|---|---|---|
| LLM system prompt | `orchestrator.py:24,26,46` | "Linux bash shell"; "Ubuntu 22.04.4 LTS, kernel 5.15.0"; "realistic Linux error message" | SunOS 5.11; ksh/bash; `/etc/release`; Solaris error strings |
| `/etc/passwd` synth | `synthetic.py:169-194` | Debian accounts (`systemd-network`, `messagebus`, `www-data`), `/usr/sbin/nologin`, `sshd:/run/sshd`, `/bin/bash` | `daemon/bin/sys/adm/lp/uucp/nuucp/listen/noaccess/nobody4`; `/usr/bin/bash`; no systemd |
| `/etc/group` synth | `synthetic.py:196-220` | `sudo=27`, `docker=998`, `www-data=33` | `staff=10`, `sysadmin=14`, `other=1`; no sudo group (RBAC profiles) |
| netstat | `orchestrator.py` `_render_netstat` (~501) | Linux `ss`/`netstat` with `PID/program` column, `612/sshd`, `mysqld` | Solaris `netstat -an`: no PID/prog column, different state names |
| Canned responses | `caches/default_responses.yaml:16-22` | `uname→Linux`, `uname -r→5.15.0-…-generic`, `uname -m→x86_64`, `$SHELL→/bin/bash` | `SunOS`, `5.11`, `sun4v`, `/usr/bin/bash` |
| sim-bot fleet | `sim_bot.py:41-128` | GNU `who`/`w`/`uptime`/`last` column layout + `load average:` | Solaris column layout differs; `last` reads `wtmpx` |
| auth log | `synthetic.py:226` | `/var/log/auth.log`, Debian sshd line format | Solaris `/var/log/authlog`, syslog format |
| rotation decoys | `rotation/artifacts.py:32,50,69,91-95` | sudoers with `apt-get/dpkg/systemctl`; mysql `/var/lib/mysql`, `/var/run/mysqld` | no apt/dpkg/systemctl; `pkg`/`svcadm`; different paths |
| default bash history | `synthetic.py` `_DEFAULT_BASH_HISTORY_POOL` | apt/yum/systemctl idioms | `svcs`/`pkg`/`prtdiag` — note: per-persona `bash_history_pool` already overrides this; the scaffold uses it |
| SSH banner / prompt | `config.yaml:4`, `ssh_server.py:261` | `"Ubuntu 22.04.4 LTS"`; Linux "Last login" format | configurable today — low effort |
| VFS seed paths | `synthetic.py:296-306` | `~/.bashrc`, `~/.bash_history` filenames | uses `persona.home` — already parameterized; only the bash-specific filenames remain |

What is **already OS-agnostic** (no work needed): the persona schema,
honeytoken *placement* (keyed off `persona.home`), the VFS
(canonical-POSIX), and the per-persona `bash_history_pool` override.
The rot is concentrated in: the LLM prompt, `synthetic.py` system
files, the response cache, sim-bot formatting, and rotation artifacts.

---

## Proposed abstraction

Add `os_family: linux | solaris | aix` to the persona (already present
in the scaffold). Introduce a small `plenith/platform.py` that owns the
per-family specifics, consumed at exactly these injection points:

1. `orchestrator.py` system prompt — drive OS / kernel / shell / error
   style from the persona (`{uname}` / `{os_release}` template vars
   already exist; the template just needs to use them).
2. `synthetic.py` — `passwd_for(os_family)`, `group_for(os_family)`,
   auth-log path + format selected by family.
3. `caches/` — per-family cache file (e.g. `solaris_responses.yaml`)
   selected by `os_family`.
4. `sim_bot.py` — family-specific `who` / `w` / `last` / `uptime`
   formatters.
5. `rotation/artifacts.py` — family-specific privilege-escalation and
   service decoys (RBAC/`pfexec` vs sudo; `svcadm` vs systemctl).

This is the same persona-pack mechanism as the planned vertical
(banking) pack, extended with an `os_family` switch — not a fork.

---

## Effort & prioritization

- **Tier 1 — ≈1 day, ~70% of perceived fidelity.** Parameterize the
  `orchestrator.py` prompt + banner/config + the bare `uname*` cache
  keys from the persona. Makes the LLM "think Solaris." Cheap, high
  impact, demonstrable against `personas/solaris-dba.yaml`.
- **Tier 2 — ≈2-3 days.** `os_family`-switched `/etc/passwd`,
  `/etc/group`, netstat, sim-bot formatters, auth-log path/format.
  Survives a knowledgeable attacker's recon.
- **Tier 3 — ≈1 week + reference capture.** Rotation decoys, a
  Solaris-accurate canned cache, ksh `.sh_history`, RBAC/`pfexec`
  instead of sudo. Requires ground-truth capture from a real Solaris
  11.4 instance to get byte-accurate outputs.

### Reference capture

Plenith does not need to *run* on Solaris, but byte-accurate Tier-3
fidelity needs real outputs to copy. Cheapest substrate: **Oracle
Solaris 11.4 x86** in a local VM (Oracle ships a free eval image).
There is no Docker path — Solaris/AIX/HP-UX are different kernels and
CPU architectures (SPARC / POWER / Itanium); containers share the host
Linux kernel and no such images exist. AIX needs IBM Power hardware or
IBM Cloud Power Virtual Server; HP-UX effectively needs real Itanium
hardware.

### AIX delta

AIX is a *second* family profile, not a tweak of Solaris: `installp` /
`lslpp` / `oslevel -s`, SRC (`lssrc -a`) instead of `svcs`,
`/etc/security/passwd` for hashes, ksh88 default, `errpt`. Scope it
separately once Solaris is proven.

---

## Recommended sequencing

Tier 1 first as a standalone, demonstrable change (prompt + banner +
`uname` cache, driven by the existing scaffold). Decide whether to
continue to Tier 2/3 based on a real design-partner ask — a financial
institution running Solaris is the natural pull, the same way a banking
customer pulls the vertical persona pack forward.

---

*Companion scaffold: `personas/solaris-dba.yaml`.*
*Roadmap entry: `ROADMAP.md` → Considering → "Multi-OS persona support".*
