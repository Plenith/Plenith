#include <tunables/global>

#
# AppArmor profile for the Plenith agent container.
#
# This profile complements `seccomp-agent.json` (syscall filtering) with
# path- and capability-level mandatory access controls. Together they
# bound what the agent can do if an attacker achieves RCE inside the
# Python process.
#
# Load on the host (Debian / Ubuntu):
#   sudo cp deploy/security/apparmor-agent.profile \
#           /etc/apparmor.d/plenith-agent
#   sudo apparmor_parser -r /etc/apparmor.d/plenith-agent
#
# Verify it's loaded:
#   sudo aa-status | grep plenith
#
# Apply to a container:
#   docker run --security-opt apparmor=plenith-agent ...
# Or in docker-compose:
#   services:
#     agent:
#       security_opt:
#         - apparmor=plenith-agent
#
# To diagnose a denial in production:
#   sudo dmesg | grep DENIED
#   sudo journalctl -k | grep apparmor
#
# This profile is intentionally STRICTER than the Docker default. Once
# you've enabled it, the agent's filesystem and network surface are
# tightly bounded and intrusion attempts that achieve code execution
# inside the agent will be visibly blocked (not silently allowed).

profile plenith-agent flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  #include <abstractions/python>
  #include <abstractions/openssl>

  # ---------------------------------------------------------------------
  # Capabilities — minimal set sufficient for asyncssh + state IO.
  # ---------------------------------------------------------------------
  capability net_bind_service,    # asyncssh binds the SSH port
  capability setuid,              # asyncssh may drop privileges after bind
  capability setgid,
  capability dac_override,        # for shared volume permissions; remove if not needed
  # Explicitly deny capabilities the agent must NEVER need.
  deny capability sys_admin,
  deny capability sys_module,
  deny capability sys_ptrace,
  deny capability sys_rawio,
  deny capability sys_resource,
  deny capability sys_boot,
  deny capability mac_admin,
  deny capability mac_override,
  deny capability audit_control,
  deny capability audit_write,
  deny capability fsetid,
  deny capability fowner,
  deny capability ipc_lock,
  deny capability mknod,

  # ---------------------------------------------------------------------
  # Filesystem — read-only roots, write only to expected state dirs.
  # ---------------------------------------------------------------------

  # Python runtime + system libraries — read-only.
  /usr/bin/python*                              ix,
  /usr/bin/python3.*                            ix,
  /opt/plenith/.venv/bin/python              ix,
  /opt/plenith/.venv/lib/python**            r,
  /usr/lib/python**                             r,
  /usr/lib/x86_64-linux-gnu/**                  mr,
  /usr/lib/aarch64-linux-gnu/**                 mr,
  /lib/x86_64-linux-gnu/**                      mr,
  /lib/aarch64-linux-gnu/**                     mr,
  /etc/python**                                 r,
  /etc/ld.so.cache                              r,
  /etc/ssl/**                                   r,
  /etc/ca-certificates/**                       r,

  # Application code — read-only.
  /opt/plenith/                              r,
  /opt/plenith/**                            r,
  /opt/plenith/.venv/bin/*                   ix,

  # State directories — write allowed under specific subtrees only.
  /opt/plenith/state-docker/                 rw,
  /opt/plenith/state-docker/**               rwk,
  /opt/plenith/state/                        rw,
  /opt/plenith/state/**                      rwk,
  /opt/plenith/logs/                         rw,
  /opt/plenith/logs/**                       rwk,
  /opt/plenith/caches/                       rw,
  /opt/plenith/caches/**                     rwk,
  /tmp/                                         rw,
  /tmp/**                                       rwk,
  /var/tmp/                                     rw,
  /var/tmp/**                                   rwk,

  # /proc — limited to the container's own process tree.
  /proc/                                        r,
  /proc/sys/kernel/random/boot_id               r,
  /proc/sys/kernel/ostype                       r,
  /proc/sys/kernel/osrelease                    r,
  /proc/sys/kernel/version                      r,
  /proc/sys/net/core/somaxconn                  r,
  /proc/sys/vm/overcommit_memory                r,
  /proc/cpuinfo                                 r,
  /proc/meminfo                                 r,
  /proc/loadavg                                 r,
  /proc/uptime                                  r,
  /proc/stat                                    r,
  /proc/version                                 r,
  /proc/[0-9]*/                                 r,
  /proc/[0-9]*/cgroup                           r,
  /proc/[0-9]*/cmdline                          r,
  /proc/[0-9]*/comm                             r,
  /proc/[0-9]*/maps                             r,
  /proc/[0-9]*/stat                             r,
  /proc/[0-9]*/status                           r,
  /proc/[0-9]*/fd/                              r,
  /proc/[0-9]*/fd/**                            r,
  /proc/[0-9]*/limits                           r,

  # Block reads of OTHER processes' memory and environ — even though the
  # container is single-process, the policy is explicit.
  deny /proc/*/mem                              rwx,
  deny /proc/*/environ                          r,
  deny /proc/kcore                              rwx,
  deny /proc/kallsyms                           r,
  deny /proc/sysrq-trigger                      rwx,

  # /sys — only what the runtime asks for.
  /sys/kernel/mm/transparent_hugepage/enabled   r,
  deny /sys/kernel/**                           w,
  deny /sys/fs/cgroup/**                        w,

  # /dev — tightly scoped.
  /dev/null                                     rw,
  /dev/zero                                     rw,
  /dev/full                                     rw,
  /dev/random                                   r,
  /dev/urandom                                  r,
  /dev/tty                                      rw,
  /dev/pts/*                                    rw,
  /dev/console                                  rw,
  deny /dev/mem                                 rwx,
  deny /dev/kmem                                rwx,

  # ---------------------------------------------------------------------
  # Network — TCP + UDP only.
  # ---------------------------------------------------------------------
  network inet,
  network inet6,
  network unix,
  network netlink,         # for getifaddrs / interface enumeration
  # No raw sockets — the agent doesn't need to craft packets.
  deny network raw,
  deny network packet,
  deny network bluetooth,
  deny network can,
  deny network rds,

  # ---------------------------------------------------------------------
  # Hard denies (informational — most are blocked by the default already)
  # ---------------------------------------------------------------------
  deny mount,
  deny umount,
  deny pivot_root,
  deny remount,
  # Block writes to the host's actual /etc and /usr.
  deny /etc/shadow                              rwx,
  deny /etc/sudoers                             rwx,
  deny /etc/passwd                              w,
  deny /etc/group                               w,
  deny /root/                                   rwx,
  deny /home/                                   rwx,
}
