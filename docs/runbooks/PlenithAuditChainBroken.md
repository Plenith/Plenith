# PlenithAuditChainBroken

**Severity:** page · **Component:** audit

## What fired

`plenith_audit_chain_ok == 0` — `tools/verify_chain.py` reports a
broken hash chain in an engagement-log directory.

## Why we care

This is a **security event**, not an operational one. The hash chain
detects three classes of tamper on disk:

- An entry was modified after it was written.
- An entry was deleted from the middle of the chain.
- The tail of the chain was truncated.

Any of those means someone got read-write access to
`state-docker/logs/` and used it. The most plausible scenario:

- An attacker pivoted from the deception bubble onto the bastion
  host (a containment failure).
- They deleted or modified entries to cover their tracks.

It is also possible — but rare — that the chain broke due to:

- Disk corruption (one entry truncated mid-write because the
  filesystem died).
- A bug in the chain implementation (file an issue if you suspect this).

Either way: **do not restart the agent yet. Preserve the directory.**

## First 5 minutes

1. **Identify the affected file.**
   ```bash
   ssh <agent-host> "python /opt/plenith/tools/verify_chain.py \\
     --json /opt/plenith/state-docker/logs/ | jq '.records[] | select(.ok==false)'"
   ```
   The output tells you the path, the engagement_id, the index where
   the chain broke, and the failure reason.
2. **Snapshot the entire logs directory before touching anything.**
   ```bash
   ssh <agent-host> "sudo cp -a /opt/plenith/state-docker /var/forensics/mc-$(date +%s)"
   ```
   You will need the original bytes for any forensic work.
3. **Snapshot host state.**
   ```bash
   # Process list, open files, network connections, recent shell history
   ssh <agent-host> "ps auxwf; lsof; ss -tnp; \\
     find /home -name '.bash_history' -exec tail {} +"
   ```
4. **Check whether the bastion was compromised through another
   channel.** An attacker who can rewrite engagement logs almost
   certainly came from somewhere else first — review:
   - SSH auth logs: `/var/log/auth.log`, `/var/log/secure`
   - sudo logs
   - `last`, `lastb`
   - The agent container's own logs (was a command executed inside
     the orchestrator that doesn't appear in engagement logs?)

## Likely causes

| Failure reason | Likely cause | What to do |
| :--- | :--- | :--- |
| `entry_hash_mismatch` | Someone modified an entry's content (likely to scrub indicators) | Treat as compromise. Bastion is owned. |
| `prev_hash_mismatch` | An entry was deleted (gap in the chain) | Treat as compromise. Same. |
| `chain_tip_mismatch_truncation_suspected` | The tail of the chain was deleted | Treat as compromise. Same. |
| `missing_prev_hash` / `missing_entry_hash` | Implementation bug OR partial write during crash | Check `plenith` process logs around the timestamp; if no crash, file as a bug. |
| `unreadable` / `invalid_json` | File-system corruption | Verify the disk; the bastion may also be at risk of data loss. |

## Mitigation

This is a containment failure. Standard IR posture:

1. **Isolate the bastion from the network** (do not power off — RAM
   forensics may be useful). The agent is no longer trusted.
2. **Rotate every credential** the bastion held: SSH keys, API
   tokens, MFA bridge secrets, LLM endpoint credentials.
3. **Re-image** the bastion from a known-good template; do not try to
   clean in place.
4. **Identify the pivot path**: how did the attacker get from the
   deception bubble (which is supposed to be isolated) to the host
   running Plenith? This is the containment bug; finding it is the
   point of the rebuild.

## Post-incident

- File a CVE-equivalent internal advisory documenting the pivot path.
- Update `docs/THREAT_MODEL.md` with the new failure mode.
- If the cause was disk corruption rather than tamper, file a bug
  against the chain implementation to handle partial-write edge cases
  more gracefully (e.g. distinguish "torn write" from "deliberate
  truncation").
- Update the IR playbook with timing data — how long from chain-broken
  alert to network isolation? That number determines how much further
  an attacker could pivot in a real incident.
