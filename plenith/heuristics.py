# V1 heuristic action selector.
#
# Each rule self-disables once fired (via an `alerted_*` / `planted_*` flag),
# so `decide_action` is idempotent — it returns at most one action per call,
# and re-calling will skip rules that have already fired.
#
# Priority order: VFS-driven security alerts first (critical/high), then the
# original command-driven deception actions (planting, spawning).

def decide_action(session):
    obs = session.observed

    # --- CRITICAL: Reverse shell ---
    # Attacker ran a canonical reverse-shell idiom (bash -i + /dev/tcp,
    # nc -e, python socket+subprocess, etc.). Active C2 establishment —
    # absolute highest priority.
    if obs.get("reverse_shell_attempted") and not obs.get("alerted_reverse_shell"):
        obs["alerted_reverse_shell"] = True
        return {
            "action": "alert_reverse_shell",
            "severity": "critical",
            "rationale": (
                f"Attacker invoked a reverse shell idiom: "
                f"{obs.get('reverse_shell_command', '?')[:160]!r}. "
                "Active C2 establishment. Recommend: kill session immediately, "
                "capture netflow, snapshot the decoy container for forensics."
            ),
        }

    # --- CRITICAL: SSH persistence attempt ---
    # Attacker wrote to a path used for persistence (.ssh/authorized_keys,
    # .bashrc/.profile injection, cron drop, sudoers.d). This is always a
    # high-confidence "compromise in progress" signal.
    if obs.get("ssh_persistence_attempt") and not obs.get("alerted_ssh_persistence"):
        obs["alerted_ssh_persistence"] = True
        return {
            "action": "alert_ssh_persistence",
            "severity": "critical",
            "rationale": (
                "Attacker wrote to a persistence path (e.g. ~/.ssh/authorized_keys). "
                "Classic backdoor. Recommend: isolate session + force credential rotation."
            ),
        }

    # --- HIGH: Honeytoken tampering ---
    # Attacker overwrote or removed a planted credential file. This is
    # track-covering or staging-replacement — very suspicious.
    if obs.get("honeytoken_modifications") and not obs.get("alerted_honeytoken_tamper"):
        obs["alerted_honeytoken_tamper"] = True
        return {
            "action": "alert_honeytoken_tamper",
            "severity": "high",
            "rationale": (
                f"Attacker modified or deleted planted honeytoken(s): "
                f"{sorted(obs['honeytoken_modifications'])}. "
                "Likely covering tracks or staging malicious content."
            ),
        }

    # --- HIGH: DNS / HTTP exfil ---
    # `curl` or `wget` into a known interaction-service domain, or any
    # command-substitution-wrapped URL (typical `curl host/$(cat cred)`).
    if obs.get("dns_exfil_attempted") and not obs.get("alerted_dns_exfil"):
        obs["alerted_dns_exfil"] = True
        return {
            "action": "alert_dns_exfil",
            "severity": "high",
            "rationale": (
                f"Attacker is exfiltrating via curl/wget to a suspicious "
                f"destination: {sorted(obs['dns_exfil_commands'])[:3]}. "
                "Recommend: block destination domains at the egress, capture "
                "DNS queries for IOC export."
            ),
        }

    # --- HIGH: Counter-AI — attacker driven by an LLM ---
    # Combined timing-rhythm + lexical-purity + injection-probe signal
    # (see plenith/counter_ai.py). Two-tier escalation:
    #   * Detected (confidence ≥ 0.55) → high severity alert, arm traps.
    #   * Proven  (our trap marker echoed back) → critical override.
    if obs.get("attacker_llm_proven_via_trap") and not obs.get("alerted_attacker_llm_proven"):
        obs["alerted_attacker_llm_proven"] = True
        # Promote the earlier "detected" flag too so we don't double-fire.
        obs["alerted_attacker_llm_detected"] = True
        return {
            "action": "alert_attacker_llm_detected",
            "severity": "critical",
            "rationale": (
                "PROVEN counter-AI hit: the attacker's LLM echoed our "
                "planted trap marker back into a subsequent command — "
                "their agent is consuming our outputs as context. "
                "Recommend: capture full command stream for the attacker's "
                "prompt-engineering reverse-engineering."
            ),
        }
    if obs.get("attacker_likely_llm") and not obs.get("alerted_attacker_llm_detected"):
        obs["alerted_attacker_llm_detected"] = True
        sigs = obs.get("attacker_llm_signals", {}) or {}
        return {
            "action": "alert_attacker_llm_detected",
            "severity": "high",
            "rationale": (
                f"Attacker is likely LLM-driven "
                f"(confidence={sigs.get('confidence', 0):.2f}: "
                f"timing={sigs.get('timing', 0):.2f}, "
                f"lexical={sigs.get('lexical_avg', 0):.2f}, "
                f"injections={int(sigs.get('injections', 0))}). "
                "Trap-mode armed — prompt-injection bait will be embedded "
                "in subsequent decoy reads."
            ),
        }

    # --- HIGH: Lateral movement to decoy host ---
    # SSH/scp/rsync/psql targeting a hostname that only exists in the
    # decoy network (db-prod-01, bastion-prod, k8s-master-01, etc.).
    # A real user wouldn't probe these; the attacker has pulled them out
    # of ~/.ssh/config or the persona's notes.
    if obs.get("lateral_to_decoy") and not obs.get("alerted_lateral_decoy"):
        obs["alerted_lateral_decoy"] = True
        return {
            "action": "alert_lateral_decoy",
            "severity": "high",
            "rationale": (
                f"Attacker attempted lateral movement to decoy host(s): "
                f"{sorted(obs['decoy_targets'])}. The hostnames only exist "
                "in the persona's local config — strong attacker signal."
            ),
        }

    # --- HIGH: Log / history tampering ---
    # Track-covering: clearing bash history, truncating auth.log, removing
    # log files. Almost always a late-stage post-compromise move.
    if obs.get("log_tampering") and not obs.get("alerted_log_tampering"):
        obs["alerted_log_tampering"] = True
        return {
            "action": "alert_log_tampering",
            "severity": "high",
            "rationale": (
                f"Attacker attempted to clear logs or history: "
                f"{sorted(obs['tampering_commands'])[:3]}. "
                "Likely covering tracks after exfil. Preserve session "
                "snapshot before any cleanup runs."
            ),
        }

    # --- HIGH: Credential exfil (planted creds read) ---
    # The whole point of the honeypot — the attacker touched the planted
    # credentials. SOC must rotate the *real* equivalent NOW.
    if obs.get("credential_files_read") and not obs.get("alerted_credential_exfil"):
        obs["alerted_credential_exfil"] = True
        return {
            "action": "alert_credential_exfil",
            "severity": "high",
            "rationale": (
                f"Attacker read planted credentials: "
                f"{sorted(obs['credential_files_read'])}. "
                "Recommend: force password reset / key rotation for the real account."
            ),
        }

    # --- MEDIUM: Decoy swallowed ---
    # The orchestrator planted a file (sudoers fragment, my.cnf, secondary
    # aws creds) earlier in this engagement, and the attacker has now read
    # it. The deception is working — they followed the trail. Useful as
    # confirmation that the rules-engine response is effective.
    if obs.get("decoys_swallowed") and not obs.get("alerted_decoy_swallowed"):
        obs["alerted_decoy_swallowed"] = True
        return {
            "action": "alert_decoy_swallowed",
            "severity": "medium",
            "rationale": (
                f"Attacker engaged with planted decoy(s): "
                f"{sorted(obs['decoys_swallowed'])}. "
                "The deception's working — they're following the planted trail."
            ),
        }

    # --- MEDIUM: Active credential search (recon for secrets) ---
    # Attacker ran `find -name "*.pem"` / `grep -r AKIA /` / etc. — actively
    # hunting for credentials before having read any. Earlier signal than
    # credential_exfil, useful for proactive alerting.
    if obs.get("credential_search_attempted") and not obs.get("alerted_credential_search"):
        obs["alerted_credential_search"] = True
        return {
            "action": "alert_credential_search",
            "severity": "medium",
            "rationale": (
                f"Attacker is hunting for credentials with pattern(s): "
                f"{sorted(obs['credential_search_terms'])}. "
                "Recon stage — alert before they find anything real."
            ),
        }

    # --- MEDIUM: Payload staging ---
    # 3+ files dropped into /tmp/, /var/tmp/, or /dev/shm/ in this session
    # suggests staging or persistence prep.
    if len(obs.get("payload_drops", set())) >= 3 and not obs.get("alerted_payload_staging"):
        obs["alerted_payload_staging"] = True
        return {
            "action": "alert_payload_staging",
            "severity": "medium",
            "rationale": (
                f"Attacker dropped {len(obs['payload_drops'])} files into payload "
                f"directories ({sorted(obs['payload_drops'])})."
            ),
        }

    # --- Existing deception actions (command-driven) ---

    if obs["ran_sudo"] and not obs["planted_sudo_cve"]:
        obs["planted_sudo_cve"] = True
        return {
            "action": "plant_sudo_vulnerability",
            "severity": "info",
            "rationale": "Attacker invoked sudo; plant a fake CVE-2021-3156-style misconfig.",
        }

    if "mysql" in obs["services_probed"] and not obs["spawned_mysql"]:
        obs["spawned_mysql"] = True
        return {
            "action": "spawn_fake_mysql",
            "severity": "info",
            "rationale": "Attacker probed for MySQL; spawn a decoy mysqld on 3306.",
        }

    if obs["attempted_lateral"] and not obs["isolated"]:
        obs["isolated"] = True
        return {
            "action": "isolate_session",
            "severity": "medium",
            "rationale": "Lateral movement attempt detected; constrain the session subnet.",
        }

    if session.time_elapsed > 600 and not obs["found_crown_jewel"]:
        obs["found_crown_jewel"] = True
        return {
            "action": "plant_aws_credentials",
            "severity": "info",
            "rationale": "10 minutes elapsed without crown-jewel discovery; seed honeytokens.",
        }

    return None
