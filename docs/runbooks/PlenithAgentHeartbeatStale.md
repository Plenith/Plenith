# PlenithAgentHeartbeatStale

**Severity:** page · **Component:** agent

## What fired

`time() - plenith_agent_heartbeat_timestamp_seconds > 90` for 30s.

An agent hasn't written its on-disk heartbeat in over 90 seconds. The
heartbeat thread writes every 10s (see `plenith/heartbeat.py`), so
90s is ~9 missed beats — well past noise.

## Why we care

A stale heartbeat from a host whose API is otherwise responsive is the
clearest possible "the orchestrator is alive but stuck" signal. The
SSH proxy may still accept connections; commands inside those
connections are silently lost. This is operationally worse than a
clean crash because nothing else surfaces it.

## First 5 minutes

1. **Confirm the host identity.**
   `{{ $labels.hostname }}` in the alert tells you which agent. If you
   have multiple agents this matters — only one is hung.
2. **Is the agent process alive?**
   ```bash
   ssh <hostname> "docker ps --format '{{.Names}}: {{.Status}}' | grep plenith"
   ```
   - If the process is gone, this is really a `PlenithOrchestratorDown`
     — go to that runbook.
   - If the process is `Up <minutes>` but writing nothing, continue.
3. **What is the heartbeat file showing?**
   ```bash
   ssh <hostname> "cat /opt/plenith/state-docker/persistence/heartbeats/${HOSTNAME}.json"
   ```
   - File missing → the writer thread crashed at boot. Restart.
   - `status: stopping` → the agent was asked to stop and didn't
     finish. Almost certainly stuck in shutdown.
   - `last_beat` is recent → the file is being written, alert is a
     false positive (Prometheus textfile collector lag — check the
     node_exporter on this host).
4. **Look for the actual blocker.**
   ```bash
   # If the heartbeat thread is hung, the rest of the orchestrator
   # almost certainly is too. Get a full traceback dump.
   ssh <hostname> "docker exec plenith-orchestrator kill -SIGUSR1 1"
   ssh <hostname> "ls -la /opt/plenith/state-docker/diag/"
   ```
   The traceback dump tells you what the main thread was waiting on.

## Likely causes

| Signal in the traceback dump | Cause | Mitigation |
| :--- | :--- | :--- |
| `httpx.connect` against LM Studio | LLM endpoint hung | Restart LM Studio first; orchestrator will retry. |
| `socket.recv` against an SSH client | A specific attacker is holding the orchestrator in a long-lived call (slow loris–style) | Identify the engagement, kill the connection from the bastion side. |
| `await session.write_log` | Disk full or unmount on `state-docker/` | Check `df -h`. If full, expand and restart. |
| `await asyncio.Lock.acquire` deeply | Deadlock — file a bug with the traceback | Hot fix: restart. Cold fix: report + patch. |
| (no SIGUSR1 response) | Process is in uninterruptible sleep — kernel-level stuck | Hard restart. Capture kernel logs (`journalctl -k`) for the time window. |

## Mitigation

1. Capture diagnostics before restarting (see step 4 above). Without
   the traceback you lose your one chance to fix this rather than
   merely mitigate it.
2. Restart the agent. Heartbeat should resume within 10s.
3. If multiple agents go stale simultaneously, suspect a shared
   dependency — LLM, DNS, NTP, or the volume mount under `state-docker/`.

## Post-incident

- File the traceback dump as an issue if you don't recognize the
  cause. This is the kind of bug a single occurrence is enough to fix
  permanently.
- If the host was just slow under attacker load (rare but possible),
  consider raising the alert threshold to 120s OR adding capacity.
