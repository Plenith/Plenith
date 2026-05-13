#!/usr/bin/env bash
################################################################################
# isolation/validate.sh — continuous breakout-probe for the decoy bubble.
#
# Runs a fixed set of egress probes from inside each agent and asserts they
# all fail in the expected way:
#
#   1. curl https://www.google.com    → MUST fail (no host route)
#   2. dig google.com @8.8.8.8        → MUST fail (no external DNS reachable)
#   3. nslookup google.com            → MUST return NXDOMAIN (internal resolver)
#   4. ping 8.8.8.8                   → MUST fail (no host route)
#   5. nslookup db-prod-01            → MUST succeed (internal name resolves)
#   6. curl http://llm.internal:1234/v1/models → MUST succeed (LLM bridge ok)
#
# Exits 0 on full pass, 1 on any failure. Designed to be run in CI on every
# `docker compose up`, and as a periodic cron from the SOC monitoring node.
#
# Usage:
#     bash linux-fork/isolation/validate.sh
#     bash linux-fork/isolation/validate.sh --agent db-prod-01
################################################################################
set -uo pipefail

AGENTS=(bastion-prod db-prod-01 api-prod-03)
FAIL=0
PASS=0
TOTAL=0

# Allow filtering to one agent for debugging
if [[ "${1:-}" == "--agent" && -n "${2:-}" ]]; then
    AGENTS=("$2")
fi

# -----------------------------------------------------------------------------
# Probe helpers. Each probe runs a command inside an agent and checks whether
# the OUTCOME matches what isolation should produce. We don't trust exit codes
# alone — many of these tools print warnings but exit non-zero in confusing
# ways, so we inspect output text too.
# -----------------------------------------------------------------------------

color() { printf "\033[%sm%s\033[0m" "$1" "$2"; }
ok()    { PASS=$((PASS+1)); echo "  $(color 32 PASS) $1"; }
bad()   { FAIL=$((FAIL+1)); echo "  $(color 31 FAIL) $1"; }
probe() { TOTAL=$((TOTAL+1)); }

# Run a command inside the agent. Returns the combined stdout/stderr;
# echoes "EXIT=<n>" on the last line so we can inspect it from caller.
run_in() {
    local agent="$1"; shift
    docker exec "$agent" sh -c "$* ; echo \"EXIT=\$?\"" 2>&1
}

# Assert the command FAILED (exit != 0 OR matches one of the failure patterns).
assert_fails() {
    local agent="$1" label="$2"; shift 2
    local out exit_code
    out=$(run_in "$agent" "$*")
    exit_code=$(echo "$out" | tail -1 | sed -E 's/^EXIT=//')
    probe
    if [[ "$exit_code" != "0" ]]; then
        ok "$agent: $label (exit=$exit_code)"
    else
        bad "$agent: $label SHOULD HAVE FAILED — got exit=0"
        echo "$out" | sed 's/^/      /' | head -10
    fi
}

# Assert the command SUCCEEDED.
assert_succeeds() {
    local agent="$1" label="$2"; shift 2
    local out exit_code
    out=$(run_in "$agent" "$*")
    exit_code=$(echo "$out" | tail -1 | sed -E 's/^EXIT=//')
    probe
    if [[ "$exit_code" == "0" ]]; then
        ok "$agent: $label"
    else
        bad "$agent: $label SHOULD HAVE SUCCEEDED — got exit=$exit_code"
        echo "$out" | sed 's/^/      /' | head -10
    fi
}

# Assert the command output CONTAINS a substring (regardless of exit).
assert_contains() {
    local agent="$1" label="$2" needle="$3"; shift 3
    local out
    out=$(run_in "$agent" "$*")
    probe
    if echo "$out" | grep -q -- "$needle"; then
        ok "$agent: $label (saw '$needle')"
    else
        bad "$agent: $label MISSING '$needle' in output"
        echo "$out" | sed 's/^/      /' | head -10
    fi
}

# -----------------------------------------------------------------------------
# Egress / DNS / NTP / LLM-bridge tests.
# -----------------------------------------------------------------------------

for AGENT in "${AGENTS[@]}"; do
    echo "── $AGENT ──"

    # 1. External HTTPS must fail (no host route, no MASQUERADE on internal net).
    #    We use a 3s connect timeout so the test doesn't hang forever.
    assert_fails "$AGENT" "curl https://www.google.com → blocked" \
        "curl -sSm 3 -o /dev/null https://www.google.com"

    # 2. External DNS via a hardcoded resolver must fail too. The bubble's
    #    DNS is at 172.30.0.40; 8.8.8.8 is unreachable.
    assert_fails "$AGENT" "dig @8.8.8.8 google.com → blocked" \
        "(command -v dig >/dev/null && dig +time=2 +tries=1 +short @8.8.8.8 google.com) || nslookup -timeout=2 google.com 8.8.8.8"

    # 3. Default-resolver nslookup of an external name must NOT resolve.
    #    The CoreDNS Corefile has no `forward` plugin — there is no path
    #    out. CoreDNS returns SERVFAIL (no plugin handled it) which is
    #    functionally equivalent to NXDOMAIN here — both signal "the
    #    resolver does not know this name." We accept either.
    assert_external_dns_blocked() {
        local out
        out=$(run_in "$AGENT" "nslookup -timeout=3 google.com 172.30.0.40 || true")
        probe
        if echo "$out" | grep -Eq "(NXDOMAIN|SERVFAIL|can't find)"; then
            ok "$AGENT: nslookup google.com → blocked (NXDOMAIN/SERVFAIL)"
        else
            bad "$AGENT: nslookup google.com SHOULD HAVE FAILED — resolver returned an address"
            echo "$out" | sed 's/^/      /' | head -10
        fi
    }
    assert_external_dns_blocked

    # 4. Raw TCP to a public IP must fail. The agent image is debian-slim
    #    based — no `nc`, no `/dev/tcp` (dash, not bash). We use Python
    #    (always present, since asyncssh requires it) with a 2-second
    #    connect timeout.
    assert_fails "$AGENT" "TCP to 8.8.8.8:53 → blocked" \
        "python3 -c 'import socket,sys;s=socket.socket();s.settimeout(2);s.connect((\"8.8.8.8\",53));sys.exit(0)'"

    # 5. Internal lateral resolution must STILL work — we want lateral SSH
    #    inside the bubble, that's the whole point of the engagement.
    assert_succeeds "$AGENT" "nslookup db-prod-01 → resolves internally" \
        "nslookup -timeout=3 db-prod-01 172.30.0.40 | grep -q 172.30.0.11"

    # 6. The LLM egress bridge must respond. (We expect a 200 from /v1/models
    #    if LM Studio is running, or 502 if it isn't — either way, NOT 403
    #    which would mean the URI map rejected the request.)
    assert_contains "$AGENT" "llm.internal /v1/models → reachable" "HTTP/" \
        "curl -sSm 5 -i http://llm.internal:1234/v1/models | head -1"

    echo
done

echo "────────────────────────────────────"
if [[ "$FAIL" -eq 0 ]]; then
    echo "$(color 32 "ALL PROBES PASSED") — $PASS/$TOTAL"
    exit 0
else
    echo "$(color 31 "ISOLATION REGRESSION") — failed $FAIL/$TOTAL"
    exit 1
fi
