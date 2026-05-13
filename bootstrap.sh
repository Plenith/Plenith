#!/usr/bin/env bash
# bootstrap.sh — 60-second Plenith install on a fresh machine.
#
# Creates a venv, installs the runtime + dev deps, prints next steps.
# Idempotent — safe to re-run after pulling new commits.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

C_RESET=$'\033[0m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_BOLD=$'\033[1m'

PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then
    PYTHON=python
fi
if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "ERROR: no python3 or python on PATH. Install Python 3.11+ first." >&2
    exit 1
fi

echo "${C_BOLD}Plenith bootstrap${C_RESET}"
echo "  python: $($PYTHON --version)"
echo

# Check Python version >= 3.11
MIN_PY="3.11"
PY_VER=$($PYTHON -c "import sys; print('%d.%d' % sys.version_info[:2])")
if ! $PYTHON -c "import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)"; then
    echo "ERROR: Python $PY_VER detected, need >= $MIN_PY." >&2
    exit 1
fi

# 1. venv
VENV="$ROOT/.venv"
if [ ! -d "$VENV" ]; then
    echo "${C_GREEN}[1/3]${C_RESET} creating venv at $VENV"
    $PYTHON -m venv "$VENV"
fi

# Pick the venv python (handle Windows / POSIX layout)
if [ -x "$VENV/bin/python" ]; then
    VPY="$VENV/bin/python"
elif [ -x "$VENV/Scripts/python.exe" ]; then
    VPY="$VENV/Scripts/python.exe"
else
    echo "ERROR: venv created but no python binary found" >&2
    exit 1
fi

# 2. Deps
echo "${C_GREEN}[2/3]${C_RESET} installing dev dependencies"
"$VPY" -m pip install --upgrade pip --quiet
"$VPY" -m pip install -r requirements-dev.txt --quiet

# 3. Smoke test
echo "${C_GREEN}[3/3]${C_RESET} running smoke test (pytest, ~30s)"
"$VPY" -m pytest --ignore=tests/test_isolation.py -q --tb=line 2>&1 | tail -5 || {
    echo "${C_YELLOW}WARN: some tests failed.${C_RESET} You can still try the MVP; see docs/QUICKSTART.md."
}

echo
echo "${C_BOLD}Plenith is ready.${C_RESET}"
echo
echo "Try the single-host MVP:"
echo "  ${C_GREEN}\"$VPY\" run.py${C_RESET}"
echo
echo "Then connect from another terminal:"
echo "  ${C_GREEN}ssh -p 2222 -o StrictHostKeyChecking=no jdoe@127.0.0.1${C_RESET}"
echo
echo "For the multi-host fabric, OpenAPI inbound, Helm deployment, etc., see"
echo "  ${C_GREEN}docs/QUICKSTART.md${C_RESET}"
