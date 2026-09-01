#!/bin/sh
set -eu

SCRIPT_DIRECTORY=$(CDPATH= cd -P -- "$(dirname -- "$0")" && pwd)
REPOSITORY_ROOT=$(CDPATH= cd -P -- "$SCRIPT_DIRECTORY/.." && pwd)
PROJECT_PYTHON="$REPOSITORY_ROOT/.venv/bin/python"

if [ ! -x "$PROJECT_PYTHON" ]; then
    printf '%s\n' "Required project Python is unavailable" >&2
    exit 1
fi

MODE=${1:-verify}
if [ "$#" -gt 1 ] || { [ "$MODE" != "acquire" ] && [ "$MODE" != "verify" ] && [ "$MODE" != "summary" ]; }; then
    printf '%s\n' "Usage: scripts/setup-python-sast-realworld-cases.sh [acquire|verify|summary]" >&2
    exit 1
fi

cd "$REPOSITORY_ROOT"
exec "$PROJECT_PYTHON" -m securescan.benchmarks.python_sast_realworld_cli "$MODE"
