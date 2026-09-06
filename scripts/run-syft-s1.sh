#!/bin/sh
set -eu

SCRIPT_DIRECTORY=$(CDPATH= cd -P -- "$(dirname -- "$0")" && pwd)
REPOSITORY_ROOT=$(CDPATH= cd -P -- "$SCRIPT_DIRECTORY/.." && pwd)
PROJECT_PYTHON="$REPOSITORY_ROOT/.venv/bin/python"
SYFT_EXECUTABLE="$REPOSITORY_ROOT/.venv-syft-1.51/bin/syft"

fail() {
    printf '%s\n' "$1" >&2
    exit 1
}

[ -x "$PROJECT_PYTHON" ] || fail "Required project Python is unavailable"
[ -x "$SYFT_EXECUTABLE" ] || fail "Required trusted Syft is unavailable"

MODE=${1:-}
[ "$#" -eq 1 ] || fail "Usage: scripts/run-syft-s1.sh MODE"

cd "$REPOSITORY_ROOT"
case "$MODE" in
    check|report|record)
        env -i \
            SECURESCAN_SYFT_EXECUTABLE="$SYFT_EXECUTABLE" \
            SECURESCAN_SYFT_MODE="$MODE" \
            "$PROJECT_PYTHON" -m securescan.benchmarks.syft_inventory
        ;;
    test)
        SECURESCAN_SYFT_EXECUTABLE="$SYFT_EXECUTABLE" \
            "$PROJECT_PYTHON" -m pytest -q \
            tests/test_syft_binding.py \
            tests/test_syft_parser.py \
            tests/test_syft_source_execution.py \
            tests/test_syft_applicability.py \
            tests/test_syft_benchmark.py
        ;;
    *)
        fail "Usage: scripts/run-syft-s1.sh MODE"
        ;;
esac
