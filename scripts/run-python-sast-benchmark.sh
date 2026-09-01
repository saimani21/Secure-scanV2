#!/bin/sh
set -eu

SCRIPT_DIRECTORY=$(CDPATH= cd -P -- "$(dirname -- "$0")" && pwd)
REPOSITORY_ROOT=$(CDPATH= cd -P -- "$SCRIPT_DIRECTORY/.." && pwd)
PROJECT_PYTHON="$REPOSITORY_ROOT/.venv/bin/python"
SEMGREP_EXECUTABLE="$REPOSITORY_ROOT/.venv-semgrep-1.171/bin/semgrep"
EXPECTED_SEMGREP_VERSION="1.171.0"

fail() {
    printf '%s\n' "$1" >&2
    exit 1
}

[ -x "$PROJECT_PYTHON" ] || fail "Required project Python is unavailable"
[ -x "$SEMGREP_EXECUTABLE" ] || fail "Required benchmark Semgrep is unavailable"

TEMPORARY_ROOT=$(mktemp -d /tmp/securescan-python-sast-runner.XXXXXX)
trap 'rm -rf -- "$TEMPORARY_ROOT"' EXIT HUP INT TERM
mkdir "$TEMPORARY_ROOT/home"
SEMGREP_DIRECTORY=$(dirname -- "$SEMGREP_EXECUTABLE")
CONTROLLED_PATH="$SEMGREP_DIRECTORY:/usr/bin:/bin"

SEMGREP_VERSION=$(
    env -i \
        HOME="$TEMPORARY_ROOT/home" \
        LANG=C.UTF-8 \
        LC_ALL=C.UTF-8 \
        PATH="$CONTROLLED_PATH" \
        SEMGREP_LOG_FILE="$TEMPORARY_ROOT/semgrep.log" \
        SEMGREP_SETTINGS_FILE="$TEMPORARY_ROOT/settings.yml" \
        "$SEMGREP_EXECUTABLE" --disable-version-check --version
)
[ "$SEMGREP_VERSION" = "$EXPECTED_SEMGREP_VERSION" ] \
    || fail "Benchmark Semgrep version mismatch"

run_project_python() {
    env -i \
        HOME="$TEMPORARY_ROOT/home" \
        LANG=C.UTF-8 \
        LC_ALL=C.UTF-8 \
        PATH="$CONTROLLED_PATH" \
        "$PROJECT_PYTHON" "$@"
}

MODE=${1:-}
[ "$#" -eq 1 ] || fail "Usage: scripts/run-python-sast-benchmark.sh MODE"
cd "$REPOSITORY_ROOT"

case "$MODE" in
    check)
        PROJECT_VERSION=$(
            "$PROJECT_PYTHON" --version 2>&1
        )
        printf 'project_python=%s version=%s\n' "$PROJECT_PYTHON" "$PROJECT_VERSION"
        printf 'semgrep=%s version=%s\n' "$SEMGREP_EXECUTABLE" "$SEMGREP_VERSION"
        run_project_python -m securescan.benchmarks.python_sast_cli check
        ;;
    test)
        run_project_python -m pytest -q \
            tests/test_python_sast_benchmark.py \
            tests/test_semgrep_rule_quality.py \
            tests/test_semgrep_ruleset.py \
            tests/test_semgrep_source_binding.py
        ;;
    report)
        run_project_python -m securescan.benchmarks.python_sast_cli report
        ;;
    record)
        run_project_python -m securescan.benchmarks.python_sast_cli record
        ;;
    *)
        fail "Usage: scripts/run-python-sast-benchmark.sh MODE"
        ;;
esac
