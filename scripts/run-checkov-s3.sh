#!/usr/bin/env bash
set -euo pipefail

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)"
project_python="$repo_root/.venv/bin/python"
checkov="$repo_root/.venv-checkov-3.3.16/bin/checkov"

if [[ ! -x "$project_python" || ! -x "$checkov" ]]; then
  printf '%s\n' 'SecureScan Checkov S3 runtime is unavailable' >&2
  exit 1
fi

cd -- "$repo_root"
case "${1:-check}" in
  check)
    exec "$project_python" -m securescan.benchmarks.checkov_s3
    ;;
  test)
    exec "$project_python" -m pytest -q \
      tests/test_checkov_binding.py \
      tests/test_checkov_applicability.py \
      tests/test_checkov_source_execution.py \
      tests/test_checkov_parser.py \
      tests/test_checkov_benchmark.py
    ;;
  report)
    exec env SECURESCAN_CHECKOV_MODE=report "$project_python" -m securescan.benchmarks.checkov_s3
    ;;
  record)
    exec env SECURESCAN_CHECKOV_MODE=record "$project_python" -m securescan.benchmarks.checkov_s3
    ;;
  *)
    printf 'usage: %s {check|test|report|record}\n' "$0" >&2
    exit 2
    ;;
esac
