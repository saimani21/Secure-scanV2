#!/usr/bin/env bash
set -euo pipefail

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)"
project_python="$repo_root/.venv/bin/python"

if [[ ! -x "$project_python" ]]; then
  printf '%s\n' 'SecureScan project Python is unavailable' >&2
  exit 1
fi

cd -- "$repo_root"
mode="${1:-check}"

case "$mode" in
  check)
    exec "$project_python" -m securescan.benchmarks.osv_s2
    ;;
  test)
    exec "$project_python" -m pytest -q \
      tests/test_osv_models.py \
      tests/test_osv_parser.py \
      tests/test_osv_client.py \
      tests/test_osv_evaluation.py \
      tests/test_osv_benchmark.py
    ;;
  report)
    exec env SECURESCAN_OSV_MODE=report "$project_python" -m securescan.benchmarks.osv_s2
    ;;
  acquire)
    exec env SECURESCAN_OSV_MODE=acquire "$project_python" -m securescan.benchmarks.osv_s2
    ;;
  live-sentinel)
    exec "$project_python" -c \
      'from securescan.advisories.osv import HttpxOsvTransport,TrustedOsvClient; from securescan.benchmarks.osv_s2 import build_controlled_candidates; t=HttpxOsvTransport(); TrustedOsvClient(t).query(build_controlled_candidates()[:1]); t.close(); print("OSV_LIVE_FUNCTIONALITY_SENTINEL_PASS")'
    ;;
  *)
    printf 'usage: %s {check|test|report|acquire|live-sentinel}\n' "$0" >&2
    exit 2
    ;;
esac
