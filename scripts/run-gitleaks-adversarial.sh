#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: scripts/run-gitleaks-adversarial.sh MODE /absolute/path/to/gitleaks" >&2
  exit 2
fi

mode=$1
gitleaks_path=$2
case "$mode" in
  check|test|report|record) ;;
  *)
    echo "invalid Gitleaks adversarial mode" >&2
    exit 2
    ;;
esac

if [[ "$gitleaks_path" != /* ]]; then
  echo "Gitleaks executable path must be absolute" >&2
  exit 2
fi

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repository_root=$(CDPATH= cd -- "$script_directory/.." && pwd -P)
project_python="$repository_root/.venv/bin/python"
if [[ ! -x "$project_python" ]]; then
  echo "SecureScan project Python is unavailable" >&2
  exit 1
fi

cd -- "$repository_root"
if [[ "$mode" == "test" ]]; then
  exec "$project_python" -m pytest -q \
    tests/test_gitleaks_adversarial_benchmark.py \
    tests/test_gitleaks_adversarial.py \
    tests/test_gitleaks_benchmark.py \
    tests/test_gitleaks_corpus.py \
    tests/test_gitleaks_benchmark_contract.py \
    tests/test_gitleaks_identity.py \
    tests/test_gitleaks_parser.py \
    tests/test_gitleaks_source_execution.py \
    tests/test_gitleaks_binding.py \
    tests/test_gitleaks_applicability.py
fi

exec "$project_python" -m securescan.benchmarks.gitleaks_adversarial_cli \
  "$mode" --gitleaks "$gitleaks_path"
