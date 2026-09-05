#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: scripts/run-gitleaks-realworld.sh record /absolute/path/to/gitleaks /absolute/path/to/retained/workspaces" >&2
  exit 2
fi

mode=$1
gitleaks_path=$2
retained_workspaces=$3
if [[ "$mode" != "record" ]]; then
  echo "invalid Gitleaks real-world mode" >&2
  exit 2
fi
if [[ "$gitleaks_path" != /* || "$retained_workspaces" != /* ]]; then
  echo "Gitleaks and retained workspace paths must be absolute" >&2
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
exec "$project_python" -m securescan.benchmarks.gitleaks_realworld_evaluation_cli \
  "$mode" \
  --gitleaks "$gitleaks_path" \
  --retained-workspaces "$retained_workspaces"
