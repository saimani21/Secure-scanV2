#!/usr/bin/env bash
set -euo pipefail

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)"
lock="$repo_root/src/securescan/scanners/checkov/toolchain/checkov-3.3.16-cp312-linux-x86_64.lock"
wheelhouse="${1:-}"
destination="${2:-$repo_root/.venv-checkov-3.3.16}"
bootstrap_python="${SECURESCAN_CHECKOV_BOOTSTRAP_PYTHON:-/usr/bin/python3.12}"
expected_lock_sha256="9d8dcc6645b6d4f2035fb90fc500cdd62b1f68dd1dbafc63320d06e3f04a47d0"

if [[ -z "$wheelhouse" || "$wheelhouse" != /* || ! -d "$wheelhouse" || -L "$wheelhouse" ]]; then
  printf 'usage: %s ABSOLUTE_OFFLINE_WHEELHOUSE [ABSOLUTE_DESTINATION]\n' "$0" >&2
  exit 2
fi
if [[ "$destination" != /* || -e "$destination" || -L "$destination" ]]; then
  printf '%s\n' 'Checkov toolchain destination must be an absent absolute path' >&2
  exit 1
fi
if [[ ! -x "$bootstrap_python" ]]; then
  printf '%s\n' 'CPython 3.12.3 bootstrap interpreter is unavailable' >&2
  exit 1
fi
if [[ "$(sha256sum -- "$lock" | cut -d' ' -f1)" != "$expected_lock_sha256" ]]; then
  printf '%s\n' 'Checkov toolchain lock integrity verification failed' >&2
  exit 1
fi
if [[ "$($bootstrap_python -c 'import platform; print(platform.python_implementation(), platform.python_version())')" != "CPython 3.12.3" ]]; then
  printf '%s\n' 'CPython 3.12.3 bootstrap interpreter is unavailable' >&2
  exit 1
fi

created=false
cleanup() {
  if [[ "$created" == true && -d "$destination" ]]; then
    rm -rf -- "$destination"
  fi
}
trap cleanup EXIT

mkdir -- "$destination"
created=true
"$bootstrap_python" -m venv "$destination"
"$destination/bin/python" -m pip install \
  --no-index \
  --find-links "$wheelhouse" \
  --require-hashes \
  --no-deps \
  --requirement "$lock"
"$destination/bin/checkov" --version | grep -Fx '3.3.16' >/dev/null
created=false
printf '%s\n' 'Checkov 3.3.16 hash-locked offline toolchain prepared'
