from __future__ import annotations

import argparse
from pathlib import Path

from securescan.benchmarks.python_sast_rule_claim_contract_v2 import (
    build_audit,
    canonical_stdout,
    verify_documents,
    write_documents,
)


def repository_root() -> Path:
    root = Path(__file__).resolve().parents[3]
    if not (root / "pyproject.toml").is_file():
        raise RuntimeError("SecureScan repository root is invalid")
    return root


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("check", "generate", "summary"))
    arguments = parser.parse_args(argv)
    root = repository_root()
    if arguments.mode == "generate":
        identities = write_documents(root)
        for name, identity in sorted(identities.items()):
            print(f"{name}={identity}")
    elif arguments.mode == "check":
        identities = verify_documents(root)
        for name, identity in sorted(identities.items()):
            print(f"{name}={identity}")
    else:
        print(canonical_stdout(build_audit(root)["summary"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
