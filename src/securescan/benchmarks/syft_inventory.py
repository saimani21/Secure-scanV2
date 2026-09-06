from __future__ import annotations

import hashlib
import json
import os
from collections import Counter
from pathlib import Path
from typing import Any

from securescan.execution import CancellableProcessExecutor
from securescan.scanners.syft import (
    SYFT_ARCHIVE_SHA256,
    SYFT_CONFIG_SHA256,
    SYFT_EXECUTABLE_SHA256,
    SYFT_JSON_SCHEMA_VERSION,
    SYFT_SCANNER_ID,
    SYFT_VERSION,
    TrustedSyftBinding,
    canonical_syft_binding_artifact,
    canonical_syft_contract,
    create_default_syft_binding,
    parse_syft_json,
)

_PROJECTION_ID = "securescan-source-projection-" + "51" * 16
_CORPUS_DOMAIN = b"securescan-syft-controlled-corpus-s1\0"
_REPORT_SCHEMA = "securescan-syft-controlled-evidence-s1"


class SyftBenchmarkError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("Controlled Syft inventory evaluation failed")


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


def corpus_identity(corpus_root: Path) -> tuple[str, tuple[str, ...]]:
    try:
        paths = tuple(
            sorted(
                path.relative_to(corpus_root).as_posix()
                for path in corpus_root.rglob("*")
                if path.is_file() and not path.is_symlink()
            )
        )
        digest = hashlib.sha256()
        digest.update(_CORPUS_DOMAIN)
        for relative_path in paths:
            content = (corpus_root / relative_path).read_bytes()
            digest.update(relative_path.encode("utf-8"))
            digest.update(b"\0")
            digest.update(str(len(content)).encode("ascii"))
            digest.update(b"\0")
            digest.update(hashlib.sha256(content).digest())
        return digest.hexdigest(), paths
    except (OSError, UnicodeError):
        raise SyftBenchmarkError from None


def _execute(
    binding: TrustedSyftBinding,
    root: Path,
    *,
    snapshot_digest: str,
    paths: tuple[str, ...],
):
    executor = CancellableProcessExecutor()
    handle = binding.start_directory_execution(root, executor)
    with handle:
        result = handle.wait(timeout_seconds=305)
    if result is None:
        raise SyftBenchmarkError
    if (
        result.return_code != 0
        or result.stderr
        or result.timed_out
        or result.output_limit_exceeded
        or result.termination_requested
        or result.force_killed
    ):
        raise SyftBenchmarkError
    return parse_syft_json(
        result.stdout,
        expected_source_root=str(root),
        authorized_paths=frozenset(paths),
        projection_id=_PROJECTION_ID,
        snapshot_digest=snapshot_digest,
        binding_digest=binding.binding_digest(),
    )


def build_controlled_report(repository_root: Path, executable_path: Path) -> dict[str, Any]:
    repository_root = repository_root.resolve(strict=True)
    corpus_root = (repository_root / "benchmarks/syft/corpus").resolve(strict=True)
    binding = create_default_syft_binding(executable_path.resolve(strict=True))
    binding.verify_runtime()
    corpus_digest, paths = corpus_identity(corpus_root)
    first = _execute(binding, corpus_root, snapshot_digest=corpus_digest, paths=paths)
    second = _execute(binding, corpus_root, snapshot_digest=corpus_digest, paths=paths)
    empty_root = corpus_root / "empty"
    empty_digest, empty_paths = corpus_identity(empty_root)
    empty = _execute(
        binding,
        empty_root,
        snapshot_digest=empty_digest,
        paths=empty_paths,
    )
    if first.canonical_json() != second.canonical_json() or empty.package_count != 0:
        raise SyftBenchmarkError
    package_types = Counter(item.package_type for item in first.observations)
    languages = Counter(item.language or "unknown" for item in first.observations)
    catalogers = Counter(item.found_by for item in first.observations)
    return {
        "binding": {
            "archive_sha256": SYFT_ARCHIVE_SHA256,
            "binding_digest": binding.binding_digest(),
            "config_sha256": SYFT_CONFIG_SHA256,
            "executable_sha256": SYFT_EXECUTABLE_SHA256,
            "scanner_id": SYFT_SCANNER_ID,
            "scanner_version": SYFT_VERSION,
        },
        "cataloger_counts": dict(sorted(catalogers.items())),
        "corpus_digest": corpus_digest,
        "zero_package_fixture": {
            "completed": True,
            "package_count": empty.package_count,
        },
        "language_counts": dict(sorted(languages.items())),
        "maturity_recommendation": "scannable",
        "observations": [
            {
                "cataloger": item.found_by,
                "language": item.language,
                "locations": list(item.locations),
                "package_key": item.package_key,
                "package_observation_id": item.package_observation_id,
                "package_type": item.package_type,
                "version_resolved": item.package_version is not None,
            }
            for item in first.observations
        ],
        "package_count": first.package_count,
        "package_type_counts": dict(sorted(package_types.items())),
        "repeatability": {
            "normalized_structural_evidence_equal": True,
            "runs": 2,
        },
        "requested_cataloger_strategy": list(first.requested_cataloger_strategy),
        "schema_version": _REPORT_SCHEMA,
        "syft_json_schema_version": SYFT_JSON_SCHEMA_VERSION,
        "used_catalogers": list(first.used_catalogers),
    }


def record_controlled_artifacts(repository_root: Path, executable_path: Path) -> None:
    report = canonical_json(build_controlled_report(repository_root, executable_path))
    binding = create_default_syft_binding(executable_path.resolve(strict=True))
    expected = {
        repository_root / "benchmarks/syft/controlled-s1-evidence.json": report,
        repository_root / "benchmarks/syft/syft-binding-v1.json": (
            canonical_syft_binding_artifact(binding)
        ),
        repository_root / "benchmarks/syft/contract-v1.json": canonical_syft_contract(binding),
    }
    for path, payload in expected.items():
        if path.exists() and path.read_bytes() != payload:
            raise SyftBenchmarkError
    for path, payload in expected.items():
        path.write_bytes(payload)


def main() -> int:
    root = Path(__file__).resolve().parents[3]
    executable_value = os.environ.get("SECURESCAN_SYFT_EXECUTABLE")
    if not executable_value:
        raise SyftBenchmarkError
    executable = Path(executable_value)
    mode = os.environ.get("SECURESCAN_SYFT_MODE", "report")
    if mode == "check":
        binding = create_default_syft_binding(executable.resolve(strict=True))
        binding.verify_runtime()
        corpus_digest, _ = corpus_identity(root / "benchmarks/syft/corpus")
        print(
            canonical_json(
                {
                    "binding_digest": binding.binding_digest(),
                    "corpus_digest": corpus_digest,
                    "scanner_id": SYFT_SCANNER_ID,
                    "scanner_version": SYFT_VERSION,
                }
            ).decode(),
            end="",
        )
    elif mode == "report":
        print(canonical_json(build_controlled_report(root, executable)).decode(), end="")
    elif mode == "record":
        record_controlled_artifacts(root, executable)
    else:
        raise SyftBenchmarkError
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
