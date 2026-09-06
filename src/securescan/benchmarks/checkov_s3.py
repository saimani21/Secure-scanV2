from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import Any, Final

from securescan.execution import CancellableProcessExecutor
from securescan.scanners.checkov import (
    CHECKOV_AUTHORITY_EXCLUDED_CHECKS,
    CHECKOV_CONFIG_SHA256,
    CHECKOV_FRAMEWORKS,
    CheckovExecutionResultEnvelope,
    CheckovExecutionStatus,
    CheckovFailureCode,
    TrustedCheckovBinding,
    canonical_checkov_binding_artifact,
    create_default_checkov_binding,
    parse_checkov_execution_result,
)
from securescan.source.projection import PreparedSourceProjection
from securescan.workspaces.models import (
    RepositoryManifest,
    RepositoryManifestEntry,
    repository_content_digest,
)

CHECKOV_CORPUS_MANIFEST_SHA256: Final = (
    "bf2f7d73f82e76dfb297f654e73b3afc6797e653af8c8fade0eebd0c05f584a2"
)
CHECKOV_CORPUS_DIGEST: Final = "be2c1fb0760329d1923f851e17e926d471ca9dd403eba7072ef7d227a09aaca6"
CHECKOV_BINDING_ARTIFACT_SHA256: Final = (
    "e1f064ed06da250b1804e91cd96f8194f812afb378eb53f82c1d0475841ef79d"
)
CHECKOV_CONTROLLED_REPORT_SHA256: Final = (
    "5f30ca5511c1aa12c408d5d323d9922f8a69abfbe7babf5fcaac170bbf8dc4ad"
)
CHECKOV_TOOLCHAIN_ARTIFACT_SHA256: Final = (
    "2380453c897805ec7df03854411e5849465f7b8e1af0b0142c76e51b27343dbd"
)

_CORPUS_DOMAIN = b"securescan-checkov-controlled-corpus-s3\0"
_PROJECTION_ID = "securescan-source-projection-" + "3" * 32
_CONTEXT_DIGEST = "6" * 64
_CONTROL_RELATIONS = (
    (
        "terraform",
        "CKV_AWS_18",
        "terraform/fail/main.tf",
        "aws_s3_bucket.controlled_fail",
        "terraform/pass/main.tf",
        "aws_s3_bucket.controlled_pass",
    ),
    (
        "cloudformation",
        "CKV_AWS_18",
        "cloudformation/fail/template.yaml",
        "AWS::S3::Bucket.ControlledFail",
        "cloudformation/pass/template.yaml",
        "AWS::S3::Bucket.ControlledPass",
    ),
    (
        "kubernetes",
        "CKV_K8S_20",
        "kubernetes/fail/pod.yaml",
        "Pod.default.controlled-fail",
        "kubernetes/pass/pod.yaml",
        "Pod.default.controlled-pass",
    ),
    (
        "dockerfile",
        "CKV_DOCKER_3",
        "dockerfile/fail/Dockerfile",
        "/dockerfile/fail/Dockerfile.",
        "dockerfile/pass/Dockerfile",
        "/dockerfile/pass/Dockerfile.USER",
    ),
    (
        "github_actions",
        "CKV_GHA_7",
        "github_actions/fail/.github/workflows/controlled.yml",
        "on(controlled-fail)",
        "github_actions/pass/.github/workflows/controlled.yml",
        "on(controlled-pass)",
    ),
)


class CheckovBenchmarkError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("Controlled Checkov benchmark failed")


def _root() -> Path:
    return Path(__file__).resolve().parents[3]


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        ).encode()
        + b"\n"
    )


def _load_manifest(root: Path) -> tuple[dict[str, Any], bytes]:
    path = root / "benchmarks" / "checkov" / "controlled-corpus-manifest-v1.json"
    try:
        metadata = os.lstat(path)
        payload = path.read_bytes()
        document = json.loads(payload)
    except (OSError, TypeError, ValueError):
        raise CheckovBenchmarkError from None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or hashlib.sha256(payload).hexdigest() != CHECKOV_CORPUS_MANIFEST_SHA256
        or not isinstance(document, dict)
        or document.get("schema_version") != "securescan-checkov-controlled-corpus-s3"
        or not isinstance(document.get("files"), list)
        or hashlib.sha256(_CORPUS_DOMAIN + payload).hexdigest() != CHECKOV_CORPUS_DIGEST
    ):
        raise CheckovBenchmarkError
    return document, payload


def _verify_corpus(root: Path) -> tuple[tuple[RepositoryManifestEntry, ...], frozenset[str]]:
    document, _payload = _load_manifest(root)
    corpus = root / "benchmarks" / "checkov" / "corpus"
    entries: list[RepositoryManifestEntry] = []
    listed: list[str] = []
    for raw in document["files"]:
        if not isinstance(raw, dict) or set(raw) != {"path", "sha256", "size_bytes"}:
            raise CheckovBenchmarkError
        path = raw["path"]
        try:
            target = corpus / path
            metadata = os.lstat(target)
            payload = target.read_bytes()
            entry = RepositoryManifestEntry(path, raw["size_bytes"], raw["sha256"])
        except (OSError, TypeError, ValueError):
            raise CheckovBenchmarkError from None
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_size != entry.size_bytes
            or len(payload) != entry.size_bytes
            or hashlib.sha256(payload).hexdigest() != entry.sha256
        ):
            raise CheckovBenchmarkError
        entries.append(entry)
        listed.append(path)
    discovered = sorted(
        item.relative_to(corpus).as_posix() for item in corpus.rglob("*") if item.is_file()
    )
    if listed != sorted(listed) or listed != discovered or len(set(listed)) != len(listed):
        raise CheckovBenchmarkError
    return tuple(entries), frozenset(listed)


def _binding(root: Path, executable_path: Path | None = None) -> TrustedCheckovBinding:
    return create_default_checkov_binding(
        (root / ".venv-checkov-3.3.16" / "bin" / "checkov").resolve()
        if executable_path is None
        else executable_path.resolve()
    )


def _projection(
    root: Path, entries: tuple[RepositoryManifestEntry, ...]
) -> PreparedSourceProjection:
    digest = repository_content_digest(entries)
    manifest = RepositoryManifest(
        entries=entries,
        file_count=len(entries),
        total_bytes=sum(item.size_bytes for item in entries),
        content_digest=digest,
    )
    projection_root = root / "benchmarks" / "checkov" / _PROJECTION_ID
    return PreparedSourceProjection(
        projection_id=_PROJECTION_ID,
        root_directory=projection_root,
        source_directory=projection_root / "source",
        manifest=manifest,
        context_digest=_CONTEXT_DIGEST,
        projection_digest=digest,
    )


def build_controlled_checkov_report(
    root: Path | None = None,
    *,
    executable_path: Path | None = None,
) -> dict[str, Any]:
    repository_root = _root() if root is None else root.resolve()
    entries, authorized_paths = _verify_corpus(repository_root)
    binding = _binding(repository_root, executable_path)
    executor = CancellableProcessExecutor()
    binding.verify_runtime(executor)
    request = binding.build_directory_request(repository_root / "benchmarks" / "checkov" / "corpus")
    try:
        with executor.start(request) as handle:
            process_result = handle.wait(timeout_seconds=310.0)
    except Exception:
        raise CheckovBenchmarkError from None
    if process_result is None:
        raise CheckovBenchmarkError
    projection = _projection(repository_root, entries)
    envelope = CheckovExecutionResultEnvelope.from_process_result(
        process_result,
        binding=binding,
        projection=projection,
        cancellation_requested=False,
    )
    if envelope.execution_status is not CheckovExecutionStatus.COMPLETED:
        raise CheckovBenchmarkError
    parsed = parse_checkov_execution_result(
        envelope,
        projection_root=repository_root / "benchmarks" / "checkov" / "corpus",
        authorized_paths=authorized_paths,
    )
    failed_keys = {
        (item.framework, item.check_id, item.normalized_path, item.resource)
        for item in parsed.observations
    }
    passed_keys = {
        (item.framework, item.check_id, item.normalized_path, item.resource)
        for item in parsed.passed_observations
    }
    relations: list[dict[str, Any]] = []
    for (
        framework,
        check_id,
        fail_path,
        fail_resource,
        pass_path,
        pass_resource,
    ) in _CONTROL_RELATIONS:
        fail_ok = (framework, check_id, fail_path, fail_resource) in failed_keys
        pass_ok = (framework, check_id, pass_path, pass_resource) in passed_keys
        if not fail_ok or not pass_ok:
            raise CheckovBenchmarkError
        relations.append(
            {
                "check_id": check_id,
                "fail_path": fail_path,
                "failed_observed": fail_ok,
                "framework": framework,
                "pass_path": pass_path,
                "passed_observed": pass_ok,
            }
        )
    expected_suppression = (
        "terraform",
        "CKV_AWS_18",
        "terraform/suppressed/main.tf",
        "controlled accepted risk",
    )
    if not any(
        (item.framework, item.check_id, item.normalized_path, item.reason) == expected_suppression
        for item in parsed.suppressions
    ) or not any(
        item.framework == "terraform"
        and item.normalized_path == "terraform/malformed/main.tf"
        and item.code == CheckovFailureCode.PARSE_GAP.value
        for item in parsed.gaps
    ):
        raise CheckovBenchmarkError
    authority_excluded = set(CHECKOV_AUTHORITY_EXCLUDED_CHECKS)
    if any(item.check_id in authority_excluded for item in parsed.observations):
        raise CheckovBenchmarkError
    if (
        "terraform/authority-secret/main.tf" not in authorized_paths
        or (
            "terraform",
            "CKV_AWS_18",
            "terraform/authority-secret/main.tf",
            "aws_s3_bucket.authority_control",
        )
        not in failed_keys
    ):
        raise CheckovBenchmarkError
    return {
        "authority_boundary": {
            "direct_secret_material_check_ids_excluded": list(
                CHECKOV_AUTHORITY_EXCLUDED_CHECKS
            ),
            "excluded_check_observations": 0,
            "unrelated_configuration_control_observed": {
                "check_id": "CKV_AWS_18",
                "path": "terraform/authority-secret/main.tf",
                "resource": "aws_s3_bucket.authority_control",
            },
        },
        "binding": {
            "config_sha256": CHECKOV_CONFIG_SHA256,
            "digest": binding.binding_digest(),
            "scanner_id": binding.scanner_id,
            "scanner_version": binding.scanner_version,
        },
        "controlled_relations": relations,
        "corpus_digest": CHECKOV_CORPUS_DIGEST,
        "framework_allowlist": list(CHECKOV_FRAMEWORKS),
        "normalized_result": parsed.canonical_data(),
        "privacy": {
            "absolute_host_paths_persisted": False,
            "code_blocks_persisted": False,
            "connected_nodes_persisted": False,
            "evaluations_persisted": False,
            "raw_json_persisted": False,
            "variable_values_persisted": False,
        },
        "schema_version": "securescan-checkov-controlled-report-s3",
    }


def _write_exclusive(path: Path, payload: bytes) -> None:
    staging: Path | None = None
    linked_identity: tuple[int, int] | None = None
    committed = False
    try:
        path.lstat()
    except FileNotFoundError:
        pass
    except OSError:
        raise CheckovBenchmarkError from None
    else:
        raise CheckovBenchmarkError
    try:
        parent = path.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode):
            raise CheckovBenchmarkError
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        staging = Path(temporary_name)
        try:
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise CheckovBenchmarkError
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        staging_metadata = staging.lstat()
        os.link(staging, path, follow_symlinks=False)
        linked_identity = (staging_metadata.st_dev, staging_metadata.st_ino)
        directory_descriptor = os.open(
            path.parent,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        committed = True
    except CheckovBenchmarkError:
        raise
    except (OSError, TypeError, ValueError):
        raise CheckovBenchmarkError from None
    finally:
        if linked_identity is not None and not committed:
            try:
                destination_metadata = path.lstat()
                if (destination_metadata.st_dev, destination_metadata.st_ino) == linked_identity:
                    path.unlink()
            except OSError:
                pass
        if staging is not None:
            with suppress(OSError):
                staging.unlink()


def verify_frozen_checkov_evidence(root: Path | None = None) -> None:
    repository_root = _root() if root is None else root.resolve()
    _verify_corpus(repository_root)
    binding = _binding(repository_root)
    binding.verify_runtime()
    binding_path = repository_root / "benchmarks" / "checkov" / "binding-v1.json"
    report_path = repository_root / "benchmarks" / "checkov" / "controlled-evaluation-v1.json"
    toolchain_path = (
        repository_root / "benchmarks" / "checkov" / "toolchain-characterization-v1.json"
    )
    try:
        binding_payload = binding_path.read_bytes()
        report_payload = report_path.read_bytes()
        toolchain_payload = toolchain_path.read_bytes()
    except OSError:
        raise CheckovBenchmarkError from None
    if (
        binding_payload != canonical_checkov_binding_artifact(binding)
        or hashlib.sha256(binding_payload).hexdigest() != CHECKOV_BINDING_ARTIFACT_SHA256
        or hashlib.sha256(report_payload).hexdigest() != CHECKOV_CONTROLLED_REPORT_SHA256
        or hashlib.sha256(toolchain_payload).hexdigest()
        != CHECKOV_TOOLCHAIN_ARTIFACT_SHA256
    ):
        raise CheckovBenchmarkError


def main() -> None:
    mode = os.environ.get("SECURESCAN_CHECKOV_MODE", "check")
    root = _root()
    if mode == "check":
        verify_frozen_checkov_evidence(root)
        return
    report = build_controlled_checkov_report(root)
    payload = _canonical_json(report)
    if mode == "report":
        os.write(1, payload)
        return
    if mode == "record":
        _write_exclusive(root / "benchmarks" / "checkov" / "controlled-evaluation-v1.json", payload)
        return
    raise CheckovBenchmarkError


if __name__ == "__main__":
    main()
