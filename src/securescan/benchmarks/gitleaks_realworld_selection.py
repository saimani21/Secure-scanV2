from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from contextlib import suppress
from pathlib import Path
from typing import Final

from securescan.benchmarks.gitleaks_realworld_acquisition_contract import (
    GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_PATH,
    GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_SCHEMA_PATH,
    GITLEAKS_REALWORLD_ACQUISITION_POLICY_PATH,
    GitleaksRealworldAcquisitionContractError,
    GitleaksRealworldAcquisitionManifestEntry,
    GitleaksRealworldAcquisitionManifestModel,
    GitleaksRealworldAcquisitionManifestState,
    canonical_gitleaks_realworld_acquisition,
    gitleaks_realworld_acquisition_manifest_schema_document,
    load_gitleaks_realworld_acquisition_manifest_schema,
    load_gitleaks_realworld_acquisition_policy,
)
from securescan.benchmarks.gitleaks_realworld_contract import (
    GITLEAKS_MATURITY,
    GITLEAKS_REALWORLD_RESULT_PATH,
    GitleaksRealworldAcquisitionMethod,
    GitleaksRealworldContractError,
    GitleaksRealworldRepositoryRole,
    verify_gitleaks_realworld_contract,
)

GITLEAKS_F5B1_COMMIT: Final = "b5a65d961b136966095ad97c5afb9945d56a6f08"
GITLEAKS_F5B1_TAG: Final = "source-v0.4F5B1-gitleaks-acquisition-policy"
GITLEAKS_F5B2_COMMIT: Final = "f8237a01879f437c3fdf958416663f957afcbe21"
GITLEAKS_F5B2_TAG: Final = "source-v0.4F5B2-gitleaks-repository-selection"
GITLEAKS_F5B2_SELECTED_MANIFEST_SHA256: Final = (
    "2af9aa332be75b069e948c5d01db95c2a7b5138d654e12ed5ce8e748cd632679"
)
GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_SHA256: Final = (
    "cde25ca550f76ec35ea1b09e7c4d113beb8b205865c8ebf278e9c16159e2d510"
)

_MAX_MANIFEST_BYTES = 1024 * 1024


class GitleaksRealworldSelectionError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("Gitleaks real-world repository selection is invalid")


def gitleaks_realworld_selected_model() -> GitleaksRealworldAcquisitionManifestModel:
    selections = (
        GitleaksRealworldAcquisitionManifestEntry(
            slot_id="RW01",
            role=GitleaksRealworldRepositoryRole.RW01_SMALL_APPLICATION,
            repository_id="charmbracelet-gum",
            upstream_url="https://github.com/charmbracelet/gum",
            archive_url=(
                "https://github.com/charmbracelet/gum/archive/"
                "4d089f95507708a71f64dacfe7ca513219dd5267.tar.gz"
            ),
            exact_commit_sha="4d089f95507708a71f64dacfe7ca513219dd5267",
            license_identifier="MIT",
            acquisition_method=GitleaksRealworldAcquisitionMethod.UPSTREAM_ARCHIVE,
            pre_scan_role_evidence=("application_entrypoint", "package_manifest"),
            pre_scan_role_rationale=(
                "Public standalone Go CLI application with a main entry point and Go "
                "module manifest in a compact source layout."
            ),
        ),
        GitleaksRealworldAcquisitionManifestEntry(
            slot_id="RW02",
            role=GitleaksRealworldRepositoryRole.RW02_LIBRARY_PACKAGE,
            repository_id="psf-requests",
            upstream_url="https://github.com/psf/requests",
            archive_url=(
                "https://github.com/psf/requests/archive/"
                "dae7ef63b4df6eded86637f251fc4e3a06c3b479.tar.gz"
            ),
            exact_commit_sha="dae7ef63b4df6eded86637f251fc4e3a06c3b479",
            license_identifier="Apache-2.0",
            acquisition_method=GitleaksRealworldAcquisitionMethod.UPSTREAM_ARCHIVE,
            pre_scan_role_evidence=(
                "package_manifest",
                "documentation_directory",
                "tests_directory",
            ),
            pre_scan_role_rationale=(
                "Public Python HTTP client library with package metadata, maintained "
                "documentation, and a dedicated test tree."
            ),
        ),
        GitleaksRealworldAcquisitionManifestEntry(
            slot_id="RW03",
            role=GitleaksRealworldRepositoryRole.RW03_DOCS_EXAMPLES_HEAVY,
            repository_id="pallets-flask",
            upstream_url="https://github.com/pallets/flask",
            archive_url=(
                "https://github.com/pallets/flask/archive/"
                "d318b683471101618febed18996405ad26462110.tar.gz"
            ),
            exact_commit_sha="d318b683471101618febed18996405ad26462110",
            license_identifier="BSD-3-Clause",
            acquisition_method=GitleaksRealworldAcquisitionMethod.UPSTREAM_ARCHIVE,
            pre_scan_role_evidence=(
                "package_manifest",
                "documentation_directory",
                "examples_directory",
                "tests_directory",
            ),
            pre_scan_role_rationale=(
                "Public Python web framework with substantial documentation, examples, "
                "and tests alongside its package metadata."
            ),
        ),
        GitleaksRealworldAcquisitionManifestEntry(
            slot_id="RW04",
            role=(
                GitleaksRealworldRepositoryRole.RW04_DEPENDENCY_GENERATED_PATH_HEAVY
            ),
            repository_id="quad4-software-reticulum-go",
            upstream_url="https://github.com/Quad4-Software/Reticulum-Go",
            archive_url=(
                "https://github.com/Quad4-Software/Reticulum-Go/archive/"
                "5bf60debb7fdcd27b175d4db2585dd994a3d1b66.tar.gz"
            ),
            exact_commit_sha="5bf60debb7fdcd27b175d4db2585dd994a3d1b66",
            license_identifier="Apache-2.0",
            acquisition_method=GitleaksRealworldAcquisitionMethod.UPSTREAM_ARCHIVE,
            pre_scan_role_evidence=("package_manifest", "vendor_directory"),
            pre_scan_role_rationale=(
                "Public Go network-stack application with module metadata and a tracked "
                "vendor tree that exercises dependency-heavy paths."
            ),
        ),
        GitleaksRealworldAcquisitionManifestEntry(
            slot_id="RW05",
            role=GitleaksRealworldRepositoryRole.RW05_MULTI_LANGUAGE,
            repository_id="git-git",
            upstream_url="https://github.com/git/git",
            archive_url=(
                "https://github.com/git/git/archive/"
                "3cb9185f65410273787f74333cc027d2ea5daada.tar.gz"
            ),
            exact_commit_sha="3cb9185f65410273787f74333cc027d2ea5daada",
            license_identifier="GPL-2.0-only",
            acquisition_method=GitleaksRealworldAcquisitionMethod.UPSTREAM_ARCHIVE,
            pre_scan_role_evidence=(
                "documentation_directory",
                "tests_directory",
                "multiple_language_families",
            ),
            pre_scan_role_rationale=(
                "Public Git source mirror spanning C, shell, Perl, Python, Tcl, "
                "documentation, and test trees."
            ),
        ),
        GitleaksRealworldAcquisitionManifestEntry(
            slot_id="RW06",
            role=GitleaksRealworldRepositoryRole.RW06_BINARY_CONFIG_ASSETS,
            repository_id="sslmate-go-pkcs12",
            upstream_url="https://github.com/SSLMate/go-pkcs12",
            archive_url=(
                "https://github.com/SSLMate/go-pkcs12/archive/"
                "c0472edb16891765fbc86573ea468365b7fd2197.tar.gz"
            ),
            exact_commit_sha="c0472edb16891765fbc86573ea468365b7fd2197",
            license_identifier="BSD-3-Clause",
            acquisition_method=GitleaksRealworldAcquisitionMethod.UPSTREAM_ARCHIVE,
            pre_scan_role_evidence=(
                "package_manifest",
                "tests_directory",
                "binary_asset",
                "configuration_asset",
            ),
            pre_scan_role_rationale=(
                "Public Go PKCS#12 library with package metadata, repository "
                "configuration, and tracked binary certificate fixtures under testdata."
            ),
        ),
    )
    return GitleaksRealworldAcquisitionManifestModel(
        state=GitleaksRealworldAcquisitionManifestState.SELECTED,
        entries=selections,
    )


def gitleaks_realworld_selection_document() -> dict[str, object]:
    document = gitleaks_realworld_acquisition_manifest_schema_document()
    model = gitleaks_realworld_selected_model()
    document["acquisition_state"] = model.state.value
    document["repository_slots"] = [entry.canonical_data() for entry in model.entries]
    return document


def _stat_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _read_stable_manifest(path: Path) -> bytes:
    descriptor = -1
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or before.st_size > _MAX_MANIFEST_BYTES
        ):
            raise OSError
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _stat_identity(opened) != _stat_identity(before):
            raise OSError
        payload = bytearray()
        while len(payload) <= _MAX_MANIFEST_BYTES:
            chunk = os.read(
                descriptor,
                min(65536, _MAX_MANIFEST_BYTES + 1 - len(payload)),
            )
            if not chunk:
                break
            payload.extend(chunk)
        finished = os.fstat(descriptor)
        after = path.lstat()
        if (
            len(payload) > _MAX_MANIFEST_BYTES
            or len(payload) != before.st_size
            or _stat_identity(finished) != _stat_identity(before)
            or _stat_identity(after) != _stat_identity(before)
        ):
            raise OSError
        return bytes(payload)
    except OSError:
        raise GitleaksRealworldSelectionError from None
    finally:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _reject_nonfinite(_value: str) -> None:
    raise ValueError


def load_gitleaks_realworld_selection(path: Path) -> dict[str, object]:
    payload = _read_stable_manifest(path)
    try:
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeDecodeError, ValueError):
        raise GitleaksRealworldSelectionError from None
    if (
        not isinstance(document, dict)
        or canonical_gitleaks_realworld_acquisition(document) != payload
        or hashlib.sha256(payload).hexdigest()
        != GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_SHA256
        or document != gitleaks_realworld_selection_document()
    ):
        raise GitleaksRealworldSelectionError
    return document


def _git_environment() -> dict[str, str]:
    return {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


def _git(
    repository_root: Path,
    *arguments: str,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", *arguments],
            cwd=repository_root,
            env=_git_environment(),
            check=check,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        raise GitleaksRealworldSelectionError from None


def _verify_selection_git_boundary(repository_root: Path) -> None:
    branch = _git(repository_root, "branch", "--show-current").stdout.strip()
    resolved = _git(
        repository_root,
        "rev-parse",
        f"{GITLEAKS_F5B2_TAG}^{{commit}}",
    ).stdout.strip()
    ancestry = _git(
        repository_root,
        "merge-base",
        "--is-ancestor",
        GITLEAKS_F5B2_COMMIT,
        "HEAD",
        check=False,
    )
    if (
        branch != "source/v0.3-semgrep"
        or resolved != GITLEAKS_F5B2_COMMIT
        or ancestry.returncode != 0
        or GITLEAKS_F5B2_SELECTED_MANIFEST_SHA256
        != "2af9aa332be75b069e948c5d01db95c2a7b5138d654e12ed5ce8e748cd632679"
    ):
        raise GitleaksRealworldSelectionError


def verify_gitleaks_realworld_selection(repository_root: Path) -> dict[str, object]:
    if not isinstance(repository_root, Path) or not repository_root.is_absolute():
        raise GitleaksRealworldSelectionError
    try:
        verify_gitleaks_realworld_contract(repository_root)
        load_gitleaks_realworld_acquisition_policy(
            repository_root / GITLEAKS_REALWORLD_ACQUISITION_POLICY_PATH
        )
        load_gitleaks_realworld_acquisition_manifest_schema(
            repository_root / GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_SCHEMA_PATH
        )
    except (
        GitleaksRealworldAcquisitionContractError,
        GitleaksRealworldContractError,
    ):
        raise GitleaksRealworldSelectionError from None
    _verify_selection_git_boundary(repository_root)
    document = load_gitleaks_realworld_selection(
        repository_root / GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_PATH
    )
    if document.get("maturity") != GITLEAKS_MATURITY:
        raise GitleaksRealworldSelectionError
    try:
        (repository_root / GITLEAKS_REALWORLD_RESULT_PATH).lstat()
    except FileNotFoundError:
        return document
    except OSError:
        raise GitleaksRealworldSelectionError from None
    raise GitleaksRealworldSelectionError
