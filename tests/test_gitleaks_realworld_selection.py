from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from securescan.benchmarks.gitleaks_realworld_acquisition_contract import (
    GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_PATH,
    GITLEAKS_REALWORLD_ACQUISITION_POLICY_SHA256,
    GITLEAKS_ROLE_EVIDENCE_VOCABULARY,
    GitleaksRealworldAcquisitionManifestState,
    canonical_gitleaks_realworld_acquisition,
)
from securescan.benchmarks.gitleaks_realworld_contract import (
    GITLEAKS_MATURITY,
    GITLEAKS_REALWORLD_RESULT_PATH,
    GitleaksRealworldAcquisitionMethod,
)
from securescan.benchmarks.gitleaks_realworld_selection import (
    GITLEAKS_F5B1_COMMIT,
    GITLEAKS_F5B1_TAG,
    GITLEAKS_F5B2_COMMIT,
    GITLEAKS_F5B2_SELECTED_MANIFEST_SHA256,
    GITLEAKS_F5B2_TAG,
    GITLEAKS_F5B2R1_COMMIT,
    GITLEAKS_F5B2R1_SELECTED_MANIFEST_SHA256,
    GITLEAKS_F5B2R1_TAG,
    GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_SHA256,
    GITLEAKS_SELECTION_COMPATIBILITY_REPLACEMENTS,
    GitleaksRealworldSelectionError,
    gitleaks_realworld_selected_model,
    gitleaks_realworld_selection_document,
    load_gitleaks_realworld_selection,
    verify_gitleaks_realworld_selection,
)

ROOT = Path(__file__).resolve().parents[1]
_ACQUISITION_FIELDS = (
    "archive_sha256",
    "archive_byte_count",
    "snapshot_digest",
    "file_count",
    "byte_count",
)
_EXPECTED_IDENTITIES = (
    (
        "RW01",
        "RW01_SMALL_APPLICATION",
        "charmbracelet-gum",
        "https://github.com/charmbracelet/gum",
        "https://github.com/charmbracelet/gum/archive/4d089f95507708a71f64dacfe7ca513219dd5267.tar.gz",
        "4d089f95507708a71f64dacfe7ca513219dd5267",
        "MIT",
    ),
    (
        "RW02",
        "RW02_LIBRARY_PACKAGE",
        "pallets-click",
        "https://github.com/pallets/click",
        "https://github.com/pallets/click/archive/36baa15ff831b939a22bc527cd76ce653ef6f66d.tar.gz",
        "36baa15ff831b939a22bc527cd76ce653ef6f66d",
        "BSD-3-Clause",
    ),
    (
        "RW03",
        "RW03_DOCS_EXAMPLES_HEAVY",
        "pallets-flask",
        "https://github.com/pallets/flask",
        "https://github.com/pallets/flask/archive/d318b683471101618febed18996405ad26462110.tar.gz",
        "d318b683471101618febed18996405ad26462110",
        "BSD-3-Clause",
    ),
    (
        "RW04",
        "RW04_DEPENDENCY_GENERATED_PATH_HEAVY",
        "quad4-software-reticulum-go",
        "https://github.com/Quad4-Software/Reticulum-Go",
        "https://github.com/Quad4-Software/Reticulum-Go/archive/5bf60debb7fdcd27b175d4db2585dd994a3d1b66.tar.gz",
        "5bf60debb7fdcd27b175d4db2585dd994a3d1b66",
        "Apache-2.0",
    ),
    (
        "RW05",
        "RW05_MULTI_LANGUAGE",
        "golang-go",
        "https://github.com/golang/go",
        "https://github.com/golang/go/archive/c5941983810b68ba93c30f0ef22c91ad63fb3e5c.tar.gz",
        "c5941983810b68ba93c30f0ef22c91ad63fb3e5c",
        "BSD-3-Clause",
    ),
    (
        "RW06",
        "RW06_BINARY_CONFIG_ASSETS",
        "sslmate-go-pkcs12",
        "https://github.com/SSLMate/go-pkcs12",
        "https://github.com/SSLMate/go-pkcs12/archive/c0472edb16891765fbc86573ea468365b7fd2197.tar.gz",
        "c0472edb16891765fbc86573ea468365b7fd2197",
        "BSD-3-Clause",
    ),
)
_EXPECTED_ROLE_EVIDENCE = (
    ("application_entrypoint", "package_manifest"),
    ("package_manifest", "documentation_directory", "tests_directory"),
    (
        "package_manifest",
        "documentation_directory",
        "examples_directory",
        "tests_directory",
    ),
    ("package_manifest", "vendor_directory"),
    ("documentation_directory", "tests_directory", "multiple_language_families"),
    ("package_manifest", "tests_directory", "binary_asset", "configuration_asset"),
)


def test_selected_manifest_is_canonical_digest_bound_and_verified() -> None:
    path = ROOT / GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_PATH
    payload = path.read_bytes()

    assert hashlib.sha256(payload).hexdigest() == (
        GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_SHA256
    )
    assert GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_SHA256 == (
        "c4843b6558fbccff370d66cd621a42927ec9c1fb1bc26cb2f036c6656b24673b"
    )
    assert payload == canonical_gitleaks_realworld_acquisition(
        gitleaks_realworld_selection_document()
    )
    assert load_gitleaks_realworld_selection(path) == json.loads(payload)
    assert verify_gitleaks_realworld_selection(ROOT.resolve()) == json.loads(payload)


def test_f5b1_boundary_is_exact_and_current_head_is_a_descendant() -> None:
    resolved = subprocess.run(
        ["git", "rev-parse", f"{GITLEAKS_F5B1_TAG}^{{commit}}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    ancestry = subprocess.run(
        ["git", "merge-base", "--is-ancestor", GITLEAKS_F5B1_COMMIT, "HEAD"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert GITLEAKS_F5B1_COMMIT == "b5a65d961b136966095ad97c5afb9945d56a6f08"
    assert GITLEAKS_F5B1_TAG == "source-v0.4F5B1-gitleaks-acquisition-policy"
    assert resolved == GITLEAKS_F5B1_COMMIT
    assert ancestry.returncode == 0


def test_f5b2_boundary_is_exact_and_current_head_is_a_descendant() -> None:
    resolved = subprocess.run(
        ["git", "rev-parse", f"{GITLEAKS_F5B2_TAG}^{{commit}}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    ancestry = subprocess.run(
        ["git", "merge-base", "--is-ancestor", GITLEAKS_F5B2_COMMIT, "HEAD"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert GITLEAKS_F5B2_COMMIT == "f8237a01879f437c3fdf958416663f957afcbe21"
    assert GITLEAKS_F5B2_TAG == "source-v0.4F5B2-gitleaks-repository-selection"
    assert GITLEAKS_F5B2_SELECTED_MANIFEST_SHA256 == (
        "2af9aa332be75b069e948c5d01db95c2a7b5138d654e12ed5ce8e748cd632679"
    )
    assert resolved == GITLEAKS_F5B2_COMMIT
    assert ancestry.returncode == 0


def test_rw01_and_unchanged_slots_are_byte_equivalent_to_f5b2r1() -> None:
    historical_payload = subprocess.run(
        [
            "git",
            "show",
            f"{GITLEAKS_F5B2R1_COMMIT}:{GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_PATH}",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout
    historical = json.loads(historical_payload)
    corrected = gitleaks_realworld_selection_document()

    for position in (0, 2, 3, 5):
        assert canonical_gitleaks_realworld_acquisition(
            historical["repository_slots"][position]
        ) == canonical_gitleaks_realworld_acquisition(
            corrected["repository_slots"][position]
        )
    for position in (1, 4):
        assert historical["repository_slots"][position] != corrected[
            "repository_slots"
        ][position]


def test_f5b2r1_boundary_is_exact_and_current_head_is_a_descendant() -> None:
    resolved = subprocess.run(
        ["git", "rev-parse", f"{GITLEAKS_F5B2R1_TAG}^{{commit}}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    ancestry = subprocess.run(
        ["git", "merge-base", "--is-ancestor", GITLEAKS_F5B2R1_COMMIT, "HEAD"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert GITLEAKS_F5B2R1_COMMIT == "d7aede2a8ad0425756b330026c4bd7172648ce90"
    assert GITLEAKS_F5B2R1_TAG == (
        "source-v0.4F5B2R1-gitleaks-repository-selection-correction"
    )
    assert GITLEAKS_F5B2R1_SELECTED_MANIFEST_SHA256 == (
        "cde25ca550f76ec35ea1b09e7c4d113beb8b205865c8ebf278e9c16159e2d510"
    )
    assert resolved == GITLEAKS_F5B2R1_COMMIT
    assert ancestry.returncode == 0


def test_replacements_are_only_for_f5b1_acquisition_compatibility() -> None:
    entries = gitleaks_realworld_selected_model().entries

    assert entries[0].repository_id == "charmbracelet-gum"
    assert entries[1].repository_id == "pallets-click"
    assert entries[4].repository_id == "golang-go"
    assert "psf-requests" not in {entry.repository_id for entry in entries}
    assert "git-git" not in {entry.repository_id for entry in entries}
    assert GITLEAKS_SELECTION_COMPATIBILITY_REPLACEMENTS == (
        ("RW02", "F5B1_ACQUISITION_POLICY_SYMLINK"),
        ("RW05", "F5B1_ACQUISITION_POLICY_SYMLINK_AND_GITLINK"),
    )


def test_exact_selected_repository_identities_are_frozen() -> None:
    entries = gitleaks_realworld_selected_model().entries

    assert tuple(
        (
            entry.slot_id,
            entry.role.value,
            entry.repository_id,
            entry.upstream_url,
            entry.archive_url,
            entry.exact_commit_sha,
            entry.license_identifier,
        )
        for entry in entries
    ) == _EXPECTED_IDENTITIES


def test_selected_state_populates_only_selection_fields() -> None:
    model = gitleaks_realworld_selected_model()

    assert model.state is GitleaksRealworldAcquisitionManifestState.SELECTED
    assert len(model.entries) == 6
    for entry in model.entries:
        data = entry.canonical_data()
        assert entry.acquisition_method is (
            GitleaksRealworldAcquisitionMethod.UPSTREAM_ARCHIVE
        )
        assert all(data[field] is None for field in _ACQUISITION_FIELDS)
        assert all(
            data[field] is not None
            for field in (
                "repository_id",
                "upstream_url",
                "archive_url",
                "exact_commit_sha",
                "license_identifier",
                "acquisition_method",
                "pre_scan_role_evidence",
                "pre_scan_role_rationale",
            )
        )


def test_selected_identities_satisfy_all_f5b1_uniqueness_requirements() -> None:
    entries = gitleaks_realworld_selected_model().entries

    assert len({entry.repository_id for entry in entries}) == 6
    assert len({entry.upstream_url for entry in entries}) == 6
    assert len({entry.archive_url for entry in entries}) == 6
    assert len(
        {(entry.upstream_url, entry.exact_commit_sha) for entry in entries}
    ) == 6


def test_archive_urls_are_https_and_explicitly_bind_the_exact_commit() -> None:
    for entry in gitleaks_realworld_selected_model().entries:
        assert entry.archive_url is not None
        assert entry.archive_url.startswith("https://")
        assert entry.exact_commit_sha is not None
        assert f"/{entry.exact_commit_sha}.tar.gz" in entry.archive_url


def test_role_evidence_uses_only_the_frozen_vocabulary() -> None:
    allowed = set(GITLEAKS_ROLE_EVIDENCE_VOCABULARY)
    entries = gitleaks_realworld_selected_model().entries

    assert tuple(entry.pre_scan_role_evidence for entry in entries) == (
        _EXPECTED_ROLE_EVIDENCE
    )
    for entry in entries:
        assert entry.pre_scan_role_evidence
        assert set(entry.pre_scan_role_evidence) <= allowed
        assert entry.pre_scan_role_rationale


def test_selection_preserves_frozen_bindings_maturity_and_result_absence() -> None:
    document = gitleaks_realworld_selection_document()

    assert document["bindings"]["acquisition_policy_sha256"] == (
        GITLEAKS_REALWORLD_ACQUISITION_POLICY_SHA256
    )
    assert document["maturity"] == GITLEAKS_MATURITY == "SCANNABLE"
    assert document["contains_result_or_finding_data"] is False
    assert not os.path.lexists(ROOT / GITLEAKS_REALWORLD_RESULT_PATH)


@pytest.mark.parametrize("invalid", ("modified", "noncanonical", "symlink"))
def test_untrusted_selection_artifact_fails_closed(
    tmp_path: Path,
    invalid: str,
) -> None:
    source = ROOT / GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_PATH
    path = tmp_path / "selection.json"
    if invalid == "modified":
        path.write_bytes(source.read_bytes() + b"modified")
    elif invalid == "noncanonical":
        path.write_text(json.dumps(json.loads(source.read_bytes()), indent=2) + "\n")
    else:
        path.symlink_to(source)

    with pytest.raises(
        GitleaksRealworldSelectionError,
        match="^Gitleaks real-world repository selection is invalid$",
    ):
        load_gitleaks_realworld_selection(path)
