from __future__ import annotations

import hashlib
import json
import os
import shutil
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import pytest

from securescan.benchmarks.gitleaks_realworld_contract import (
    GITLEAKS_BINDING_ARTIFACT_PATH,
    GITLEAKS_BINDING_ARTIFACT_SHA256,
    GITLEAKS_BINDING_DIGEST,
    GITLEAKS_CONFIG_PATH,
    GITLEAKS_CONFIG_SHA256,
    GITLEAKS_F3B_COMMIT,
    GITLEAKS_F3B_REPORT_PATH,
    GITLEAKS_F3B_REPORT_SHA256,
    GITLEAKS_F3B_TAG,
    GITLEAKS_F4C_CHARACTERIZATION_PATH,
    GITLEAKS_F4C_CHARACTERIZATION_SHA256,
    GITLEAKS_F4C_COMMIT,
    GITLEAKS_F4C_TAG,
    GITLEAKS_IGNORE_PATH,
    GITLEAKS_IGNORE_SHA256,
    GITLEAKS_MATURITY,
    GITLEAKS_REALWORLD_CONTRACT_PATH,
    GITLEAKS_REALWORLD_CONTRACT_SCHEMA_VERSION,
    GITLEAKS_REALWORLD_CONTRACT_SHA256,
    GITLEAKS_REALWORLD_EVALUATION_ID,
    GITLEAKS_REALWORLD_RESULT_PATH,
    GITLEAKS_SCANNER_ID,
    GITLEAKS_SCANNER_VERSION,
    GitleaksRealworldAcquisitionMethod,
    GitleaksRealworldAcquisitionState,
    GitleaksRealworldContractError,
    GitleaksRealworldRepositoryRole,
    GitleaksRealworldRepositorySelection,
    GitleaksRealworldRepositorySlot,
    GitleaksRealworldReviewClassification,
    canonical_gitleaks_realworld_contract,
    gitleaks_realworld_contract_document,
    load_gitleaks_realworld_contract,
    pre_acquisition_repository_selection,
    verify_gitleaks_realworld_contract,
)

ROOT = Path(__file__).resolve().parents[1]
_FROZEN_PATHS = (
    GITLEAKS_F3B_REPORT_PATH,
    GITLEAKS_F4C_CHARACTERIZATION_PATH,
    GITLEAKS_BINDING_ARTIFACT_PATH,
    GITLEAKS_CONFIG_PATH,
    GITLEAKS_IGNORE_PATH,
    GITLEAKS_REALWORLD_CONTRACT_PATH,
)
_IDENTITY_FIELDS = (
    "repository_id",
    "upstream_url",
    "exact_commit_sha",
    "license_identifier",
    "acquisition_method",
    "archive_sha256",
    "snapshot_digest",
    "file_count",
    "byte_count",
    "role_selection_evidence",
    "role_selection_rationale",
)
_ACCURACY_METRICS = {"precision", "recall", "f1", "tp", "tn", "fp", "fn"}


def _copy_checkpoint(tmp_path: Path) -> Path:
    root = (tmp_path / "repository").resolve()
    for relative in _FROZEN_PATHS:
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, destination)
    return root


def _rejects(root: Path) -> None:
    with pytest.raises(
        GitleaksRealworldContractError,
        match="^Gitleaks real-world contract is invalid$",
    ):
        verify_gitleaks_realworld_contract(root)


def _rewrite_contract(
    root: Path,
    mutate: Callable[[dict[str, object]], None],
) -> None:
    path = root / GITLEAKS_REALWORLD_CONTRACT_PATH
    document = json.loads(path.read_bytes())
    mutate(document)
    path.write_bytes(canonical_gitleaks_realworld_contract(document))


def _resolved_slot(role: GitleaksRealworldRepositoryRole) -> GitleaksRealworldRepositorySlot:
    position = tuple(GitleaksRealworldRepositoryRole).index(role) + 1
    return GitleaksRealworldRepositorySlot(
        slot_id=role.value.split("_", 1)[0],
        role=role,
        repository_id=f"example-{role.value.lower()}",
        upstream_url=f"https://example.invalid/{role.value.lower()}.git",
        exact_commit_sha=f"{position:x}" * 40,
        license_identifier="Apache-2.0",
        acquisition_method=GitleaksRealworldAcquisitionMethod.UPSTREAM_ARCHIVE,
        archive_sha256=f"{position + 6:x}" * 64,
        snapshot_digest=f"{position:x}" * 64,
        file_count=position,
        byte_count=position * 10,
        role_selection_evidence=(f"frozen evidence {position}",),
        role_selection_rationale=f"role rationale {position}",
    )


def test_frozen_contract_is_canonical_deterministic_and_verified() -> None:
    artifact = (ROOT / GITLEAKS_REALWORLD_CONTRACT_PATH).read_bytes()
    document = verify_gitleaks_realworld_contract(ROOT.resolve())

    assert document == gitleaks_realworld_contract_document()
    assert canonical_gitleaks_realworld_contract(document) == artifact
    assert hashlib.sha256(artifact).hexdigest() == GITLEAKS_REALWORLD_CONTRACT_SHA256
    assert load_gitleaks_realworld_contract(
        ROOT / GITLEAKS_REALWORLD_CONTRACT_PATH
    ) == document
    assert document["schema_version"] == GITLEAKS_REALWORLD_CONTRACT_SCHEMA_VERSION
    assert document["evaluation_id"] == GITLEAKS_REALWORLD_EVALUATION_ID


def test_exact_six_unique_primary_repository_roles_are_frozen_in_order() -> None:
    selection = verify_gitleaks_realworld_contract(ROOT.resolve())["repository_selection"]
    slots = selection["slots"]

    assert selection["slot_count"] == len(slots) == 6
    assert [slot["role"] for slot in slots] == [
        role.value for role in GitleaksRealworldRepositoryRole
    ]
    assert len({slot["role"] for slot in slots}) == 6
    assert len({slot["slot_id"] for slot in slots}) == 6


def test_f5a_repository_identities_are_all_unresolved() -> None:
    selection = verify_gitleaks_realworld_contract(ROOT.resolve())["repository_selection"]

    assert selection["state"] == GitleaksRealworldAcquisitionState.PRE_ACQUISITION.value
    assert all(slot[field] is None for slot in selection["slots"] for field in _IDENTITY_FIELDS)
    serialized = canonical_gitleaks_realworld_contract(selection)
    assert b"https://" not in serialized
    assert b'"exact_commit_sha":"' not in serialized


def test_pre_acquisition_model_accepts_only_fully_unresolved_slots() -> None:
    selection = pre_acquisition_repository_selection()
    assert all(not slot.resolved for slot in selection.slots)

    with pytest.raises(GitleaksRealworldContractError):
        replace(selection.slots[0], repository_id="premature")
    with pytest.raises(GitleaksRealworldContractError):
        GitleaksRealworldRepositorySelection(
            state=GitleaksRealworldAcquisitionState.PRE_ACQUISITION,
            slots=(_resolved_slot(selection.slots[0].role), *selection.slots[1:]),
        )


def test_acquired_model_requires_every_slot_to_be_fully_resolved() -> None:
    resolved = tuple(_resolved_slot(role) for role in GitleaksRealworldRepositoryRole)
    acquired = GitleaksRealworldRepositorySelection(
        state=GitleaksRealworldAcquisitionState.ACQUIRED,
        slots=resolved,
    )
    assert all(slot.resolved for slot in acquired.slots)

    with pytest.raises(GitleaksRealworldContractError):
        GitleaksRealworldRepositorySelection(
            state=GitleaksRealworldAcquisitionState.ACQUIRED,
            slots=(*resolved[:-1], pre_acquisition_repository_selection().slots[-1]),
        )


@pytest.mark.parametrize(
    "field",
    ("repository_id", "upstream_url", "snapshot_digest", "commit_pair"),
)
def test_acquired_model_rejects_duplicate_repository_identities(
    field: str,
) -> None:
    resolved = list(_resolved_slot(role) for role in GitleaksRealworldRepositoryRole)
    first = resolved[0]
    if field == "commit_pair":
        resolved[1] = replace(
            resolved[1],
            upstream_url=first.upstream_url,
            exact_commit_sha=first.exact_commit_sha,
        )
    else:
        resolved[1] = replace(resolved[1], **{field: getattr(first, field)})

    with pytest.raises(GitleaksRealworldContractError):
        GitleaksRealworldRepositorySelection(
            state=GitleaksRealworldAcquisitionState.ACQUIRED,
            slots=tuple(resolved),
        )


@pytest.mark.parametrize(
    "upstream_url",
    (
        "http://example.invalid/repository",
        "https:///repository",
        "https://user@example.invalid/repository",
        "https://user:password@example.invalid/repository",
        "https://example.invalid/repository?ref=main",
        "https://example.invalid/repository#fragment",
    ),
)
def test_resolved_repository_rejects_untrusted_url_forms(upstream_url: str) -> None:
    slot = _resolved_slot(GitleaksRealworldRepositoryRole.RW01_SMALL_APPLICATION)

    with pytest.raises(GitleaksRealworldContractError):
        replace(slot, upstream_url=upstream_url)


def test_resolved_repository_accepts_provider_neutral_https_url() -> None:
    slot = _resolved_slot(GitleaksRealworldRepositoryRole.RW01_SMALL_APPLICATION)

    assert slot.upstream_url == "https://example.invalid/rw01_small_application.git"


def test_repository_selection_rejects_duplicate_missing_and_reordered_roles() -> None:
    selection = pre_acquisition_repository_selection()
    invalid_slots = (
        (*selection.slots[:-1], selection.slots[0]),
        selection.slots[:-1],
        (selection.slots[1], selection.slots[0], *selection.slots[2:]),
    )

    for slots in invalid_slots:
        with pytest.raises(GitleaksRealworldContractError):
            GitleaksRealworldRepositorySelection(
                state=GitleaksRealworldAcquisitionState.PRE_ACQUISITION,
                slots=slots,
            )


def test_partial_or_malformed_repository_identity_is_rejected() -> None:
    role = GitleaksRealworldRepositoryRole.RW01_SMALL_APPLICATION
    with pytest.raises(GitleaksRealworldContractError):
        GitleaksRealworldRepositorySlot(slot_id="RW01", role=role, repository_id="partial")
    with pytest.raises(GitleaksRealworldContractError):
        GitleaksRealworldRepositorySlot(slot_id="wrong", role=role)
    with pytest.raises(GitleaksRealworldContractError):
        GitleaksRealworldRepositorySlot(slot_id="RW01", role="RW01_SMALL_APPLICATION")  # type: ignore[arg-type]


def test_operational_metrics_exclude_accuracy_metrics_and_ground_truth_is_required() -> None:
    evaluation = verify_gitleaks_realworld_contract(ROOT.resolve())["evaluation"]
    metric_names = {name.casefold() for name in evaluation["operational_metrics"]}

    assert metric_names.isdisjoint(_ACCURACY_METRICS)
    assert evaluation["accuracy_scoring"] == {
        "authorization_requirement": "SEPARATELY_FROZEN_COMPLETE_GROUND_TRUTH",
        "authorized": False,
    }
    assert evaluation["repeatability"] == {
        "comparison": "CANONICAL_STRUCTURAL_FINDING_SET_EQUALITY",
        "fixed_inputs": [
            "repository_snapshot_digest",
            "binding_digest",
            "config_sha256",
            "ignore_sha256",
        ],
    }


def test_snapshot_identity_is_the_existing_repository_manifest_identity() -> None:
    acquisition = verify_gitleaks_realworld_contract(ROOT.resolve())["acquisition"]

    assert acquisition["snapshot_identity"] == {
        "authority": "SECURESCAN_REPOSITORY_MANIFEST",
        "byte_count_field": "total_bytes",
        "digest_field": "content_digest",
        "file_count_field": "file_count",
        "scan_identity_source": "VERIFIED_LOCAL_SOURCE_SNAPSHOT",
    }
    assert acquisition["repository_workspace_ingress"] == (
        "EXISTING_REPOSITORY_WORKSPACE_MANAGER"
    )


def test_untrusted_archive_acquisition_requirements_are_frozen() -> None:
    acquisition = verify_gitleaks_realworld_contract(ROOT.resolve())["acquisition"]

    assert acquisition["archive_acceptance"] == {
        "complete_archive_sha256_verified_before_acceptance": True,
        "download_phase": "EXPLICIT_ACQUISITION_CHECKPOINT_ONLY",
    }
    assert acquisition["operations"] == {
        "build": False,
        "hooks": False,
        "install": False,
        "repository_code_execution": False,
    }
    assert acquisition["archive_extraction"] == {
        "absolute_member_paths": "REJECT",
        "device_fifo_socket_and_special_entries": "REJECT",
        "dotdot_traversal": "REJECT",
        "duplicate_normalized_output_paths": "REJECT",
        "limits": {
            "authority": "F5B_FROZEN_ACQUISITION_POLICY",
            "member_count": "BOUNDED",
            "per_file_size": "BOUNDED",
            "relative_path_length": "BOUNDED",
            "total_expanded_bytes": "BOUNDED",
        },
        "normalized_path_escape": "REJECT",
        "provider_top_level_directory": (
            "NORMALIZE_OR_STRIP_ONLY_AFTER_CONTAINMENT_VALIDATION"
        ),
        "symlink_or_hardlink_escape": "REJECT",
    }
    assert acquisition["output"] == "LOCAL_ORDINARY_SOURCE_TREE"
    assert acquisition["scan_snapshot_excludes_git_history"] is True
    assert acquisition["scan_uses_local_acquired_snapshot_only"] is True


def test_role_eligibility_and_prescan_evidence_requirements_are_frozen() -> None:
    selection = verify_gitleaks_realworld_contract(ROOT.resolve())["repository_selection"]
    eligibility = selection["role_eligibility"]

    assert [row["role"] for row in eligibility] == [
        role.value for role in GitleaksRealworldRepositoryRole
    ]
    assert all(row["requirements"] for row in eligibility)
    assert selection["one_primary_slot_per_repository"] is True
    assert selection["pre_scan_role_selection"] == {
        "evidence_and_rationale_required": True,
        "required_before_gitleaks_execution": True,
    }


def test_confidentiality_and_review_boundaries_are_exact() -> None:
    document = verify_gitleaks_realworld_contract(ROOT.resolve())
    confidentiality = document["confidentiality"]
    review = document["review"]

    assert confidentiality["forbidden_report_fields"] == [
        "Secret",
        "Match",
        "raw Fingerprint",
        "credential hash",
        "raw stdout",
        "raw stderr",
        "host path",
        "temporary path",
        "repository checkout path",
        "provider validation response",
    ]
    assert confidentiality["public_finding_identity"] == "STRUCTURAL_V0_4E_FINDING_ID"
    assert confidentiality["sanitized_parser_output_only"] is True
    assert review["classifications"] == [
        item.value for item in GitleaksRealworldReviewClassification
    ]
    assert review["provider_validation"] is False
    assert review["credential_usability_claim"] is False
    assert review["raw_credential_persistence"] is False


def test_scan_constraints_forbid_history_provider_validation_and_network() -> None:
    constraints = verify_gitleaks_realworld_contract(ROOT.resolve())["scan_constraints"]

    assert constraints == {
        "current_snapshot_only": True,
        "git_history": False,
        "provider_validation": False,
        "scanner_network_access": False,
        "scanner_output": "SENSITIVE_IN_MEMORY_ONLY",
        "source_execution": "PRODUCTION_SOURCE_EXECUTION_BRIDGE_ONLY",
    }


def test_failure_states_can_never_be_successful_or_clean() -> None:
    failure = verify_gitleaks_realworld_contract(ROOT.resolve())["failure_semantics"]

    assert failure == {
        "outcome": "NEVER_SUCCESSFUL_OR_CLEAN",
        "states": [
            "FAILED",
            "TIMED_OUT",
            "CANCELLED",
            "OUTPUT_LIMIT_EXCEEDED",
            "INVALID_EXIT",
            "MALFORMED_JSON",
            "PARSER_REJECTION",
            "CONFIDENTIALITY_VIOLATION",
        ],
    }


def test_frozen_scanner_f3b_f4c_and_maturity_identities_are_exact() -> None:
    document = verify_gitleaks_realworld_contract(ROOT.resolve())

    assert document["scanner"] == {
        "binding_artifact_sha256": GITLEAKS_BINDING_ARTIFACT_SHA256,
        "binding_digest": GITLEAKS_BINDING_DIGEST,
        "config_sha256": GITLEAKS_CONFIG_SHA256,
        "id": GITLEAKS_SCANNER_ID,
        "ignore_sha256": GITLEAKS_IGNORE_SHA256,
        "version": GITLEAKS_SCANNER_VERSION,
    }
    assert document["evidence"] == {
        "f3b": {
            "commit": GITLEAKS_F3B_COMMIT,
            "report_sha256": GITLEAKS_F3B_REPORT_SHA256,
            "role": "CONTROLLED_ACCURACY_EVIDENCE",
            "tag": GITLEAKS_F3B_TAG,
        },
        "f4c": {
            "characterization_sha256": GITLEAKS_F4C_CHARACTERIZATION_SHA256,
            "commit": GITLEAKS_F4C_COMMIT,
            "role": "LIMITATION_AND_CLAIM_EVIDENCE",
            "tag": GITLEAKS_F4C_TAG,
        },
    }
    assert document["maturity"] == GITLEAKS_MATURITY == "SCANNABLE"


@pytest.mark.parametrize("invalid", ("duplicate", "nonfinite", "noncanonical", "unexpected"))
def test_invalid_contract_json_is_rejected(tmp_path: Path, invalid: str) -> None:
    root = _copy_checkpoint(tmp_path)
    path = root / GITLEAKS_REALWORLD_CONTRACT_PATH
    payload = path.read_bytes()
    if invalid == "duplicate":
        path.write_bytes(b'{"schema_version":"duplicate",' + payload[1:])
    elif invalid == "nonfinite":
        path.write_bytes(payload[:-2] + b',"nonfinite":NaN}\n')
    elif invalid == "noncanonical":
        path.write_bytes(json.dumps(json.loads(payload), indent=2).encode() + b"\n")
    else:
        _rewrite_contract(root, lambda value: value.update(unexpected=True))
    _rejects(root)


@pytest.mark.parametrize("relative", _FROZEN_PATHS)
def test_symlinked_frozen_input_is_rejected(tmp_path: Path, relative: str) -> None:
    root = _copy_checkpoint(tmp_path)
    path = root / relative
    target = tmp_path / f"{Path(relative).name}.target"
    shutil.copy2(path, target)
    path.unlink()
    path.symlink_to(target)
    _rejects(root)


@pytest.mark.parametrize(
    "relative",
    (
        GITLEAKS_F3B_REPORT_PATH,
        GITLEAKS_F4C_CHARACTERIZATION_PATH,
        GITLEAKS_BINDING_ARTIFACT_PATH,
        GITLEAKS_CONFIG_PATH,
        GITLEAKS_IGNORE_PATH,
    ),
)
def test_modified_frozen_input_is_rejected(tmp_path: Path, relative: str) -> None:
    root = _copy_checkpoint(tmp_path)
    (root / relative).write_bytes(b"modified frozen input\n")
    _rejects(root)


@pytest.mark.parametrize("entry_kind", ("file", "directory", "valid-symlink", "broken-symlink"))
def test_any_preexisting_realworld_result_entry_is_rejected(
    tmp_path: Path,
    entry_kind: str,
) -> None:
    root = _copy_checkpoint(tmp_path)
    result = root / GITLEAKS_REALWORLD_RESULT_PATH
    result.parent.mkdir(parents=True, exist_ok=True)
    if entry_kind == "file":
        result.write_bytes(b"result must not exist\n")
    elif entry_kind == "directory":
        result.mkdir()
    elif entry_kind == "valid-symlink":
        target = tmp_path / "result-target"
        target.write_bytes(b"target\n")
        result.symlink_to(target)
    else:
        result.symlink_to(tmp_path / "missing-result-target")
    _rejects(root)


def test_contract_module_has_no_scanner_or_network_execution_path() -> None:
    source = (ROOT / "src/securescan/benchmarks/gitleaks_realworld_contract.py").read_text()

    assert "subprocess" not in source
    assert "urllib.request" not in source
    assert "http.client" not in source
    assert "import socket" not in source
    assert "import requests" not in source
    assert "gitleaks dir" not in source
    assert not os.path.lexists(ROOT / GITLEAKS_REALWORLD_RESULT_PATH)
