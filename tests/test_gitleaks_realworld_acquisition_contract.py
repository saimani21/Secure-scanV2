from __future__ import annotations

import hashlib
import json
import os
import shutil
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import pytest

from securescan.benchmarks.gitleaks_realworld_acquisition_contract import (
    GITLEAKS_ARCHIVE_FORMATS,
    GITLEAKS_ARCHIVE_MAX_DOWNLOADED_BYTES,
    GITLEAKS_F5A_COMMIT,
    GITLEAKS_F5A_TAG,
    GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_ID,
    GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_PATH,
    GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_SCHEMA_PATH,
    GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_SCHEMA_SHA256,
    GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_SCHEMA_VERSION,
    GITLEAKS_REALWORLD_ACQUISITION_POLICY_ID,
    GITLEAKS_REALWORLD_ACQUISITION_POLICY_PATH,
    GITLEAKS_REALWORLD_ACQUISITION_POLICY_SCHEMA_VERSION,
    GITLEAKS_REALWORLD_ACQUISITION_POLICY_SHA256,
    GITLEAKS_ROLE_EVIDENCE_VOCABULARY,
    GitleaksRealworldAcquisitionContractError,
    GitleaksRealworldAcquisitionManifestEntry,
    GitleaksRealworldAcquisitionManifestModel,
    GitleaksRealworldAcquisitionManifestState,
    canonical_gitleaks_realworld_acquisition,
    gitleaks_realworld_acquisition_manifest_schema_document,
    gitleaks_realworld_acquisition_policy_document,
    load_gitleaks_realworld_acquisition_manifest_schema,
    load_gitleaks_realworld_acquisition_policy,
    verify_gitleaks_realworld_acquisition_contract,
)
from securescan.benchmarks.gitleaks_realworld_contract import (
    GITLEAKS_BINDING_ARTIFACT_PATH,
    GITLEAKS_BINDING_DIGEST,
    GITLEAKS_CONFIG_PATH,
    GITLEAKS_CONFIG_SHA256,
    GITLEAKS_IGNORE_PATH,
    GITLEAKS_IGNORE_SHA256,
    GITLEAKS_REALWORLD_CONTRACT_PATH,
    GITLEAKS_REALWORLD_CONTRACT_SHA256,
    GITLEAKS_REALWORLD_RESULT_PATH,
    GITLEAKS_SCANNER_ID,
    GITLEAKS_SCANNER_VERSION,
    GitleaksRealworldAcquisitionMethod,
    GitleaksRealworldRepositoryRole,
)
from securescan.workspaces.models import RepositoryIntakeLimits

ROOT = Path(__file__).resolve().parents[1]
_REQUIRED_PATHS = (
    GITLEAKS_REALWORLD_CONTRACT_PATH,
    GITLEAKS_REALWORLD_ACQUISITION_POLICY_PATH,
    GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_SCHEMA_PATH,
    GITLEAKS_BINDING_ARTIFACT_PATH,
    GITLEAKS_CONFIG_PATH,
    GITLEAKS_IGNORE_PATH,
)
_ENTRY_FIELDS = (
    "slot_id",
    "role",
    "repository_id",
    "upstream_url",
    "archive_url",
    "exact_commit_sha",
    "license_identifier",
    "acquisition_method",
    "archive_sha256",
    "archive_byte_count",
    "snapshot_digest",
    "file_count",
    "byte_count",
    "pre_scan_role_evidence",
    "pre_scan_role_rationale",
)
_UNRESOLVED_FIELDS = _ENTRY_FIELDS[2:]


def _copy_checkpoint(tmp_path: Path) -> Path:
    root = (tmp_path / "repository").resolve()
    for relative in _REQUIRED_PATHS:
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, destination)
    return root


def _rejects(root: Path) -> None:
    with pytest.raises(
        GitleaksRealworldAcquisitionContractError,
        match="^Gitleaks real-world acquisition contract is invalid$",
    ):
        verify_gitleaks_realworld_acquisition_contract(root)


def _rewrite_json(
    root: Path,
    relative: str,
    mutate: Callable[[dict[str, object]], None],
) -> None:
    path = root / relative
    document = json.loads(path.read_bytes())
    mutate(document)
    path.write_bytes(canonical_gitleaks_realworld_acquisition(document))


def _manifest_entry(
    role: GitleaksRealworldRepositoryRole,
    *,
    acquired: bool,
) -> GitleaksRealworldAcquisitionManifestEntry:
    position = tuple(GitleaksRealworldRepositoryRole).index(role) + 1
    selection = {
        "repository_id": f"repository-{position}",
        "upstream_url": f"https://source.example.invalid/repository-{position}",
        "archive_url": f"https://archive.example.invalid/repository-{position}.tar.gz",
        "exact_commit_sha": f"{position:x}" * 40,
        "license_identifier": "Apache-2.0",
        "acquisition_method": GitleaksRealworldAcquisitionMethod.UPSTREAM_ARCHIVE,
        "pre_scan_role_evidence": (GITLEAKS_ROLE_EVIDENCE_VOCABULARY[position - 1],),
        "pre_scan_role_rationale": f"role rationale {position}",
    }
    acquisition = (
        {
            "archive_sha256": f"{position + 6:x}" * 64,
            "archive_byte_count": position * 100,
            "snapshot_digest": f"{position:x}" * 64,
            "file_count": position,
            "byte_count": position * 10,
        }
        if acquired
        else {}
    )
    return GitleaksRealworldAcquisitionManifestEntry(
        slot_id=role.value.split("_", 1)[0],
        role=role,
        **selection,
        **acquisition,
    )


def _manifest_model(
    state: GitleaksRealworldAcquisitionManifestState,
) -> GitleaksRealworldAcquisitionManifestModel:
    if state is GitleaksRealworldAcquisitionManifestState.PRE_SELECTION:
        entries = tuple(
            GitleaksRealworldAcquisitionManifestEntry(
                slot_id=role.value.split("_", 1)[0],
                role=role,
            )
            for role in GitleaksRealworldRepositoryRole
        )
    else:
        entries = tuple(
            _manifest_entry(
                role,
                acquired=state is GitleaksRealworldAcquisitionManifestState.ACQUIRED,
            )
            for role in GitleaksRealworldRepositoryRole
        )
    return GitleaksRealworldAcquisitionManifestModel(state=state, entries=entries)


def test_frozen_policy_and_manifest_schema_are_canonical_and_verified(
    tmp_path: Path,
) -> None:
    policy_bytes = (ROOT / GITLEAKS_REALWORLD_ACQUISITION_POLICY_PATH).read_bytes()
    schema_bytes = (
        ROOT / GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_SCHEMA_PATH
    ).read_bytes()
    policy, schema = verify_gitleaks_realworld_acquisition_contract(
        _copy_checkpoint(tmp_path)
    )

    assert policy == gitleaks_realworld_acquisition_policy_document()
    assert schema == gitleaks_realworld_acquisition_manifest_schema_document()
    assert canonical_gitleaks_realworld_acquisition(policy) == policy_bytes
    assert canonical_gitleaks_realworld_acquisition(schema) == schema_bytes
    assert hashlib.sha256(policy_bytes).hexdigest() == (
        GITLEAKS_REALWORLD_ACQUISITION_POLICY_SHA256
    )
    assert hashlib.sha256(schema_bytes).hexdigest() == (
        GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_SCHEMA_SHA256
    )
    assert load_gitleaks_realworld_acquisition_policy(
        ROOT / GITLEAKS_REALWORLD_ACQUISITION_POLICY_PATH
    ) == policy
    assert load_gitleaks_realworld_acquisition_manifest_schema(
        ROOT / GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_SCHEMA_PATH
    ) == schema


def test_policy_identity_and_f5a_binding_are_exact() -> None:
    policy = gitleaks_realworld_acquisition_policy_document()

    assert policy["schema_version"] == (
        GITLEAKS_REALWORLD_ACQUISITION_POLICY_SCHEMA_VERSION
    )
    assert policy["policy_id"] == GITLEAKS_REALWORLD_ACQUISITION_POLICY_ID
    assert policy["f5a"] == {
        "commit": GITLEAKS_F5A_COMMIT,
        "contract_sha256": GITLEAKS_REALWORLD_CONTRACT_SHA256,
        "tag": GITLEAKS_F5A_TAG,
    }
    assert GITLEAKS_F5A_COMMIT == "21298b3da86067dcf36665441e1a4ee5f94f4dc3"
    assert GITLEAKS_F5A_TAG == "source-v0.4F5A-gitleaks-realworld-contract"
    assert GITLEAKS_REALWORLD_CONTRACT_SHA256 == (
        "8a6269cc9d655ff3bc733a69dfbafaec9eab13a01df53a6aebe26f8cf0812982"
    )


def test_production_repository_workspace_limits_are_reused_exactly() -> None:
    policy = gitleaks_realworld_acquisition_policy_document()
    actual = policy["repository_workspace_limits"]
    limits = RepositoryIntakeLimits()

    assert actual == {
        "authority": "securescan.workspaces.models.RepositoryIntakeLimits",
        "max_directory_depth": limits.max_directory_depth,
        "max_file_count": limits.max_file_count,
        "max_relative_path_bytes": limits.max_relative_path_bytes,
        "max_single_file_bytes": limits.max_single_file_bytes,
        "max_total_bytes": limits.max_total_bytes,
        "policy": "UNCHANGED_PRODUCTION_DEFAULTS",
    }
    assert actual == {
        "authority": "securescan.workspaces.models.RepositoryIntakeLimits",
        "max_directory_depth": 64,
        "max_file_count": 50_000,
        "max_relative_path_bytes": 4_096,
        "max_single_file_bytes": 33_554_432,
        "max_total_bytes": 1_073_741_824,
        "policy": "UNCHANGED_PRODUCTION_DEFAULTS",
    }


def test_archive_bounds_are_positive_and_internally_consistent() -> None:
    limits = gitleaks_realworld_acquisition_policy_document()["archive_limits"]

    assert limits == {
        "max_downloaded_archive_bytes": GITLEAKS_ARCHIVE_MAX_DOWNLOADED_BYTES,
        "max_expanded_member_bytes": 33_554_432,
        "max_member_count": 50_000,
        "max_normalized_relative_path_bytes": 4_096,
        "max_path_depth": 64,
        "max_total_expanded_bytes": 1_073_741_824,
        "policy": "ARCHIVE_SPECIFIC_BOUNDS_ALIGNED_TO_WORKSPACE_INTAKE",
    }
    assert all(
        type(value) is int and value > 0
        for key, value in limits.items()
        if key.startswith("max_")
    )
    assert limits["max_expanded_member_bytes"] <= limits["max_total_expanded_bytes"]
    assert limits["max_downloaded_archive_bytes"] <= limits["max_total_expanded_bytes"]


def test_transport_and_checksum_policy_are_exact() -> None:
    transport = gitleaks_realworld_acquisition_policy_document()["archive_transport"]

    assert transport == {
        "allowed_formats": list(GITLEAKS_ARCHIVE_FORMATS),
        "archive_sha256_verified_before_extraction_acceptance": True,
        "checksum_algorithm": "SHA-256",
        "network_phase": "EXPLICIT_ACQUISITION_CHECKPOINT_ONLY",
    }
    assert GITLEAKS_ARCHIVE_FORMATS == ("tar.gz",)


def test_extraction_requires_member_validation_without_blind_extractall() -> None:
    extraction = gitleaks_realworld_acquisition_policy_document()["archive_extraction"]

    assert extraction["member_processing"] == "VALIDATE_THEN_WRITE_INDIVIDUALLY"
    assert extraction["standard_library_extractall"] == "FORBIDDEN"
    assert extraction["temporary_extraction_location"] == "OUTSIDE_REPOSITORY"
    assert extraction["containment_after_normalization"] == "REQUIRED"
    assert extraction["top_level_provider_directory"] == {
        "containment_validation_before_stripping": True,
        "mode": "STRIP_EXACTLY_ONE_COMMON_TOP_LEVEL_DIRECTORY",
        "post_strip_empty_path": "REJECT",
        "required": True,
    }


def test_materialized_archive_member_types_are_exact() -> None:
    extraction = gitleaks_realworld_acquisition_policy_document()["archive_extraction"]

    assert extraction["allowed_materialized_member_types"] == [
        "REGULAR_FILE",
        "DIRECTORY",
    ]


def test_unsafe_archive_entries_traversal_links_and_collisions_are_rejected() -> None:
    extraction = gitleaks_realworld_acquisition_policy_document()["archive_extraction"]

    assert extraction["absolute_member_paths"] == "REJECT"
    assert extraction["dotdot_traversal"] == "REJECT"
    assert extraction["normalized_path_escape"] == "REJECT"
    assert extraction["symlinks_and_hardlinks"] == "REJECT"
    assert extraction["device_fifo_socket_and_special_entries"] == "REJECT"
    assert extraction["duplicate_output_paths"] == "REJECT"
    assert extraction["normalized_path_collisions"] == "REJECT"


def test_repository_code_git_build_install_hooks_and_recursion_are_forbidden() -> None:
    prohibited = gitleaks_realworld_acquisition_policy_document()[
        "prohibited_operations"
    ]

    assert prohibited == {
        "archive_symlink_or_hardlink_materialization": True,
        "build": True,
        "git_checkout": True,
        "git_submodules": True,
        "hooks": True,
        "package_install": True,
        "recursive_remote_acquisition": True,
        "repository_code_execution": True,
    }


def test_snapshot_identity_preserves_repository_manifest_authority() -> None:
    snapshot = gitleaks_realworld_acquisition_policy_document()["snapshot_identity"]

    assert snapshot == {
        "authority": "RepositoryWorkspaceManager/RepositoryManifest",
        "byte_count_field": "total_bytes",
        "digest_field": "content_digest",
        "file_count_field": "file_count",
    }


def test_manifest_schema_identity_and_bindings_are_exact() -> None:
    schema = gitleaks_realworld_acquisition_manifest_schema_document()

    assert schema["schema_version"] == (
        GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_SCHEMA_VERSION
    )
    assert schema["acquisition_manifest_id"] == (
        GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_ID
    )
    assert schema["acquisition_state"] == "PRE_SELECTION"
    assert schema["allowed_acquisition_states"] == [
        "PRE_SELECTION",
        "SELECTED",
        "ACQUIRED",
    ]
    assert schema["bindings"] == {
        "acquisition_policy_sha256": GITLEAKS_REALWORLD_ACQUISITION_POLICY_SHA256,
        "config_sha256": GITLEAKS_CONFIG_SHA256,
        "f5a_contract_sha256": GITLEAKS_REALWORLD_CONTRACT_SHA256,
        "ignore_sha256": GITLEAKS_IGNORE_SHA256,
        "scanner_binding_digest": GITLEAKS_BINDING_DIGEST,
        "scanner_id": GITLEAKS_SCANNER_ID,
        "scanner_version": GITLEAKS_SCANNER_VERSION,
    }


def test_manifest_entry_fields_are_exact_and_contain_no_result_fields() -> None:
    schema = gitleaks_realworld_acquisition_manifest_schema_document()
    forbidden_result_fields = {
        "findings",
        "results",
        "execution_status",
        "return_code",
        "precision",
        "recall",
        "f1",
        "tp",
        "tn",
        "fp",
        "fn",
    }

    assert tuple(schema["repository_entry_fields"]) == _ENTRY_FIELDS
    assert set(schema["repository_entry_fields"]).isdisjoint(forbidden_result_fields)
    assert schema["contains_result_or_finding_data"] is False
    assert all(
        set(slot) == set(_ENTRY_FIELDS) and set(slot).isdisjoint(forbidden_result_fields)
        for slot in schema["repository_slots"]
    )


def test_manifest_state_requirements_are_exact() -> None:
    requirements = gitleaks_realworld_acquisition_manifest_schema_document()[
        "state_requirements"
    ]
    selection_fields = [
        "repository_id",
        "upstream_url",
        "archive_url",
        "exact_commit_sha",
        "license_identifier",
        "acquisition_method",
        "pre_scan_role_evidence",
        "pre_scan_role_rationale",
    ]
    acquisition_fields = [
        "archive_sha256",
        "archive_byte_count",
        "snapshot_digest",
        "file_count",
        "byte_count",
    ]

    assert requirements == {
        "ACQUIRED": {
            "required_resolved": list(_ENTRY_FIELDS[2:]),
            "unique": [
                "repository_id",
                "upstream_url",
                "archive_url",
                "snapshot_digest",
                "(upstream_url,exact_commit_sha)",
            ],
        },
        "PRE_SELECTION": {"required_null": list(_ENTRY_FIELDS[2:])},
        "SELECTED": {
            "required_null": acquisition_fields,
            "required_resolved": selection_fields,
            "unique": [
                "repository_id",
                "upstream_url",
                "archive_url",
                "(upstream_url,exact_commit_sha)",
            ],
        },
    }


def test_all_three_in_memory_manifest_states_accept_valid_entries() -> None:
    assert [state.value for state in GitleaksRealworldAcquisitionManifestState] == [
        "PRE_SELECTION",
        "SELECTED",
        "ACQUIRED",
    ]
    for state in GitleaksRealworldAcquisitionManifestState:
        assert _manifest_model(state).state is state


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("repository_id", "repository"),
        ("upstream_url", "https://source.example.invalid/repository"),
        ("archive_url", "https://archive.example.invalid/repository.tar.gz"),
        ("exact_commit_sha", "1" * 40),
        ("license_identifier", "Apache-2.0"),
        ("acquisition_method", GitleaksRealworldAcquisitionMethod.UPSTREAM_ARCHIVE),
        ("archive_sha256", "2" * 64),
        ("archive_byte_count", 1),
        ("snapshot_digest", "3" * 64),
        ("file_count", 1),
        ("byte_count", 0),
        ("pre_scan_role_evidence", ("application_entrypoint",)),
        ("pre_scan_role_rationale", "rationale"),
    ),
)
def test_preselection_rejects_every_populated_repository_field(
    field: str,
    value: object,
) -> None:
    model = _manifest_model(GitleaksRealworldAcquisitionManifestState.PRE_SELECTION)
    entries = list(model.entries)
    entries[0] = replace(entries[0], **{field: value})

    with pytest.raises(GitleaksRealworldAcquisitionContractError):
        GitleaksRealworldAcquisitionManifestModel(
            state=GitleaksRealworldAcquisitionManifestState.PRE_SELECTION,
            entries=tuple(entries),
        )


@pytest.mark.parametrize(
    "field",
    (
        "repository_id",
        "upstream_url",
        "archive_url",
        "exact_commit_sha",
        "license_identifier",
        "acquisition_method",
        "pre_scan_role_evidence",
        "pre_scan_role_rationale",
    ),
)
def test_selected_requires_every_selection_field(field: str) -> None:
    model = _manifest_model(GitleaksRealworldAcquisitionManifestState.SELECTED)
    entries = list(model.entries)
    entries[0] = replace(entries[0], **{field: None})

    with pytest.raises(GitleaksRealworldAcquisitionContractError):
        GitleaksRealworldAcquisitionManifestModel(
            state=GitleaksRealworldAcquisitionManifestState.SELECTED,
            entries=tuple(entries),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("archive_sha256", "2" * 64),
        ("archive_byte_count", 1),
        ("snapshot_digest", "3" * 64),
        ("file_count", 1),
        ("byte_count", 0),
    ),
)
def test_selected_rejects_every_acquisition_or_snapshot_field(
    field: str,
    value: object,
) -> None:
    model = _manifest_model(GitleaksRealworldAcquisitionManifestState.SELECTED)
    entries = list(model.entries)
    entries[0] = replace(entries[0], **{field: value})

    with pytest.raises(GitleaksRealworldAcquisitionContractError):
        GitleaksRealworldAcquisitionManifestModel(
            state=GitleaksRealworldAcquisitionManifestState.SELECTED,
            entries=tuple(entries),
        )


@pytest.mark.parametrize("field", _ENTRY_FIELDS[2:])
def test_acquired_requires_every_repository_field(field: str) -> None:
    model = _manifest_model(GitleaksRealworldAcquisitionManifestState.ACQUIRED)
    entries = list(model.entries)
    entries[0] = replace(entries[0], **{field: None})

    with pytest.raises(GitleaksRealworldAcquisitionContractError):
        GitleaksRealworldAcquisitionManifestModel(
            state=GitleaksRealworldAcquisitionManifestState.ACQUIRED,
            entries=tuple(entries),
        )


@pytest.mark.parametrize("field", ("repository_id", "upstream_url", "commit_pair"))
def test_selected_rejects_duplicate_repository_identity(field: str) -> None:
    model = _manifest_model(GitleaksRealworldAcquisitionManifestState.SELECTED)
    entries = list(model.entries)
    first = entries[0]
    if field == "commit_pair":
        entries[1] = replace(
            entries[1],
            upstream_url=first.upstream_url,
            exact_commit_sha=first.exact_commit_sha,
        )
    else:
        entries[1] = replace(entries[1], **{field: getattr(first, field)})

    with pytest.raises(GitleaksRealworldAcquisitionContractError):
        GitleaksRealworldAcquisitionManifestModel(
            state=GitleaksRealworldAcquisitionManifestState.SELECTED,
            entries=tuple(entries),
        )


def test_selected_rejects_duplicate_archive_url() -> None:
    model = _manifest_model(GitleaksRealworldAcquisitionManifestState.SELECTED)
    entries = list(model.entries)
    entries[1] = replace(entries[1], archive_url=entries[0].archive_url)

    with pytest.raises(GitleaksRealworldAcquisitionContractError):
        GitleaksRealworldAcquisitionManifestModel(
            state=GitleaksRealworldAcquisitionManifestState.SELECTED,
            entries=tuple(entries),
        )


def test_acquired_rejects_duplicate_snapshot_digest() -> None:
    model = _manifest_model(GitleaksRealworldAcquisitionManifestState.ACQUIRED)
    entries = list(model.entries)
    entries[1] = replace(entries[1], snapshot_digest=entries[0].snapshot_digest)

    with pytest.raises(GitleaksRealworldAcquisitionContractError):
        GitleaksRealworldAcquisitionManifestModel(
            state=GitleaksRealworldAcquisitionManifestState.ACQUIRED,
            entries=tuple(entries),
        )


@pytest.mark.parametrize(
    "archive_url",
    (
        "http://archive.example.invalid/repository.tar.gz",
        "https:///repository.tar.gz",
        "https://user@archive.example.invalid/repository.tar.gz",
        "https://user:password@archive.example.invalid/repository.tar.gz",
        "https://archive.example.invalid/repository.tar.gz?ref=commit",
        "https://archive.example.invalid/repository.tar.gz#fragment",
    ),
)
def test_archive_url_rejects_untrusted_url_forms(archive_url: str) -> None:
    entry = _manifest_entry(
        GitleaksRealworldRepositoryRole.RW01_SMALL_APPLICATION,
        acquired=False,
    )

    with pytest.raises(GitleaksRealworldAcquisitionContractError):
        replace(entry, archive_url=archive_url)


def test_archive_url_is_absent_before_selection_and_required_afterward() -> None:
    preselection = _manifest_model(
        GitleaksRealworldAcquisitionManifestState.PRE_SELECTION
    )
    selected = _manifest_model(GitleaksRealworldAcquisitionManifestState.SELECTED)
    acquired = _manifest_model(GitleaksRealworldAcquisitionManifestState.ACQUIRED)

    assert all(entry.archive_url is None for entry in preselection.entries)
    assert all(entry.archive_url is not None for entry in selected.entries)
    assert all(entry.archive_url is not None for entry in acquired.entries)


def test_archive_url_is_bound_to_commit_without_provider_specific_layout() -> None:
    schema = gitleaks_realworld_acquisition_manifest_schema_document()

    assert schema["future_acquired_entry_requirements"][
        "archive_url_exact_commit_association"
    ] == "REQUIRED_WITHOUT_PROVIDER_SPECIFIC_URL_LAYOUT"


def test_manifest_confidentiality_fields_are_forbidden() -> None:
    schema = gitleaks_realworld_acquisition_manifest_schema_document()
    confidentiality = schema["confidentiality"]
    entry_keys = set().union(*(set(slot) for slot in schema["repository_slots"]))

    assert confidentiality == {
        "forbidden_fields": [
            "Secret",
            "Match",
            "Fingerprint",
            "credential_hash",
            "raw_secret_content",
            "scanner_output",
            "host_checkout_path",
            "temporary_extraction_path",
        ],
        "raw_secret_material_allowed": False,
    }
    assert entry_keys.isdisjoint(confidentiality["forbidden_fields"])


def test_role_evidence_vocabulary_is_exact() -> None:
    schema = gitleaks_realworld_acquisition_manifest_schema_document()

    assert tuple(schema["role_evidence_vocabulary"]) == (
        "application_entrypoint",
        "package_manifest",
        "documentation_directory",
        "examples_directory",
        "tests_directory",
        "vendor_directory",
        "generated_directory",
        "multiple_language_families",
        "binary_asset",
        "configuration_asset",
    )
    assert tuple(schema["role_evidence_vocabulary"]) == (
        GITLEAKS_ROLE_EVIDENCE_VOCABULARY
    )


def test_unresolved_manifest_has_exact_six_roles_and_no_repository_identity() -> None:
    schema = gitleaks_realworld_acquisition_manifest_schema_document()
    slots = schema["repository_slots"]

    assert schema["repository_count"] == len(slots) == 6
    assert [slot["slot_id"] for slot in slots] == [
        role.value.split("_", 1)[0] for role in GitleaksRealworldRepositoryRole
    ]
    assert [slot["role"] for slot in slots] == [
        role.value for role in GitleaksRealworldRepositoryRole
    ]
    assert all(slot[field] is None for slot in slots for field in _UNRESOLVED_FIELDS)
    serialized_slots = canonical_gitleaks_realworld_acquisition(slots)
    assert b"https://" not in serialized_slots
    assert b'"exact_commit_sha":"' not in serialized_slots


def test_future_distinctness_and_primary_slot_requirements_are_exact() -> None:
    requirements = gitleaks_realworld_acquisition_manifest_schema_document()[
        "future_acquired_entry_requirements"
    ]

    assert requirements == {
        "all_entry_fields_required": True,
        "archive_url_exact_commit_association": (
            "REQUIRED_WITHOUT_PROVIDER_SPECIFIC_URL_LAYOUT"
        ),
        "distinct_by": [
            "repository_id",
            "upstream_url",
            "archive_url",
            "snapshot_digest",
            "(upstream_url,exact_commit_sha)",
        ],
        "one_repository_per_primary_slot": True,
    }


def test_preselection_artifacts_remain_scannable_and_results_absent(
    tmp_path: Path,
) -> None:
    root = _copy_checkpoint(tmp_path)
    policy, schema = verify_gitleaks_realworld_acquisition_contract(root)

    assert policy["maturity"] == schema["maturity"] == "SCANNABLE"
    assert not os.path.lexists(root / GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_PATH)
    assert not os.path.lexists(root / GITLEAKS_REALWORLD_RESULT_PATH)


@pytest.mark.parametrize(
    "relative",
    (
        GITLEAKS_REALWORLD_ACQUISITION_POLICY_PATH,
        GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_SCHEMA_PATH,
    ),
)
@pytest.mark.parametrize("invalid", ("duplicate", "nonfinite", "noncanonical", "unexpected"))
def test_invalid_canonical_artifacts_are_rejected(
    tmp_path: Path,
    relative: str,
    invalid: str,
) -> None:
    root = _copy_checkpoint(tmp_path)
    path = root / relative
    payload = path.read_bytes()
    if invalid == "duplicate":
        path.write_bytes(b'{"schema_version":"duplicate",' + payload[1:])
    elif invalid == "nonfinite":
        path.write_bytes(payload[:-2] + b',"nonfinite":NaN}\n')
    elif invalid == "noncanonical":
        path.write_bytes(json.dumps(json.loads(payload), indent=2).encode() + b"\n")
    else:
        _rewrite_json(root, relative, lambda value: value.update(unexpected=True))
    _rejects(root)


def test_modified_f5a_contract_is_rejected(tmp_path: Path) -> None:
    root = _copy_checkpoint(tmp_path)
    (root / GITLEAKS_REALWORLD_CONTRACT_PATH).write_bytes(b"modified F5A\n")
    _rejects(root)


@pytest.mark.parametrize("relative", _REQUIRED_PATHS)
def test_symlinked_required_artifact_is_rejected(tmp_path: Path, relative: str) -> None:
    root = _copy_checkpoint(tmp_path)
    path = root / relative
    target = tmp_path / f"{Path(relative).name}.target"
    shutil.copy2(path, target)
    path.unlink()
    path.symlink_to(target)
    _rejects(root)


@pytest.mark.parametrize(
    "relative",
    (GITLEAKS_REALWORLD_ACQUISITION_MANIFEST_PATH, GITLEAKS_REALWORLD_RESULT_PATH),
)
@pytest.mark.parametrize("entry_kind", ("file", "directory", "valid-symlink", "broken-symlink"))
def test_future_phase_output_entry_does_not_change_f5b1_artifact_integrity(
    tmp_path: Path,
    relative: str,
    entry_kind: str,
) -> None:
    root = _copy_checkpoint(tmp_path)
    output = root / relative
    output.parent.mkdir(parents=True, exist_ok=True)
    if entry_kind == "file":
        output.write_bytes(b"forbidden output\n")
    elif entry_kind == "directory":
        output.mkdir()
    elif entry_kind == "valid-symlink":
        target = tmp_path / "output-target"
        target.write_bytes(b"target\n")
        output.symlink_to(target)
    else:
        output.symlink_to(tmp_path / "missing-output-target")
    policy, schema = verify_gitleaks_realworld_acquisition_contract(root)
    assert policy["maturity"] == schema["maturity"] == "SCANNABLE"


def test_module_exposes_no_downloader_extractor_scanner_or_network_surface() -> None:
    source = (
        ROOT
        / "src/securescan/benchmarks/gitleaks_realworld_acquisition_contract.py"
    ).read_text()

    assert "subprocess" not in source
    assert "urllib.request" not in source
    assert "import requests" not in source
    assert "import socket" not in source
    assert "tarfile" not in source
    assert "zipfile" not in source
    assert ".extractall(" not in source.casefold()
    assert "gitleaks dir" not in source
