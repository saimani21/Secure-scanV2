from __future__ import annotations

import builtins
import os
import re
import socket
import subprocess
from dataclasses import (
    FrozenInstanceError,
)
from pathlib import Path

import pytest

from securescan.scanners.gitleaks.binding import (
    GITLEAKS_SCANNER_ID,
    GITLEAKS_VERSION,
)
from securescan.scanners.gitleaks.identity import (
    GITLEAKS_IDENTITY_SCHEMA_VERSION,
    GITLEAKS_IDENTITY_SCOPE,
    GITLEAKS_V04D_BASELINE_COMMIT,
    GitleaksFindingIdentity,
    GitleaksIdentityError,
    build_gitleaks_finding_identities,
    build_gitleaks_finding_identity,
)
from securescan.scanners.gitleaks.parser import (
    GitleaksDetectionKind,
    NormalizedGitleaksFinding,
)

_PROJECTION_A = (
    "securescan-source-projection-"
    + "a" * 16
)
_PROJECTION_B = (
    "securescan-source-projection-"
    + "b" * 16
)

_CONTENT_GOLDEN_ID = (
    "803c1c75c2eaa2024436f9e1d0f8e539"
    "c13874a2105c9e88a2edd51c3b791e3f"
)
_PATH_GOLDEN_ID = (
    "c03a2a8aee58e9492fa309067fd71ee5"
    "082d259fc261143d246def9f8c964e60"
)


def _content_finding(
    **changes: object,
) -> NormalizedGitleaksFinding:
    arguments: dict[str, object] = {
        "scanner_id": GITLEAKS_SCANNER_ID,
        "scanner_version": GITLEAKS_VERSION,
        "rule_id": "github-pat",
        "file_path": "src/app.py",
        "detection_kind": (
            GitleaksDetectionKind.CONTENT
        ),
        "start_line": 12,
        "end_line": 12,
        "start_column": 3,
        "end_column": 9,
        "projection_id": _PROJECTION_A,
        "context_digest": "b" * 64,
        "projection_digest": "c" * 64,
    }
    arguments.update(changes)
    return NormalizedGitleaksFinding(
        **arguments  # type: ignore[arg-type]
    )


def _path_finding(
    **changes: object,
) -> NormalizedGitleaksFinding:
    arguments: dict[str, object] = {
        "scanner_id": GITLEAKS_SCANNER_ID,
        "scanner_version": GITLEAKS_VERSION,
        "rule_id": "pkcs12-file",
        "file_path": (
            "certificates/client.p12"
        ),
        "detection_kind": (
            GitleaksDetectionKind.PATH
        ),
        "start_line": None,
        "end_line": None,
        "start_column": None,
        "end_column": None,
        "projection_id": _PROJECTION_A,
        "context_digest": "b" * 64,
        "projection_digest": "c" * 64,
    }
    arguments.update(changes)
    return NormalizedGitleaksFinding(
        **arguments  # type: ignore[arg-type]
    )


def test_identity_schema_and_baseline_are_frozen() -> None:
    assert GITLEAKS_IDENTITY_SCHEMA_VERSION == (
        "securescan-gitleaks-finding-identity-v0.4E"
    )
    assert GITLEAKS_IDENTITY_SCOPE == (
        "structural_location"
    )
    assert GITLEAKS_V04D_BASELINE_COMMIT == (
        "9b482168e1236729cb47f9e989989aa5cee2d2fa"
    )


def test_content_identity_has_literal_golden_digest() -> None:
    identity = build_gitleaks_finding_identity(
        _content_finding()
    )

    assert (
        identity.finding_instance_id
        == _CONTENT_GOLDEN_ID
    )
    assert identity.identity_material() == {
        "detection_kind": "CONTENT",
        "file_path": "src/app.py",
        "identity_scope": (
            "structural_location"
        ),
        "location": {
            "end_column": 9,
            "end_line": 12,
            "start_column": 3,
            "start_line": 12,
        },
        "rule_id": "github-pat",
        "scanner_id": "gitleaks",
        "scanner_version": "8.30.1",
        "schema_version": (
            "securescan-gitleaks-finding-identity-v0.4E"
        ),
    }


def test_path_identity_has_literal_golden_digest() -> None:
    identity = build_gitleaks_finding_identity(
        _path_finding()
    )

    assert (
        identity.finding_instance_id
        == _PATH_GOLDEN_ID
    )
    assert identity.identity_material() == {
        "detection_kind": "PATH",
        "file_path": (
            "certificates/client.p12"
        ),
        "identity_scope": (
            "structural_location"
        ),
        "rule_id": "pkcs12-file",
        "scanner_id": "gitleaks",
        "scanner_version": "8.30.1",
        "schema_version": (
            "securescan-gitleaks-finding-identity-v0.4E"
        ),
    }


def test_path_identity_contains_no_fabricated_location() -> None:
    identity = build_gitleaks_finding_identity(
        _path_finding()
    )

    assert "location" not in (
        identity.identity_material()
    )
    assert identity.start_line is None
    assert identity.end_line is None
    assert identity.start_column is None
    assert identity.end_column is None


def test_identical_content_finding_has_stable_identity() -> None:
    first = build_gitleaks_finding_identity(
        _content_finding()
    )
    second = build_gitleaks_finding_identity(
        _content_finding()
    )

    assert first == second
    assert (
        first.finding_instance_id
        == second.finding_instance_id
    )


def test_run_specific_provenance_does_not_change_identity() -> None:
    first = build_gitleaks_finding_identity(
        _content_finding()
    )
    second = build_gitleaks_finding_identity(
        _content_finding(
            projection_id=_PROJECTION_B,
            context_digest="d" * 64,
            projection_digest="e" * 64,
        )
    )

    assert (
        first.finding_instance_id
        == second.finding_instance_id
    )
    assert first == second


def test_path_run_specific_provenance_does_not_change_identity() -> None:
    first = build_gitleaks_finding_identity(
        _path_finding()
    )
    second = build_gitleaks_finding_identity(
        _path_finding(
            projection_id=_PROJECTION_B,
            context_digest="d" * 64,
            projection_digest="e" * 64,
        )
    )

    assert (
        first.finding_instance_id
        == second.finding_instance_id
    )


@pytest.mark.parametrize(
    "change",
    (
        {"rule_id": "gitlab-pat"},
        {"file_path": "src/other.py"},
        {"start_line": 13, "end_line": 13},
        {"start_column": 4},
        {"end_column": 10},
    ),
)
def test_content_structural_change_changes_identity(
    change: dict[str, object],
) -> None:
    original = build_gitleaks_finding_identity(
        _content_finding()
    )
    changed = build_gitleaks_finding_identity(
        _content_finding(**change)
    )

    assert (
        original.finding_instance_id
        != changed.finding_instance_id
    )


@pytest.mark.parametrize(
    "change",
    (
        {"rule_id": "other-path-rule"},
        {"file_path": "certificates/other.p12"},
    ),
)
def test_path_structural_change_changes_identity(
    change: dict[str, object],
) -> None:
    original = build_gitleaks_finding_identity(
        _path_finding()
    )
    changed = build_gitleaks_finding_identity(
        _path_finding(**change)
    )

    assert (
        original.finding_instance_id
        != changed.finding_instance_id
    )


def test_content_and_path_domains_do_not_collide() -> None:
    content = _content_finding(
        rule_id="test-rule",
        file_path="same/file.txt",
    )
    path = _path_finding(
        rule_id="test-rule",
        file_path="same/file.txt",
    )

    content_identity = (
        build_gitleaks_finding_identity(
            content
        )
    )
    path_identity = (
        build_gitleaks_finding_identity(
            path
        )
    )

    assert (
        content_identity.finding_instance_id
        != path_identity.finding_instance_id
    )


def test_content_without_columns_is_deterministic() -> None:
    finding = _content_finding(
        start_column=None,
        end_column=None,
    )

    first = build_gitleaks_finding_identity(
        finding
    )
    second = build_gitleaks_finding_identity(
        finding
    )

    assert first == second
    assert first.identity_material()["location"] == {
        "end_column": None,
        "end_line": 12,
        "start_column": None,
        "start_line": 12,
    }


def test_identity_excludes_run_specific_provenance() -> None:
    identity = build_gitleaks_finding_identity(
        _content_finding()
    )
    material = identity.identity_material()

    assert "projection_id" not in material
    assert "projection_digest" not in material
    assert "context_digest" not in material
    assert "repository_digest" not in material
    assert "file_digest" not in material


def test_identity_excludes_secret_bearing_scanner_fields() -> None:
    identity = build_gitleaks_finding_identity(
        _content_finding()
    )
    rendered = (
        identity.canonical_json()
        .decode("ascii")
    )

    for forbidden in (
        "Secret",
        "secret",
        "Match",
        "match",
        "Fingerprint",
        "fingerprint",
        "REDACTED",
    ):
        assert forbidden not in rendered


def test_identity_has_only_lowercase_sha256_public_id() -> None:
    identity = build_gitleaks_finding_identity(
        _content_finding()
    )

    assert re.fullmatch(
        r"[0-9a-f]{64}",
        identity.finding_instance_id,
    )


def test_canonical_json_is_repeatable_and_newline_terminated() -> None:
    identity = build_gitleaks_finding_identity(
        _content_finding()
    )

    first = identity.canonical_json()
    second = identity.canonical_json()

    assert first == second
    assert first.endswith(b"\n")
    assert b" " not in first


def test_identity_object_is_immutable() -> None:
    identity = build_gitleaks_finding_identity(
        _content_finding()
    )

    with pytest.raises(FrozenInstanceError):
        identity.rule_id = "changed"  # type: ignore[misc]


def test_duplicate_findings_keep_duplicate_identity_observations() -> None:
    finding = _content_finding()

    identities = (
        build_gitleaks_finding_identities(
            (finding, finding)
        )
    )

    assert len(identities) == 2
    assert identities[0] == identities[1]
    assert (
        identities[0].finding_instance_id
        == identities[1].finding_instance_id
    )


def test_batch_identity_preserves_input_order() -> None:
    first = _content_finding(
        file_path="a.py"
    )
    second = _content_finding(
        file_path="b.py"
    )

    identities = (
        build_gitleaks_finding_identities(
            (first, second)
        )
    )

    assert tuple(
        identity.file_path
        for identity in identities
    ) == ("a.py", "b.py")


def test_empty_batch_is_valid() -> None:
    assert (
        build_gitleaks_finding_identities(())
        == ()
    )


def test_batch_rejects_non_tuple_and_wrong_member_type() -> None:
    with pytest.raises(GitleaksIdentityError):
        build_gitleaks_finding_identities(
            []  # type: ignore[arg-type]
        )

    with pytest.raises(GitleaksIdentityError):
        build_gitleaks_finding_identities(
            (object(),)  # type: ignore[arg-type]
        )


def test_builder_rejects_wrong_input_type_with_fixed_error() -> None:
    with pytest.raises(
        GitleaksIdentityError
    ) as raised:
        build_gitleaks_finding_identity(
            object()  # type: ignore[arg-type]
        )

    assert str(raised.value) == (
        "Gitleaks finding identity is invalid"
    )


def test_hostile_mutated_normalized_finding_is_revalidated() -> None:
    finding = _content_finding()
    object.__setattr__(
        finding,
        "rule_id",
        "hostile rule id",
    )

    with pytest.raises(
        GitleaksIdentityError
    ) as raised:
        build_gitleaks_finding_identity(
            finding
        )

    assert str(raised.value) == (
        "Gitleaks finding identity is invalid"
    )
    assert "hostile rule id" not in str(
        raised.value
    )


def test_hostile_mutated_identity_is_revalidated_before_serialization() -> None:
    identity = build_gitleaks_finding_identity(
        _content_finding()
    )

    object.__setattr__(
        identity,
        "file_path",
        "../escape",
    )

    with pytest.raises(
        GitleaksIdentityError
    ):
        identity.canonical_data()

    with pytest.raises(
        GitleaksIdentityError
    ):
        identity.canonical_json()


def test_direct_identity_with_incorrect_digest_is_rejected() -> None:
    with pytest.raises(
        GitleaksIdentityError
    ):
        GitleaksFindingIdentity(
            scanner_id=GITLEAKS_SCANNER_ID,
            scanner_version=GITLEAKS_VERSION,
            rule_id="github-pat",
            file_path="src/app.py",
            detection_kind=(
                GitleaksDetectionKind.CONTENT
            ),
            start_line=12,
            end_line=12,
            start_column=3,
            end_column=9,
            finding_instance_id="0" * 64,
        )


def test_identity_generation_has_no_external_side_effects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finding = _content_finding()

    def fail(
        *_args: object,
        **_kwargs: object,
    ) -> None:
        raise AssertionError(
            "external operation attempted"
        )

    monkeypatch.setattr(
        builtins,
        "open",
        fail,
    )
    monkeypatch.setattr(
        os,
        "open",
        fail,
    )
    monkeypatch.setattr(
        Path,
        "open",
        fail,
    )
    monkeypatch.setattr(
        Path,
        "read_bytes",
        fail,
    )
    monkeypatch.setattr(
        Path,
        "read_text",
        fail,
    )
    monkeypatch.setattr(
        subprocess,
        "Popen",
        fail,
    )
    monkeypatch.setattr(
        subprocess,
        "run",
        fail,
    )
    monkeypatch.setattr(
        socket,
        "socket",
        fail,
    )

    identity = (
        build_gitleaks_finding_identity(
            finding
        )
    )

    assert (
        identity.finding_instance_id
        == _CONTENT_GOLDEN_ID
    )


def test_identity_layer_does_not_claim_dedup_or_tracking() -> None:
    identity = build_gitleaks_finding_identity(
        _content_finding()
    )

    assert not hasattr(
        identity,
        "deduplicated",
    )
    assert not hasattr(
        identity,
        "tracking_id",
    )
    assert not hasattr(
        identity,
        "baseline_status",
    )
    assert not hasattr(
        identity,
        "credential_id",
    )


def test_identity_path_contract_rejects_url_scheme_shape() -> None:
    identity = build_gitleaks_finding_identity(
        _path_finding()
    )

    object.__setattr__(
        identity,
        "file_path",
        "https:credential.p12",
    )

    with pytest.raises(GitleaksIdentityError):
        identity.canonical_data()


def test_identity_path_contract_rejects_overlong_path() -> None:
    identity = build_gitleaks_finding_identity(
        _path_finding()
    )

    object.__setattr__(
        identity,
        "file_path",
        "a" * 4097,
    )

    with pytest.raises(GitleaksIdentityError):
        identity.canonical_data()


def test_identity_location_contract_rejects_reversed_same_line_columns() -> None:
    finding = _content_finding(
        start_line=12,
        end_line=12,
        start_column=3,
        end_column=9,
    )

    identity = build_gitleaks_finding_identity(
        finding
    )

    object.__setattr__(
        identity,
        "end_column",
        2,
    )

    with pytest.raises(GitleaksIdentityError):
        identity.canonical_data()


@pytest.mark.parametrize(
    ("start_line", "end_line", "start_column", "end_column"),
    (
        (235, 236, 46, 19),
        (37, 38, 41, 26),
    ),
)
def test_multiline_parser_locations_generate_stable_structural_identity(
    start_line: int,
    end_line: int,
    start_column: int,
    end_column: int,
) -> None:
    finding = _content_finding(
        start_line=start_line,
        end_line=end_line,
        start_column=start_column,
        end_column=end_column,
    )

    first = build_gitleaks_finding_identity(finding)
    second = build_gitleaks_finding_identity(finding)

    assert first == second
    assert (
        first.start_line,
        first.end_line,
        first.start_column,
        first.end_column,
    ) == (start_line, end_line, start_column, end_column)


@pytest.mark.parametrize(
    "path",
    (
        "src/app.py",
        "nested/config/file.env",
        "certificates/client.p12",
        "folder/a+b.txt",
    ),
)
def test_parser_valid_path_shapes_remain_identity_compatible(
    path: str,
) -> None:
    finding = (
        _path_finding(file_path=path)
        if path.endswith(".p12")
        else _content_finding(file_path=path)
    )

    identity = build_gitleaks_finding_identity(
        finding
    )

    assert identity.file_path == path
