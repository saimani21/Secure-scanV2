from __future__ import annotations

import builtins
import hashlib
import os
import socket
import subprocess
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest
import sqlalchemy

import securescan.source.components as components_module
from securescan.execution import DockerSandboxExecutor
from securescan.source import (
    AnalysisCapability,
    ComponentizedRepositoryInventory,
    EnrichedRepositoryInventory,
    EnryClient,
    FileContentKind,
    RepositoryComponent,
    SourceComponentCorrelationError,
    SourceComponentDetectionError,
    SourceFileFlag,
    SourceFileRecord,
    SourceFileRole,
    SourceLanguageProfilingPolicy,
    TrustedEnryHelper,
    build_repository_inventory,
    detect_repository_components,
    enrich_repository_inventory,
    profile_repository_languages,
)
from securescan.workspaces import RepositoryManifestEntry, RepositoryWorkspaceManager
from securescan.workspaces.models import repository_content_digest

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_LOCAL_HELPER = _PROJECT_ROOT / "tools/enry-helper/bin/securescan-enry-helper"
_COMPONENT_ID_PREFIX = b"securescan-component-root-v0.2.4\0"


def _entry(relative_path: str, content: bytes) -> RepositoryManifestEntry:
    return RepositoryManifestEntry(
        relative_path=relative_path,
        size_bytes=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
    )


def _record(
    relative_path: str,
    *,
    role: SourceFileRole = SourceFileRole.SOURCE,
    content: bytes = b"content\n",
    content_kind: FileContentKind = FileContentKind.TEXT,
    language: str | None = None,
    component_id: str | None = None,
    flags: tuple[SourceFileFlag, ...] = (),
    eligible_capabilities: tuple[AnalysisCapability, ...] = (
        AnalysisCapability.REPOSITORY_PROFILING,
    ),
) -> SourceFileRecord:
    return SourceFileRecord(
        entry=_entry(relative_path, content),
        content_kind=content_kind,
        role=role,
        language=language,
        component_id=component_id,
        flags=flags,
        eligible_capabilities=eligible_capabilities,
    )


def _binary_record(
    relative_path: str,
    *,
    component_id: str | None = None,
) -> SourceFileRecord:
    return _record(
        relative_path,
        role=SourceFileRole.BINARY,
        content=b"\x00\x01\x02",
        content_kind=FileContentKind.BINARY,
        component_id=component_id,
        flags=(SourceFileFlag.BINARY,),
    )


def _enriched(*records: SourceFileRecord) -> EnrichedRepositoryInventory:
    files = tuple(sorted(records, key=lambda record: record.relative_path))
    return EnrichedRepositoryInventory(
        repository_digest=repository_content_digest(
            tuple(record.entry for record in files)
        ),
        files=files,
    )


def _expected_component_id(root_path: str) -> str:
    digest = hashlib.sha256(_COMPONENT_ID_PREFIX + root_path.encode("utf-8"))
    return f"component-{digest.hexdigest()[:32]}"


def _component(
    root_path: str,
    *,
    component_id: str | None = None,
    manifest_paths: tuple[str, ...] = (),
    lockfile_paths: tuple[str, ...] = (),
) -> RepositoryComponent:
    return RepositoryComponent(
        component_id=component_id or _expected_component_id(root_path),
        display_name=(
            "Repository root"
            if root_path == "."
            else Path(root_path).name
        ),
        root_path=root_path,
        manifest_paths=manifest_paths,
        lockfile_paths=lockfile_paths,
    )


def _component_by_root(
    result: ComponentizedRepositoryInventory,
) -> dict[str, RepositoryComponent]:
    return {component.root_path: component for component in result.components}


def _files_by_path(
    result: ComponentizedRepositoryInventory,
) -> dict[str, SourceFileRecord]:
    return {file.relative_path: file for file in result.files}


def _root_componentized_inventory() -> ComponentizedRepositoryInventory:
    return detect_repository_components(
        _enriched(
            _record("pyproject.toml", role=SourceFileRole.MANIFEST),
            _record("src/app.py", language="Python"),
        )
    )


def test_empty_componentized_inventory_is_valid() -> None:
    inventory = _enriched()

    result = detect_repository_components(inventory)

    assert result == ComponentizedRepositoryInventory(
        repository_digest=repository_content_digest(()),
        files=(),
        components=(),
    )
    assert result.file_count == 0
    assert result.component_count == 0
    assert result.total_bytes == 0


def test_componentized_inventory_rejects_wrong_schema() -> None:
    with pytest.raises(ValueError, match="Componentized repository inventory is invalid"):
        ComponentizedRepositoryInventory(
            repository_digest=repository_content_digest(()),
            files=(),
            components=(),
            schema_version="0.2.3",
        )


@pytest.mark.parametrize(
    "repository_digest",
    ["A" * 64, "a" * 63, "g" * 64, b"a" * 64],
)
def test_componentized_inventory_rejects_invalid_repository_digest(
    repository_digest: object,
) -> None:
    with pytest.raises(ValueError, match="Componentized repository inventory is invalid"):
        ComponentizedRepositoryInventory(
            repository_digest=repository_digest,  # type: ignore[arg-type]
            files=(),
            components=(),
        )


def test_componentized_inventory_rejects_unsorted_files() -> None:
    files = (_record("z.py"), _record("a.py"))
    with pytest.raises(ValueError, match="Componentized repository inventory is invalid"):
        ComponentizedRepositoryInventory(
            repository_digest=repository_content_digest(
                tuple(file.entry for file in files)
            ),
            files=files,
            components=(),
        )


def test_componentized_inventory_rejects_duplicate_files() -> None:
    file = _record("a.py")
    files = (file, file)
    with pytest.raises(ValueError, match="Componentized repository inventory is invalid"):
        ComponentizedRepositoryInventory(
            repository_digest=repository_content_digest(
                tuple(item.entry for item in files)
            ),
            files=files,
            components=(),
        )


def test_componentized_inventory_rejects_unsorted_components() -> None:
    result = detect_repository_components(
        _enriched(
            _record("a/pyproject.toml", role=SourceFileRole.MANIFEST),
            _record("z/pyproject.toml", role=SourceFileRole.MANIFEST),
        )
    )

    with pytest.raises(ValueError, match="Componentized repository inventory is invalid"):
        ComponentizedRepositoryInventory(
            repository_digest=result.repository_digest,
            files=result.files,
            components=tuple(reversed(result.components)),
        )


def test_componentized_inventory_rejects_duplicate_component_ids() -> None:
    components = (
        _component("a", component_id="component-same"),
        _component("b", component_id="component-same"),
    )
    with pytest.raises(ValueError, match="Componentized repository inventory is invalid"):
        ComponentizedRepositoryInventory(
            repository_digest=repository_content_digest(()),
            files=(),
            components=components,
        )


def test_componentized_inventory_rejects_duplicate_component_roots() -> None:
    components = (
        _component("same", component_id="component-a"),
        _component("same", component_id="component-b"),
    )
    with pytest.raises(ValueError, match="Componentized repository inventory is invalid"):
        ComponentizedRepositoryInventory(
            repository_digest=repository_content_digest(()),
            files=(),
            components=components,
        )


def test_componentized_inventory_rejects_unknown_file_component_id() -> None:
    file = _record("src/app.py", component_id="missing")
    with pytest.raises(
        ValueError,
        match="Componentized repository inventory references an unknown component",
    ):
        ComponentizedRepositoryInventory(
            repository_digest=repository_content_digest((file.entry,)),
            files=(file,),
            components=(),
        )


def test_componentized_inventory_rejects_missing_manifest_reference() -> None:
    with pytest.raises(ValueError, match="Component manifest reference is invalid"):
        ComponentizedRepositoryInventory(
            repository_digest=repository_content_digest(()),
            files=(),
            components=(
                _component(".", manifest_paths=("pyproject.toml",)),
            ),
        )


def test_componentized_inventory_rejects_missing_lockfile_reference() -> None:
    with pytest.raises(ValueError, match="Component lockfile reference is invalid"):
        ComponentizedRepositoryInventory(
            repository_digest=repository_content_digest(()),
            files=(),
            components=(
                _component(".", lockfile_paths=("poetry.lock",)),
            ),
        )


def test_componentized_inventory_rejects_manifest_role_mismatch() -> None:
    component_id = _expected_component_id(".")
    file = _record("not-a-manifest.py", component_id=component_id)
    with pytest.raises(ValueError, match="Component manifest reference is invalid"):
        ComponentizedRepositoryInventory(
            repository_digest=repository_content_digest((file.entry,)),
            files=(file,),
            components=(
                _component(".", manifest_paths=(file.relative_path,)),
            ),
        )


def test_componentized_inventory_rejects_lockfile_role_mismatch() -> None:
    component_id = _expected_component_id(".")
    file = _record("not-a-lockfile.py", component_id=component_id)
    with pytest.raises(ValueError, match="Component lockfile reference is invalid"):
        ComponentizedRepositoryInventory(
            repository_digest=repository_content_digest((file.entry,)),
            files=(file,),
            components=(
                _component(".", lockfile_paths=(file.relative_path,)),
            ),
        )


def test_componentized_inventory_rejects_digest_file_mismatch() -> None:
    with pytest.raises(
        ValueError,
        match="Componentized repository inventory digest does not match its files",
    ):
        ComponentizedRepositoryInventory(
            repository_digest="a" * 64,
            files=(_record("src/app.py"),),
            components=(),
        )


def test_componentized_inventory_rejects_evidence_outside_root() -> None:
    component = object.__new__(RepositoryComponent)
    object.__setattr__(component, "component_id", "component-a")
    object.__setattr__(component, "display_name", "backend")
    object.__setattr__(component, "root_path", "backend")
    object.__setattr__(component, "manifest_paths", ("outside/pyproject.toml",))
    object.__setattr__(component, "lockfile_paths", ())
    file = _record(
        "outside/pyproject.toml",
        role=SourceFileRole.MANIFEST,
        component_id="component-a",
    )

    with pytest.raises(ValueError, match="Component manifest reference is invalid"):
        ComponentizedRepositoryInventory(
            repository_digest=repository_content_digest((file.entry,)),
            files=(file,),
            components=(component,),
        )


def test_parent_component_cannot_reference_nested_component_file() -> None:
    parent_id = _expected_component_id(".")
    child_id = _expected_component_id("child")
    file = _record(
        "child/pyproject.toml",
        role=SourceFileRole.MANIFEST,
        component_id=child_id,
    )
    components = tuple(
        sorted(
            (
                _component(".", manifest_paths=(file.relative_path,)),
                _component(
                    "child",
                    manifest_paths=(file.relative_path,),
                ),
            ),
            key=lambda item: item.component_id,
        )
    )
    assert parent_id != child_id

    with pytest.raises(ValueError, match="Component manifest reference is invalid"):
        ComponentizedRepositoryInventory(
            repository_digest=repository_content_digest((file.entry,)),
            files=(file,),
            components=components,
        )


def test_componentized_canonical_representation_is_deterministic() -> None:
    result = _root_componentized_inventory()

    assert result.canonical_data() == {
        "component_count": 1,
        "components": [result.components[0].canonical_data()],
        "file_count": 2,
        "files": [file.canonical_data() for file in result.files],
        "repository_digest": result.repository_digest,
        "schema_version": "0.2.4",
        "total_bytes": sum(file.entry.size_bytes for file in result.files),
    }
    assert result.canonical_data() == result.canonical_data()


def test_componentization_digest_is_deterministic() -> None:
    result = _root_componentized_inventory()

    assert len(result.componentization_digest()) == 64
    assert result.componentization_digest() == result.componentization_digest()


def test_componentization_digest_has_fixed_golden_value() -> None:
    result = _root_componentized_inventory()

    assert result.componentization_digest() == (
        "80244dc0046f6c0ff350c6848468e0db"
        "8d6b2159019ce92e605267c2d4675863"
    )


def test_componentization_semantic_change_changes_digest() -> None:
    first = detect_repository_components(
        _enriched(_record("pyproject.toml", role=SourceFileRole.MANIFEST))
    )
    second = detect_repository_components(
        _enriched(
            _record("pyproject.toml", role=SourceFileRole.MANIFEST),
            _record("src/app.py"),
        )
    )

    assert first.componentization_digest() != second.componentization_digest()


def test_componentized_inventory_is_immutable() -> None:
    result = _root_componentized_inventory()

    with pytest.raises(FrozenInstanceError):
        result.components = ()  # type: ignore[misc]


def test_detect_repository_components_rejects_invalid_input() -> None:
    with pytest.raises(SourceComponentDetectionError, match="Source component detection failed"):
        detect_repository_components(object())  # type: ignore[arg-type]


def test_root_pyproject_creates_repository_root_component() -> None:
    result = detect_repository_components(
        _enriched(_record("pyproject.toml", role=SourceFileRole.MANIFEST))
    )
    component = result.components[0]

    assert component.root_path == "."
    assert component.display_name == "Repository root"
    assert component.manifest_paths == ("pyproject.toml",)


def test_nested_pyproject_creates_nested_component() -> None:
    result = detect_repository_components(
        _enriched(_record("backend/pyproject.toml", role=SourceFileRole.MANIFEST))
    )

    assert result.components[0].root_path == "backend"
    assert result.components[0].display_name == "backend"


@pytest.mark.parametrize(
    "manifest_name",
    ["setup.py", "setup.cfg", "requirements-dev.txt", "package.json"],
)
def test_existing_manifest_roles_create_components(manifest_name: str) -> None:
    result = detect_repository_components(
        _enriched(
            _record(
                f"service/{manifest_name}",
                role=SourceFileRole.MANIFEST,
            )
        )
    )

    assert tuple(component.root_path for component in result.components) == ("service",)


def test_multiple_manifests_in_same_directory_create_one_component() -> None:
    paths = (
        "backend/pyproject.toml",
        "backend/requirements.txt",
        "backend/setup.cfg",
    )
    result = detect_repository_components(
        _enriched(*(_record(path, role=SourceFileRole.MANIFEST) for path in paths))
    )

    assert result.component_count == 1
    assert result.components[0].manifest_paths == paths


def test_terraform_file_creates_component() -> None:
    result = detect_repository_components(
        _enriched(_record("infra/main.tf", role=SourceFileRole.TERRAFORM))
    )

    assert result.components[0].root_path == "infra"
    assert result.components[0].manifest_paths == ()


def test_multiple_terraform_files_in_directory_create_one_component() -> None:
    result = detect_repository_components(
        _enriched(
            _record("infra/main.tf", role=SourceFileRole.TERRAFORM),
            _record("infra/variables.tf", role=SourceFileRole.TERRAFORM),
        )
    )

    assert result.component_count == 1
    assert all(
        file.component_id == result.components[0].component_id
        for file in result.files
    )


def test_nested_terraform_directory_creates_independent_component() -> None:
    result = detect_repository_components(
        _enriched(
            _record("infra/main.tf", role=SourceFileRole.TERRAFORM),
            _record("infra/modules/db/main.tf", role=SourceFileRole.TERRAFORM),
        )
    )

    assert set(_component_by_root(result)) == {"infra", "infra/modules/db"}


def test_manifest_and_terraform_same_directory_coalesce() -> None:
    result = detect_repository_components(
        _enriched(
            _record("service/main.tf", role=SourceFileRole.TERRAFORM),
            _record("service/package.json", role=SourceFileRole.MANIFEST),
            _record("service/pyproject.toml", role=SourceFileRole.MANIFEST),
        )
    )

    assert result.component_count == 1
    assert result.components[0].manifest_paths == (
        "service/package.json",
        "service/pyproject.toml",
    )


@pytest.mark.parametrize(
    ("relative_path", "role", "binary"),
    [
        ("Dockerfile", SourceFileRole.DOCKERFILE, False),
        ("poetry.lock", SourceFileRole.LOCKFILE, False),
        ("src/app.py", SourceFileRole.SOURCE, False),
        ("README.md", SourceFileRole.DOCUMENTATION, False),
        ("asset.bin", SourceFileRole.BINARY, True),
    ],
)
def test_non_marker_files_alone_do_not_create_components(
    relative_path: str,
    role: SourceFileRole,
    binary: bool,
) -> None:
    record = _binary_record(relative_path) if binary else _record(relative_path, role=role)
    result = detect_repository_components(_enriched(record))

    assert result.components == ()
    assert result.files[0].component_id is None


@pytest.mark.parametrize(
    "lockfile_name",
    [
        "Pipfile.lock",
        "package-lock.json",
        "pnpm-lock.yaml",
        "poetry.lock",
        "uv.lock",
        "yarn.lock",
    ],
)
def test_same_directory_lockfile_is_associated(lockfile_name: str) -> None:
    result = detect_repository_components(
        _enriched(
            _record("backend/pyproject.toml", role=SourceFileRole.MANIFEST),
            _record(f"backend/{lockfile_name}", role=SourceFileRole.LOCKFILE),
        )
    )

    assert result.components[0].lockfile_paths == (f"backend/{lockfile_name}",)


def test_nested_lockfile_is_not_metadata_associated_to_ancestor() -> None:
    result = detect_repository_components(
        _enriched(
            _record("backend/pyproject.toml", role=SourceFileRole.MANIFEST),
            _record("backend/nested/poetry.lock", role=SourceFileRole.LOCKFILE),
        )
    )
    files = _files_by_path(result)

    assert result.components[0].lockfile_paths == ()
    assert files["backend/nested/poetry.lock"].component_id == (
        result.components[0].component_id
    )


def test_orphan_lockfile_does_not_create_component() -> None:
    result = detect_repository_components(
        _enriched(_record("orphan/poetry.lock", role=SourceFileRole.LOCKFILE))
    )

    assert result.components == ()
    assert result.files[0].component_id is None


def test_lockfile_association_is_deterministic() -> None:
    inventory = _enriched(
        _record("backend/package-lock.json", role=SourceFileRole.LOCKFILE),
        _record("backend/package.json", role=SourceFileRole.MANIFEST),
        _record("backend/yarn.lock", role=SourceFileRole.LOCKFILE),
    )

    first = detect_repository_components(inventory)
    second = detect_repository_components(inventory)

    assert first.components == second.components
    assert first.components[0].lockfile_paths == (
        "backend/package-lock.json",
        "backend/yarn.lock",
    )


def test_root_component_assigns_all_non_nested_files() -> None:
    result = detect_repository_components(
        _enriched(
            _record("pyproject.toml", role=SourceFileRole.MANIFEST),
            _record("README.md", role=SourceFileRole.DOCUMENTATION),
            _record("src/app.py"),
        )
    )
    root_id = _component_by_root(result)["."].component_id

    assert all(file.component_id == root_id for file in result.files)


def test_nested_component_files_are_assigned_to_nested_component() -> None:
    result = detect_repository_components(
        _enriched(
            _record("pyproject.toml", role=SourceFileRole.MANIFEST),
            _record("packages/api/package.json", role=SourceFileRole.MANIFEST),
            _record("packages/api/src/app.js"),
        )
    )
    components = _component_by_root(result)
    files = _files_by_path(result)

    assert files["packages/api/src/app.js"].component_id == (
        components["packages/api"].component_id
    )


def test_deepest_component_root_wins() -> None:
    result = detect_repository_components(
        _enriched(
            _record("a/pyproject.toml", role=SourceFileRole.MANIFEST),
            _record("a/b/package.json", role=SourceFileRole.MANIFEST),
            _record("a/b/c/setup.cfg", role=SourceFileRole.MANIFEST),
            _record("a/b/c/src/app.py"),
        )
    )
    components = _component_by_root(result)

    assert _files_by_path(result)["a/b/c/src/app.py"].component_id == (
        components["a/b/c"].component_id
    )


def test_parent_source_remains_assigned_to_parent() -> None:
    result = detect_repository_components(
        _enriched(
            _record("pyproject.toml", role=SourceFileRole.MANIFEST),
            _record("packages/api/package.json", role=SourceFileRole.MANIFEST),
            _record("src/root.py"),
        )
    )

    assert _files_by_path(result)["src/root.py"].component_id == (
        _component_by_root(result)["."].component_id
    )


def test_child_manifest_belongs_only_to_child_component() -> None:
    result = detect_repository_components(
        _enriched(
            _record("pyproject.toml", role=SourceFileRole.MANIFEST),
            _record("child/package.json", role=SourceFileRole.MANIFEST),
        )
    )
    components = _component_by_root(result)
    child_path = "child/package.json"

    assert _files_by_path(result)[child_path].component_id == components["child"].component_id
    assert child_path not in components["."].manifest_paths
    assert components["child"].manifest_paths == (child_path,)


def test_child_lockfile_belongs_and_is_associated_only_to_child() -> None:
    result = detect_repository_components(
        _enriched(
            _record("pyproject.toml", role=SourceFileRole.MANIFEST),
            _record("child/package-lock.json", role=SourceFileRole.LOCKFILE),
            _record("child/package.json", role=SourceFileRole.MANIFEST),
        )
    )
    components = _component_by_root(result)
    lock_path = "child/package-lock.json"

    assert _files_by_path(result)[lock_path].component_id == components["child"].component_id
    assert lock_path not in components["."].lockfile_paths
    assert components["child"].lockfile_paths == (lock_path,)


def test_file_outside_every_component_remains_unassigned() -> None:
    result = detect_repository_components(
        _enriched(
            _record("backend/pyproject.toml", role=SourceFileRole.MANIFEST),
            _record("README.md", role=SourceFileRole.DOCUMENTATION),
        )
    )

    assert _files_by_path(result)["README.md"].component_id is None


def test_repository_without_components_leaves_all_files_unassigned() -> None:
    result = detect_repository_components(
        _enriched(
            _record("README.md", role=SourceFileRole.DOCUMENTATION),
            _record("src/a.py"),
            _record("src/b.py"),
        )
    )

    assert result.components == ()
    assert all(file.component_id is None for file in result.files)


@pytest.mark.parametrize(
    ("relative_path", "record_factory"),
    [
        ("service/Dockerfile", "docker"),
        ("service/asset.bin", "binary"),
        ("service/docs/README.md", "documentation"),
    ],
)
def test_non_marker_file_under_component_receives_membership(
    relative_path: str,
    record_factory: str,
) -> None:
    if record_factory == "binary":
        member = _binary_record(relative_path)
    else:
        role = (
            SourceFileRole.DOCKERFILE
            if record_factory == "docker"
            else SourceFileRole.DOCUMENTATION
        )
        member = _record(relative_path, role=role)
    result = detect_repository_components(
        _enriched(
            _record("service/pyproject.toml", role=SourceFileRole.MANIFEST),
            member,
        )
    )

    assert _files_by_path(result)[relative_path].component_id == (
        result.components[0].component_id
    )


def test_component_assignment_preserves_all_d2_file_facts() -> None:
    record = _record(
        "service/src/app.py",
        content=b"def main():\n    return True\n",
        language="Python",
        flags=(
            SourceFileFlag.GENERATED,
            SourceFileFlag.TEST,
            SourceFileFlag.VENDORED,
        ),
        eligible_capabilities=(
            AnalysisCapability.PYTHON_SAST,
            AnalysisCapability.REPOSITORY_PROFILING,
            AnalysisCapability.SECRET_DETECTION,
        ),
    )
    inventory = _enriched(
        _record("service/pyproject.toml", role=SourceFileRole.MANIFEST),
        record,
    )

    result = detect_repository_components(inventory)
    assigned = _files_by_path(result)[record.relative_path]

    assert assigned is not record
    assert assigned.entry is record.entry
    assert assigned.content_kind is record.content_kind
    assert assigned.role is record.role
    assert assigned.language == record.language
    assert assigned.flags is record.flags
    assert assigned.eligible_capabilities is record.eligible_capabilities
    assert result.repository_digest == inventory.repository_digest


def test_root_and_nested_components_assign_expected_membership() -> None:
    result = detect_repository_components(
        _enriched(
            _record("package.json", role=SourceFileRole.MANIFEST),
            _record("packages/api/package.json", role=SourceFileRole.MANIFEST),
            _record("packages/api/src/app.js"),
            _record("src/root.js"),
        )
    )
    components = _component_by_root(result)
    files = _files_by_path(result)

    assert files["package.json"].component_id == components["."].component_id
    assert files["src/root.js"].component_id == components["."].component_id
    assert files["packages/api/package.json"].component_id == (
        components["packages/api"].component_id
    )
    assert files["packages/api/src/app.js"].component_id == (
        components["packages/api"].component_id
    )


def test_sibling_components_are_independent() -> None:
    result = detect_repository_components(
        _enriched(
            _record("apps/api/package.json", role=SourceFileRole.MANIFEST),
            _record("apps/api/src/app.js"),
            _record("apps/web/package.json", role=SourceFileRole.MANIFEST),
            _record("apps/web/src/app.js"),
        )
    )
    components = _component_by_root(result)
    files = _files_by_path(result)

    assert files["apps/api/src/app.js"].component_id == components["apps/api"].component_id
    assert files["apps/web/src/app.js"].component_id == components["apps/web"].component_id


def test_identical_basename_roots_have_distinct_ids() -> None:
    result = detect_repository_components(
        _enriched(
            _record("apps/api/package.json", role=SourceFileRole.MANIFEST),
            _record("services/api/pyproject.toml", role=SourceFileRole.MANIFEST),
        )
    )
    components = _component_by_root(result)

    assert components["apps/api"].display_name == "api"
    assert components["services/api"].display_name == "api"
    assert components["apps/api"].component_id != components["services/api"].component_id


def test_component_ids_are_stable_across_repeated_detection() -> None:
    inventory = _enriched(
        _record("apps/api/package.json", role=SourceFileRole.MANIFEST),
        _record("pyproject.toml", role=SourceFileRole.MANIFEST),
    )

    first = detect_repository_components(inventory)
    second = detect_repository_components(inventory)

    assert {
        component.root_path: component.component_id
        for component in first.components
    } == {
        component.root_path: component.component_id
        for component in second.components
    }


def test_adding_unrelated_file_does_not_change_existing_root_ids() -> None:
    first = detect_repository_components(
        _enriched(_record("service/pyproject.toml", role=SourceFileRole.MANIFEST))
    )
    second = detect_repository_components(
        _enriched(
            _record("service/pyproject.toml", role=SourceFileRole.MANIFEST),
            _record("unrelated.txt", role=SourceFileRole.OTHER),
        )
    )

    assert _component_by_root(first)["service"].component_id == (
        _component_by_root(second)["service"].component_id
    )


def test_component_ordering_is_deterministic_by_id() -> None:
    inventory = _enriched(
        _record("a/pyproject.toml", role=SourceFileRole.MANIFEST),
        _record("m/main.tf", role=SourceFileRole.TERRAFORM),
        _record("z/package.json", role=SourceFileRole.MANIFEST),
    )
    result = detect_repository_components(inventory)

    assert result.components == tuple(
        sorted(result.components, key=lambda component: component.component_id)
    )
    assert detect_repository_components(inventory).components == result.components


def test_long_component_basename_uses_fixed_safe_display_name() -> None:
    root_path = "a" * 201
    result = detect_repository_components(
        _enriched(
            _record(f"{root_path}/pyproject.toml", role=SourceFileRole.MANIFEST)
        )
    )

    assert result.components[0].display_name == "Repository component"


def test_component_id_algorithm_has_fixed_root_value() -> None:
    result = detect_repository_components(
        _enriched(_record("pyproject.toml", role=SourceFileRole.MANIFEST))
    )

    assert result.components[0].component_id == (
        "component-2e0e303148f8b55a8f42b5f6b0e0d1c9"
    )


def test_impossible_component_id_collision_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inventory = _enriched(
        _record("a/pyproject.toml", role=SourceFileRole.MANIFEST),
        _record("b/pyproject.toml", role=SourceFileRole.MANIFEST),
    )
    monkeypatch.setattr(
        components_module,
        "_component_id_for_root",
        lambda _root_path: "component-collision",
    )

    with pytest.raises(SourceComponentDetectionError):
        detect_repository_components(inventory)


def test_correct_preexisting_component_ids_are_accepted() -> None:
    root_id = _expected_component_id("service")
    inventory = _enriched(
        _record(
            "service/pyproject.toml",
            role=SourceFileRole.MANIFEST,
            component_id=root_id,
        ),
        _record("service/src/app.py", component_id=root_id),
    )

    result = detect_repository_components(inventory)

    assert all(file.component_id == root_id for file in result.files)


def test_conflicting_preexisting_component_id_is_rejected() -> None:
    inventory = _enriched(
        _record(
            "service/pyproject.toml",
            role=SourceFileRole.MANIFEST,
            component_id="component-conflict",
        )
    )

    with pytest.raises(SourceComponentCorrelationError) as raised:
        detect_repository_components(inventory)

    assert str(raised.value) == "Source component correlation failed"
    assert "service" not in str(raised.value)


def test_preexisting_component_id_without_derived_root_is_rejected() -> None:
    inventory = _enriched(
        _record("src/app.py", component_id="component-conflict")
    )

    with pytest.raises(SourceComponentCorrelationError):
        detect_repository_components(inventory)


def test_component_detection_does_not_mutate_input() -> None:
    inventory = _enriched(
        _record("service/pyproject.toml", role=SourceFileRole.MANIFEST),
        _record("service/src/app.py", language="Python"),
    )
    before = inventory.canonical_data()
    original_files = inventory.files

    detect_repository_components(inventory)

    assert inventory.canonical_data() == before
    assert inventory.files is original_files
    assert all(file.component_id is None for file in inventory.files)


def test_component_detection_has_no_external_side_effects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inventory = _enriched(
        _record("service/pyproject.toml", role=SourceFileRole.MANIFEST)
    )

    def fail(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("external operation attempted")

    monkeypatch.setattr(builtins, "open", fail)
    monkeypatch.setattr(os, "open", fail)
    monkeypatch.setattr(os, "system", fail)
    monkeypatch.setattr(Path, "open", fail)
    monkeypatch.setattr(Path, "read_bytes", fail)
    monkeypatch.setattr(Path, "read_text", fail)
    monkeypatch.setattr(subprocess, "Popen", fail)
    monkeypatch.setattr(subprocess, "run", fail)
    monkeypatch.setattr(socket, "socket", fail)
    monkeypatch.setattr(sqlalchemy, "create_engine", fail)
    monkeypatch.setattr(DockerSandboxExecutor, "execute", fail)
    monkeypatch.setattr(EnryClient, "classify", fail)

    assert detect_repository_components(inventory).component_count == 1


def test_componentized_inventory_retains_no_bytes_or_host_information() -> None:
    sensitive = b"private source content"
    inventory = _enriched(
        _record(
            "service/pyproject.toml",
            role=SourceFileRole.MANIFEST,
            content=sensitive,
        )
    )

    result = detect_repository_components(inventory)
    rendered = repr(result)

    assert sensitive.decode("ascii") not in rendered
    assert "/home/" not in rendered
    assert "enry-helper" not in rendered
    assert all(not file.relative_path.startswith("/") for file in result.files)


def test_repeated_component_detection_is_identical() -> None:
    inventory = _enriched(
        _record("pyproject.toml", role=SourceFileRole.MANIFEST),
        _record("src/app.py"),
    )

    assert detect_repository_components(inventory) == detect_repository_components(
        inventory
    )


@pytest.mark.skipif(not _LOCAL_HELPER.exists(), reason="local Enry helper is absent")
def test_real_enry_component_detection_pipeline(tmp_path: Path) -> None:
    source = tmp_path / "repository"
    files = {
        "Dockerfile": b"FROM scratch\n",
        "asset.bin": b"\x00\x01\x02\x03",
        "docs/README.md": b"# Documentation\n",
        "frontend/package-lock.json": b'{"lockfileVersion": 3}\n',
        "frontend/package.json": b'{"name": "frontend"}\n',
        "frontend/src/app.js": b"export const app = true;\n",
        "infra/main.tf": b'terraform { required_version = ">= 1.0" }\n',
        "infra/modules/db/main.tf": b'resource "null_resource" "db" {}\n',
        "infra/variables.tf": b'variable "region" { type = string }\n',
        "pyproject.toml": b"[project]\nname = 'root'\n",
        "services/api/poetry.lock": b"package = []\n",
        "services/api/pyproject.toml": b"[project]\nname = 'api'\n",
        "services/api/src/app.py": b"def main():\n    return True\n",
        "src/root.py": b"ROOT = True\n",
    }
    for relative_path, content in files.items():
        path = source / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    manager = RepositoryWorkspaceManager(tmp_path / "managed")
    workspace = manager.prepare_repository(source)
    with _LOCAL_HELPER.open("rb") as helper_stream:
        helper_digest = hashlib.file_digest(helper_stream, "sha256").hexdigest()
    client = EnryClient(
        TrustedEnryHelper(
            helper_path=_LOCAL_HELPER,
            expected_sha256=helper_digest,
        )
    )

    try:
        base_inventory = build_repository_inventory(workspace)
        language_profile = profile_repository_languages(
            workspace,
            base_inventory,
            client,
            policy=SourceLanguageProfilingPolicy(sample_bytes=1024),
        )
        enriched = enrich_repository_inventory(base_inventory, language_profile)
        result = detect_repository_components(enriched)
        repeated = detect_repository_components(enriched)
        components = _component_by_root(result)
        input_files = {file.relative_path: file for file in enriched.files}
        output_files = _files_by_path(result)

        assert set(components) == {
            ".",
            "frontend",
            "infra",
            "infra/modules/db",
            "services/api",
        }
        assert result == repeated
        assert output_files["src/root.py"].component_id == components["."].component_id
        assert output_files["Dockerfile"].component_id == components["."].component_id
        assert output_files["asset.bin"].component_id == components["."].component_id
        assert output_files["docs/README.md"].component_id == components["."].component_id
        assert output_files["frontend/src/app.js"].component_id == (
            components["frontend"].component_id
        )
        assert output_files["services/api/src/app.py"].component_id == (
            components["services/api"].component_id
        )
        assert output_files["infra/main.tf"].component_id == components["infra"].component_id
        assert output_files["infra/variables.tf"].component_id == (
            components["infra"].component_id
        )
        assert output_files["infra/modules/db/main.tf"].component_id == (
            components["infra/modules/db"].component_id
        )
        assert components["frontend"].manifest_paths == ("frontend/package.json",)
        assert components["frontend"].lockfile_paths == ("frontend/package-lock.json",)
        assert components["services/api"].manifest_paths == (
            "services/api/pyproject.toml",
        )
        assert components["services/api"].lockfile_paths == (
            "services/api/poetry.lock",
        )
        assert all(
            output_files[path].entry is input_files[path].entry
            and output_files[path].content_kind is input_files[path].content_kind
            and output_files[path].role is input_files[path].role
            and output_files[path].language == input_files[path].language
            and output_files[path].flags is input_files[path].flags
            and output_files[path].eligible_capabilities
            is input_files[path].eligible_capabilities
            for path in output_files
        )
        assert not hasattr(result, "support_state")
        assert not hasattr(result, "coverage_status")
        assert not hasattr(result, "surfaces")
        assert not hasattr(result, "scanner_plan")
    finally:
        manager.cleanup_workspace(workspace)
