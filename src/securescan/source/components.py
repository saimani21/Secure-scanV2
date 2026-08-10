from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from pathlib import PurePosixPath
from typing import Any

from securescan.source.enrichment import EnrichedRepositoryInventory
from securescan.source.enums import SourceFileRole
from securescan.source.models import RepositoryComponent, SourceFileRecord
from securescan.workspaces.models import repository_content_digest

_COMPONENT_ID_STREAM_VERSION = b"securescan-component-root-v0.2.4\0"
_COMPONENTIZATION_STREAM_VERSION = b"securescan-source-componentization-v0.2.4\0"
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_MAX_DISPLAY_NAME_CHARACTERS = 200
_FALLBACK_DISPLAY_NAME = "Repository component"


class SourceComponentDetectionError(RuntimeError):
    """Raised when deterministic component detection cannot complete."""

    def __init__(self) -> None:
        super().__init__("Source component detection failed")


class SourceComponentCorrelationError(SourceComponentDetectionError):
    """Raised when derived component facts conflict with trusted input facts."""

    def __init__(self) -> None:
        RuntimeError.__init__(
            self,
            "Source component correlation failed",
        )


def _path_is_within_root(path: str, root_path: str) -> bool:
    return root_path == "." or path.startswith(f"{root_path}/")


@dataclass(frozen=True, slots=True, kw_only=True)
class ComponentizedRepositoryInventory:
    repository_digest: str
    files: tuple[SourceFileRecord, ...]
    components: tuple[RepositoryComponent, ...]
    schema_version: str = "0.2.4"

    def __post_init__(self) -> None:
        if (
            self.schema_version != "0.2.4"
            or not isinstance(self.repository_digest, str)
            or _SHA256_PATTERN.fullmatch(self.repository_digest) is None
            or not isinstance(self.files, tuple)
            or any(not isinstance(file, SourceFileRecord) for file in self.files)
            or self.files
            != tuple(sorted(self.files, key=lambda file: file.relative_path))
            or len({file.relative_path for file in self.files}) != len(self.files)
            or not isinstance(self.components, tuple)
            or any(
                not isinstance(component, RepositoryComponent)
                for component in self.components
            )
            or self.components
            != tuple(
                sorted(
                    self.components,
                    key=lambda component: component.component_id,
                )
            )
            or len({component.component_id for component in self.components})
            != len(self.components)
            or len({component.root_path for component in self.components})
            != len(self.components)
        ):
            raise ValueError("Componentized repository inventory is invalid")

        expected_digest = repository_content_digest(
            tuple(file.entry for file in self.files)
        )
        if self.repository_digest != expected_digest:
            raise ValueError(
                "Componentized repository inventory digest does not match its files"
            )

        files_by_path = {file.relative_path: file for file in self.files}
        component_ids = {component.component_id for component in self.components}
        if any(
            file.component_id is not None
            and file.component_id not in component_ids
            for file in self.files
        ):
            raise ValueError(
                "Componentized repository inventory references an unknown component"
            )

        for component in self.components:
            for path in component.manifest_paths:
                file = files_by_path.get(path)
                if (
                    not _path_is_within_root(path, component.root_path)
                    or file is None
                    or file.role is not SourceFileRole.MANIFEST
                    or file.component_id != component.component_id
                ):
                    raise ValueError("Component manifest reference is invalid")
            for path in component.lockfile_paths:
                file = files_by_path.get(path)
                if (
                    not _path_is_within_root(path, component.root_path)
                    or file is None
                    or file.role is not SourceFileRole.LOCKFILE
                    or file.component_id != component.component_id
                ):
                    raise ValueError("Component lockfile reference is invalid")

    @property
    def file_count(self) -> int:
        return len(self.files)

    @property
    def component_count(self) -> int:
        return len(self.components)

    @property
    def total_bytes(self) -> int:
        return sum(file.entry.size_bytes for file in self.files)

    def canonical_data(self) -> dict[str, Any]:
        return {
            "component_count": self.component_count,
            "components": [
                component.canonical_data()
                for component in self.components
            ],
            "file_count": self.file_count,
            "files": [file.canonical_data() for file in self.files],
            "repository_digest": self.repository_digest,
            "schema_version": self.schema_version,
            "total_bytes": self.total_bytes,
        }

    def componentization_digest(self) -> str:
        payload = json.dumps(
            self.canonical_data(),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        digest = hashlib.sha256()
        digest.update(_COMPONENTIZATION_STREAM_VERSION)
        digest.update(payload)
        return digest.hexdigest()


def _component_root(relative_path: str) -> str:
    return str(PurePosixPath(relative_path).parent)


def _component_id_for_root(root_path: str) -> str:
    digest = hashlib.sha256()
    digest.update(_COMPONENT_ID_STREAM_VERSION)
    digest.update(root_path.encode("utf-8"))
    return f"component-{digest.hexdigest()[:32]}"


def _component_display_name(root_path: str) -> str:
    if root_path == ".":
        return "Repository root"
    name = PurePosixPath(root_path).name
    if (
        name == name.strip()
        and 1 <= len(name) <= _MAX_DISPLAY_NAME_CHARACTERS
        and not any(ord(character) < 32 or ord(character) == 127 for character in name)
    ):
        return name
    return _FALLBACK_DISPLAY_NAME


def _deepest_component_root(
    relative_path: str,
    roots_by_depth: tuple[str, ...],
) -> str | None:
    return next(
        (
            root_path
            for root_path in roots_by_depth
            if _path_is_within_root(relative_path, root_path)
        ),
        None,
    )


def detect_repository_components(
    inventory: EnrichedRepositoryInventory,
) -> ComponentizedRepositoryInventory:
    if not isinstance(inventory, EnrichedRepositoryInventory):
        raise SourceComponentDetectionError

    candidate_roots = {
        _component_root(file.relative_path)
        for file in inventory.files
        if file.role in {SourceFileRole.MANIFEST, SourceFileRole.TERRAFORM}
    }
    root_ids: dict[str, str] = {}
    id_roots: dict[str, str] = {}
    for root_path in sorted(candidate_roots):
        component_id = _component_id_for_root(root_path)
        existing_root = id_roots.get(component_id)
        if existing_root is not None and existing_root != root_path:
            raise SourceComponentDetectionError
        root_ids[root_path] = component_id
        id_roots[component_id] = root_path

    roots_by_depth = tuple(
        sorted(
            candidate_roots,
            key=lambda root_path: (
                -len(PurePosixPath(root_path).parts) if root_path != "." else 0,
                root_path,
            ),
        )
    )
    enriched_files: list[SourceFileRecord] = []
    for file in inventory.files:
        root_path = _deepest_component_root(file.relative_path, roots_by_depth)
        component_id = root_ids[root_path] if root_path is not None else None
        if file.component_id is not None and file.component_id != component_id:
            raise SourceComponentCorrelationError
        try:
            enriched_files.append(replace(file, component_id=component_id))
        except (TypeError, ValueError):
            raise SourceComponentCorrelationError from None

    files_by_path = {file.relative_path: file for file in enriched_files}
    components: list[RepositoryComponent] = []
    for root_path, component_id in root_ids.items():
        manifest_paths = tuple(
            file.relative_path
            for file in inventory.files
            if file.role is SourceFileRole.MANIFEST
            and _component_root(file.relative_path) == root_path
        )
        lockfile_paths = tuple(
            file.relative_path
            for file in inventory.files
            if file.role is SourceFileRole.LOCKFILE
            and _component_root(file.relative_path) == root_path
        )
        if any(
            files_by_path[path].component_id != component_id
            for path in (*manifest_paths, *lockfile_paths)
        ):
            raise SourceComponentCorrelationError
        components.append(
            RepositoryComponent(
                component_id=component_id,
                display_name=_component_display_name(root_path),
                root_path=root_path,
                manifest_paths=manifest_paths,
                lockfile_paths=lockfile_paths,
            )
        )

    return ComponentizedRepositoryInventory(
        repository_digest=inventory.repository_digest,
        files=tuple(enriched_files),
        components=tuple(
            sorted(
                components,
                key=lambda component: component.component_id,
            )
        ),
    )
