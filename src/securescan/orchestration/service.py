from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import PurePosixPath
from uuid import UUID, uuid4

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.domain.enums import ArtifactKind, RunStatus, TargetType
from securescan.persistence.database import (
    AnalysisRunRow,
    SourceOrchestrationAuthorityRow,
    SourceOrchestrationDependencyRow,
    SourceOrchestrationNodeRow,
    SourceOrchestrationRow,
    TargetRow,
    utc_now,
)
from securescan.source.models import RepositoryProfile
from securescan.source.planning import SourceAnalysisPlan

from .models import (
    PLANNING_SNAPSHOT_MEDIA_TYPE,
    PLANNING_SNAPSHOT_SCHEMA_VERSION,
    OrchestrationContainmentState,
    OrchestrationLifecycleState,
    OrchestrationNodeDisposition,
    OrchestrationNodeLifecycleState,
    OrchestrationTerminalOutcome,
    SourceOrchestrationIntegrityError,
    SourcePlanningSnapshot,
    TrustedSourceAuthorityRoster,
    orchestration_request_digest,
)

_IDEMPOTENCY_KEY = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
SOURCE_V1_MAX_ACTIVE_JOBS = 2


class SourceOrchestrationError(RuntimeError):
    pass


class SourceOrchestrationConflictError(SourceOrchestrationError):
    def __init__(self) -> None:
        super().__init__("Source orchestration idempotency conflict")


class SourceOrchestrationNotFoundError(SourceOrchestrationError):
    def __init__(self) -> None:
        super().__init__("Source orchestration was not found")


class SourceOrchestrationStaleVersionError(SourceOrchestrationError):
    def __init__(self) -> None:
        super().__init__("Source orchestration state version is stale")


class SourceOrchestrationStateError(SourceOrchestrationError):
    def __init__(self) -> None:
        super().__init__("Source orchestration transition is invalid")


@dataclass(frozen=True, slots=True)
class SourceOrchestrationCreateRequest:
    target_id: str
    idempotency_key: str
    profile: RepositoryProfile
    plan: SourceAnalysisPlan
    deadline_at: datetime

    def __post_init__(self) -> None:
        try:
            valid_target = str(UUID(self.target_id)) == self.target_id
        except (AttributeError, TypeError, ValueError):
            valid_target = False
        if (
            not valid_target
            or _IDEMPOTENCY_KEY.fullmatch(self.idempotency_key) is None
            or not isinstance(self.profile, RepositoryProfile)
            or not isinstance(self.plan, SourceAnalysisPlan)
            or not isinstance(self.deadline_at, datetime)
            or self.deadline_at.tzinfo is None
            or self.deadline_at.utcoffset() is None
        ):
            raise SourceOrchestrationIntegrityError("Source orchestration request is invalid")


@dataclass(frozen=True, slots=True)
class SourceOrchestrationRecord:
    run_id: str
    target_id: str
    idempotency_key: str
    lifecycle_state: OrchestrationLifecycleState
    cancel_requested: bool
    state_version: int
    max_active_jobs: int
    deadline_at: datetime
    snapshot: SourcePlanningSnapshot
    planning_snapshot_sha256: str
    roster_digest: str
    created: bool = False


class SourcePlanningSnapshotStore:
    def __init__(self, artifact_store: ContentAddressedArtifactStore) -> None:
        if not isinstance(artifact_store, ContentAddressedArtifactStore):
            raise TypeError("A content-addressed artifact store is required")
        self._store = artifact_store

    def put(self, snapshot: SourcePlanningSnapshot) -> tuple[str, int, str]:
        payload = snapshot.canonical_json()
        artifact = self._store.put(
            payload,
            kind=ArtifactKind.ORCHESTRATION_PLANNING_SNAPSHOT,
            media_type=PLANNING_SNAPSHOT_MEDIA_TYPE,
            sanitized=True,
        )
        expected_path = f"sha256/{artifact.sha256[:2]}/{artifact.sha256}"
        if artifact.storage_path != expected_path:
            raise SourceOrchestrationIntegrityError("Planning snapshot reference is invalid")
        reloaded = self._store.read_by_sha256(
            artifact.sha256,
            expected_size_bytes=artifact.size_bytes,
        )
        if reloaded != payload or SourcePlanningSnapshot.from_json(reloaded) != snapshot:
            raise SourceOrchestrationIntegrityError("Planning snapshot could not be verified")
        return artifact.sha256, artifact.size_bytes, artifact.storage_path

    def read(self, sha256: str, size_bytes: int, storage_path: str) -> SourcePlanningSnapshot:
        if not isinstance(sha256, str) or not isinstance(storage_path, str):
            raise SourceOrchestrationIntegrityError("Planning snapshot reference is invalid")
        expected_path = f"sha256/{sha256[:2]}/{sha256}"
        path = PurePosixPath(storage_path)
        if (
            _SHA256.fullmatch(sha256) is None
            or type(size_bytes) is not int
            or size_bytes < 1
            or storage_path != expected_path
            or path.is_absolute()
            or ".." in path.parts
        ):
            raise SourceOrchestrationIntegrityError("Planning snapshot reference is invalid")
        try:
            payload = self._store.read_by_sha256(
                sha256,
                expected_size_bytes=size_bytes,
            )
            snapshot = SourcePlanningSnapshot.from_json(payload)
        except (OSError, ValueError, SourceOrchestrationIntegrityError):
            raise SourceOrchestrationIntegrityError("Planning snapshot is unavailable") from None
        if snapshot.snapshot_digest() != sha256:
            raise SourceOrchestrationIntegrityError("Planning snapshot digest is invalid")
        return snapshot


class SourceOrchestrationService:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        artifact_store: ContentAddressedArtifactStore,
        trusted_roster: TrustedSourceAuthorityRoster,
        *,
        clock: Callable[[], datetime] = utc_now,
        run_id_factory: Callable[[], UUID] = uuid4,
        max_active_jobs: int = SOURCE_V1_MAX_ACTIVE_JOBS,
    ) -> None:
        if not isinstance(trusted_roster, TrustedSourceAuthorityRoster):
            raise SourceOrchestrationIntegrityError("Trusted roster is invalid")
        if type(max_active_jobs) is not int or not 1 <= max_active_jobs <= 4:
            raise SourceOrchestrationIntegrityError(
                "Source orchestration concurrency configuration is invalid"
            )
        self._session_factory = session_factory
        self._snapshots = SourcePlanningSnapshotStore(artifact_store)
        self._trusted_roster = trusted_roster
        self._clock = clock
        self._run_id_factory = run_id_factory
        self._max_active_jobs = max_active_jobs

    def create(self, request: SourceOrchestrationCreateRequest) -> SourceOrchestrationRecord:
        if not isinstance(request, SourceOrchestrationCreateRequest):
            raise SourceOrchestrationIntegrityError("Source orchestration request is invalid")
        profile_digest = request.profile.profile_digest()
        plan_digest = request.plan.plan_digest()
        roster_digest = self._trusted_roster.roster_digest()
        deadline = request.deadline_at.astimezone(UTC)
        request_digest = orchestration_request_digest(
            target_id=request.target_id,
            idempotency_key=request.idempotency_key,
            deadline_iso=deadline.isoformat(),
            profile_digest=profile_digest,
            plan_digest=plan_digest,
            roster_digest=roster_digest,
        )
        try:
            with self._session_factory.begin() as session:
                existing = session.scalar(
                    select(SourceOrchestrationRow)
                    .where(SourceOrchestrationRow.idempotency_key == request.idempotency_key)
                    .with_for_update()
                )
                if existing is not None:
                    if existing.creation_request_digest != request_digest:
                        raise SourceOrchestrationConflictError
                    return self._load_from_session(session, existing, created=False)

                target = session.get(TargetRow, request.target_id)
                if (
                    target is None
                    or target.target_type != TargetType.SOURCE_REPOSITORY.value
                    or target.content_digest != request.profile.repository_digest
                ):
                    raise SourceOrchestrationIntegrityError("Source target is invalid")
                run_id = str(self._run_id_factory())
                snapshot = SourcePlanningSnapshot.create(
                    run_id, request.profile, request.plan, self._trusted_roster
                )
                snapshot_sha, snapshot_size, storage_path = self._snapshots.put(snapshot)
                now = self._clock()
                if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
                    raise SourceOrchestrationIntegrityError("Orchestration clock is invalid")
                now = now.astimezone(UTC)
                session.add(
                    AnalysisRunRow(
                        id=run_id,
                        target_id=request.target_id,
                        status=RunStatus.QUEUED.value,
                        report_json=None,
                        created_at=now,
                    )
                )
                row = SourceOrchestrationRow(
                    run_id=run_id,
                    idempotency_key=request.idempotency_key,
                    creation_request_digest=request_digest,
                    repository_digest=request.profile.repository_digest,
                    profile_digest=profile_digest,
                    plan_digest=plan_digest,
                    roster_digest=roster_digest,
                    planning_snapshot_sha256=snapshot_sha,
                    snapshot_size_bytes=snapshot_size,
                    snapshot_media_type=PLANNING_SNAPSHOT_MEDIA_TYPE,
                    snapshot_schema_version=PLANNING_SNAPSHOT_SCHEMA_VERSION,
                    snapshot_storage_path=storage_path,
                    lifecycle_state=OrchestrationLifecycleState.PREPARED.value,
                    terminal_outcome=None,
                    cancel_requested=False,
                    cancel_requested_at=None,
                    state_version=1,
                    max_active_jobs=self._max_active_jobs,
                    deadline_at=deadline,
                    created_at=now,
                    updated_at=now,
                )
                session.add(row)
                session.flush()
                for authority in self._trusted_roster.authorities:
                    session.add(
                        SourceOrchestrationAuthorityRow(
                            run_id=run_id,
                            authority=authority.authority.value,
                            capability=authority.capability.value,
                            analyzer_id=authority.analyzer_id,
                            contract_kind=authority.contract_kind,
                            contract_digest=authority.contract_digest,
                            implementation_version=authority.implementation_version,
                        )
                    )
                session.flush()
                for node in snapshot.nodes:
                    session.add(
                        SourceOrchestrationNodeRow(
                            node_id=node.node_id,
                            run_id=run_id,
                            authority=node.authority.value,
                            capability=node.capability.value,
                            component_id=node.component_id,
                            component_key=node.component_id or "",
                            analyzer_id=node.analyzer_id,
                            contract_digest=node.contract_digest,
                            plan_entry_keys_json=list(node.plan_entry_keys),
                            selected_paths_json=list(node.selected_paths),
                            scope_digest=node.scope_digest,
                            lifecycle_state=node.initial_state.value,
                            terminal_disposition=None,
                            terminal_reason_code=None,
                            containment_state=OrchestrationContainmentState.NOT_STARTED.value,
                            state_version=1,
                        )
                    )
                session.flush()
                for dependency in snapshot.dependencies:
                    session.add(
                        SourceOrchestrationDependencyRow(
                            run_id=run_id,
                            node_id=dependency.node_id,
                            prerequisite_node_id=dependency.prerequisite_node_id,
                        )
                    )
                session.flush()
                return self._load_from_session(session, row, created=True)
        except (SourceOrchestrationError, SourceOrchestrationIntegrityError):
            raise
        except (TypeError, ValueError):
            raise SourceOrchestrationIntegrityError from None
        except IntegrityError:
            return self._resolve_create_race(request.idempotency_key, request_digest)
        except SQLAlchemyError:
            raise SourceOrchestrationError("Source orchestration creation failed") from None

    def _resolve_create_race(
        self, idempotency_key: str, request_digest: str
    ) -> SourceOrchestrationRecord:
        try:
            with self._session_factory() as session:
                row = session.scalar(
                    select(SourceOrchestrationRow).where(
                        SourceOrchestrationRow.idempotency_key == idempotency_key
                    )
                )
                if row is None:
                    raise SourceOrchestrationError("Source orchestration creation failed")
                if row.creation_request_digest != request_digest:
                    raise SourceOrchestrationConflictError
                return self._load_from_session(session, row, created=False)
        except SourceOrchestrationError:
            raise
        except (TypeError, ValueError):
            raise SourceOrchestrationIntegrityError from None
        except SQLAlchemyError:
            raise SourceOrchestrationError("Source orchestration creation failed") from None

    def load(self, run_id: str) -> SourceOrchestrationRecord:
        try:
            with self._session_factory() as session:
                row = session.get(SourceOrchestrationRow, run_id)
                if row is None:
                    raise SourceOrchestrationNotFoundError
                return self._load_from_session(session, row, created=False)
        except (SourceOrchestrationError, SourceOrchestrationIntegrityError):
            raise
        except (TypeError, ValueError):
            raise SourceOrchestrationIntegrityError from None
        except SQLAlchemyError:
            raise SourceOrchestrationError("Source orchestration load failed") from None

    def activate(self, run_id: str, expected_state_version: int) -> SourceOrchestrationRecord:
        return self._transition(
            run_id,
            expected_state_version,
            expected_state=OrchestrationLifecycleState.PREPARED,
            target_state=OrchestrationLifecycleState.ACTIVE,
            cancel=False,
        )

    def request_cancellation(
        self, run_id: str, expected_state_version: int
    ) -> SourceOrchestrationRecord:
        return self._transition(
            run_id,
            expected_state_version,
            expected_state=None,
            target_state=OrchestrationLifecycleState.CANCELLATION_REQUESTED,
            cancel=True,
        )

    def _transition(
        self,
        run_id: str,
        expected_state_version: int,
        *,
        expected_state: OrchestrationLifecycleState | None,
        target_state: OrchestrationLifecycleState,
        cancel: bool,
    ) -> SourceOrchestrationRecord:
        if type(expected_state_version) is not int or expected_state_version < 1:
            raise SourceOrchestrationStaleVersionError
        try:
            with self._session_factory.begin() as session:
                row = session.scalar(
                    select(SourceOrchestrationRow)
                    .where(SourceOrchestrationRow.run_id == run_id)
                    .with_for_update()
                )
                if row is None:
                    raise SourceOrchestrationNotFoundError
                self._load_from_session(session, row, created=False)
                if row.state_version != expected_state_version:
                    raise SourceOrchestrationStaleVersionError
                current = OrchestrationLifecycleState(row.lifecycle_state)
                if (
                    current is OrchestrationLifecycleState.TERMINAL
                    or current is OrchestrationLifecycleState.CANCELLATION_REQUESTED
                    or (expected_state is not None and current is not expected_state)
                ):
                    raise SourceOrchestrationStateError
                now = self._clock()
                if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
                    raise SourceOrchestrationIntegrityError("Orchestration clock is invalid")
                now = now.astimezone(UTC)
                values: dict[str, object] = {
                    "lifecycle_state": target_state.value,
                    "state_version": expected_state_version + 1,
                    "updated_at": now,
                }
                if cancel:
                    values.update(cancel_requested=True, cancel_requested_at=now)
                changed = session.execute(
                    update(SourceOrchestrationRow)
                    .where(
                        SourceOrchestrationRow.run_id == run_id,
                        SourceOrchestrationRow.state_version == expected_state_version,
                    )
                    .values(**values)
                )
                if changed.rowcount != 1:
                    raise SourceOrchestrationStaleVersionError
                session.expire(row)
                return self._load_from_session(session, row, created=False)
        except (SourceOrchestrationError, SourceOrchestrationIntegrityError):
            raise
        except (TypeError, ValueError):
            raise SourceOrchestrationIntegrityError from None
        except SQLAlchemyError:
            raise SourceOrchestrationError("Source orchestration transition failed") from None

    def _load_from_session(
        self, session: Session, row: SourceOrchestrationRow, *, created: bool
    ) -> SourceOrchestrationRecord:
        snapshot = self._snapshots.read(
            row.planning_snapshot_sha256,
            row.snapshot_size_bytes,
            row.snapshot_storage_path,
        )
        if (
            snapshot.run_id != row.run_id
            or snapshot.profile.repository_digest != row.repository_digest
            or snapshot.profile.profile_digest() != row.profile_digest
            or snapshot.plan.plan_digest() != row.plan_digest
            or snapshot.roster.roster_digest() != row.roster_digest
            or snapshot.roster != self._trusted_roster
            or row.snapshot_media_type != PLANNING_SNAPSHOT_MEDIA_TYPE
            or row.snapshot_schema_version != PLANNING_SNAPSHOT_SCHEMA_VERSION
        ):
            raise SourceOrchestrationIntegrityError("Durable orchestration identity is invalid")
        authorities = tuple(
            session.scalars(
                select(SourceOrchestrationAuthorityRow)
                .where(SourceOrchestrationAuthorityRow.run_id == row.run_id)
                .order_by(SourceOrchestrationAuthorityRow.authority)
            )
        )
        if tuple(
            {
                "analyzer_id": item.analyzer_id,
                "authority": item.authority,
                "capability": item.capability,
                "contract_digest": item.contract_digest,
                "contract_kind": item.contract_kind,
                "implementation_version": item.implementation_version,
            }
            for item in authorities
        ) != tuple(item.canonical_data() for item in self._trusted_roster.authorities):
            raise SourceOrchestrationIntegrityError("Durable authority roster is invalid")
        nodes = tuple(
            session.scalars(
                select(SourceOrchestrationNodeRow)
                .where(SourceOrchestrationNodeRow.run_id == row.run_id)
                .order_by(SourceOrchestrationNodeRow.node_id)
            )
        )
        expected_nodes = {item.node_id: item for item in snapshot.nodes}
        if len(nodes) != len(expected_nodes):
            raise SourceOrchestrationIntegrityError("Durable node topology is invalid")
        for node in nodes:
            expected = expected_nodes.get(node.node_id)
            if (
                expected is None
                or node.authority != expected.authority.value
                or node.capability != expected.capability.value
                or node.component_id != expected.component_id
                or node.component_key != (expected.component_id or "")
                or node.analyzer_id != expected.analyzer_id
                or node.contract_digest != expected.contract_digest
                or node.plan_entry_keys_json != list(expected.plan_entry_keys)
                or node.selected_paths_json != list(expected.selected_paths)
                or node.scope_digest != expected.scope_digest
                or node.state_version < 1
            ):
                raise SourceOrchestrationIntegrityError("Durable node scope is invalid")
            lifecycle = OrchestrationNodeLifecycleState(node.lifecycle_state)
            disposition = (
                None
                if node.terminal_disposition is None
                else OrchestrationNodeDisposition(node.terminal_disposition)
            )
            if (lifecycle is OrchestrationNodeLifecycleState.TERMINAL) != (disposition is not None):
                raise SourceOrchestrationIntegrityError("Durable node state is invalid")
            OrchestrationContainmentState(node.containment_state)
        dependencies = tuple(
            (item.node_id, item.prerequisite_node_id)
            for item in session.scalars(
                select(SourceOrchestrationDependencyRow)
                .where(SourceOrchestrationDependencyRow.run_id == row.run_id)
                .order_by(
                    SourceOrchestrationDependencyRow.node_id,
                    SourceOrchestrationDependencyRow.prerequisite_node_id,
                )
            )
        )
        if dependencies != tuple(
            (item.node_id, item.prerequisite_node_id) for item in snapshot.dependencies
        ):
            raise SourceOrchestrationIntegrityError("Durable dependency topology is invalid")
        run = session.get(AnalysisRunRow, row.run_id)
        target = None if run is None else session.get(TargetRow, run.target_id)
        if (
            run is None
            or target is None
            or target.target_type != TargetType.SOURCE_REPOSITORY.value
            or target.content_digest != row.repository_digest
        ):
            raise SourceOrchestrationIntegrityError("Source orchestration run is invalid")
        lifecycle_state = OrchestrationLifecycleState(row.lifecycle_state)
        terminal_outcome = row.terminal_outcome
        if terminal_outcome is not None:
            OrchestrationTerminalOutcome(terminal_outcome)
        assembly_values = (
            row.assembly_artifact_sha256,
            row.assembly_artifact_size_bytes,
            row.assembly_artifact_media_type,
            row.assembly_schema_version,
            row.assembly_artifact_storage_path,
            row.assembled_at,
        )
        has_assembly = all(value is not None for value in assembly_values)
        published = row.published_at is not None
        expected_published_status = {
            OrchestrationTerminalOutcome.COMPLETED.value: RunStatus.COMPLETED.value,
            OrchestrationTerminalOutcome.PARTIAL.value: RunStatus.PARTIAL.value,
            OrchestrationTerminalOutcome.FAILED.value: RunStatus.FAILED.value,
        }
        if (
            row.state_version < 1
            or type(row.max_active_jobs) is not int
            or not 1 <= row.max_active_jobs <= 4
            or type(row.cancel_requested) is not bool
            or (any(value is not None for value in assembly_values) and not has_assembly)
            or (run.report_json is not None) != published
            or published
            and (
                not has_assembly
                or lifecycle_state is not OrchestrationLifecycleState.TERMINAL
                or terminal_outcome not in expected_published_status
                or run.status != expected_published_status[terminal_outcome]
            )
            or (
                terminal_outcome == OrchestrationTerminalOutcome.CANCELLED.value
                and (published or has_assembly or run.report_json is not None)
            )
            or (lifecycle_state is OrchestrationLifecycleState.TERMINAL)
            != (terminal_outcome is not None)
            or (
                row.cancel_requested
                and lifecycle_state
                not in {
                    OrchestrationLifecycleState.CANCELLATION_REQUESTED,
                    OrchestrationLifecycleState.TERMINAL,
                }
            )
            or (
                lifecycle_state is OrchestrationLifecycleState.CANCELLATION_REQUESTED
                and not row.cancel_requested
            )
        ):
            raise SourceOrchestrationIntegrityError("Durable orchestration state is invalid")
        deadline = row.deadline_at
        if not isinstance(deadline, datetime):
            raise SourceOrchestrationIntegrityError("Durable orchestration state is invalid")
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=UTC)
        else:
            deadline = deadline.astimezone(UTC)
        if (
            _IDEMPOTENCY_KEY.fullmatch(row.idempotency_key) is None
            or any(
                _SHA256.fullmatch(value) is None
                for value in (
                    row.creation_request_digest,
                    row.repository_digest,
                    row.profile_digest,
                    row.plan_digest,
                    row.roster_digest,
                    row.planning_snapshot_sha256,
                )
            )
            or row.creation_request_digest
            != orchestration_request_digest(
                target_id=run.target_id,
                idempotency_key=row.idempotency_key,
                deadline_iso=deadline.isoformat(),
                profile_digest=row.profile_digest,
                plan_digest=row.plan_digest,
                roster_digest=row.roster_digest,
            )
        ):
            raise SourceOrchestrationIntegrityError("Durable orchestration identity is invalid")
        return SourceOrchestrationRecord(
            run_id=row.run_id,
            target_id=run.target_id,
            idempotency_key=row.idempotency_key,
            lifecycle_state=lifecycle_state,
            cancel_requested=row.cancel_requested,
            state_version=row.state_version,
            max_active_jobs=row.max_active_jobs,
            deadline_at=deadline,
            snapshot=snapshot,
            planning_snapshot_sha256=row.planning_snapshot_sha256,
            roster_digest=row.roster_digest,
            created=created,
        )
