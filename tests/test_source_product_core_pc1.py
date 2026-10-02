from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest
from sqlalchemy import inspect, select

from securescan.domain.enums import ArtifactKind, ExecutionOutcome, JobStatus
from securescan.evidence import SecureScanEvidenceReport
from securescan.orchestration.assembly import SourceResultAssemblyService
from securescan.orchestration.coordinator import SourceOrchestrationCoordinatorService
from securescan.orchestration.execution import SourceScannerAttemptService
from securescan.orchestration.execution_models import (
    AttemptContainmentOutcome,
    SourceSandboxCleanupReceipt,
    source_sandbox_execution_identity,
)
from securescan.orchestration.models import (
    OrchestrationLifecycleState,
    SourceAuthority,
    frozen_source_v1_authority_roster,
    orchestration_request_digest,
)
from securescan.persistence.database import (
    AnalysisRunRow,
    JobRow,
    SourceFindingOccurrenceRow,
    SourceLineageRunRow,
    SourceOrchestrationRow,
    SourceTargetLineageRow,
    TargetRow,
    ToolExecutionRow,
)
from securescan.product_core import ProductCoreIndexError, SourceFindingIndexService
from securescan.product_core.interoperability import SourceInteroperabilityService
from securescan.product_core.verified_read import (
    VerifiedPublishedRunError,
    VerifiedPublishedRunGateway,
)
from tests.test_source_engine_closure import _with_controlled_finding
from tests.test_source_orchestration_s6b import (
    _CONTROLLED_SECRET,
    _DEADLINE,
    _LEASE_TOKEN,
    _NOW,
    _RUN_ID,
    _Environment,
)

_INDEXED_AT = datetime(2026, 9, 1, tzinfo=UTC)
_LINEAGE_IDS = (
    UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1"),
    UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2"),
)


def _publish_environment(environment: _Environment) -> None:
    with environment.factory.begin() as session:
        parent = session.get(SourceOrchestrationRow, str(_RUN_ID))
        run = session.get(AnalysisRunRow, str(_RUN_ID))
        assert parent is not None and run is not None
        parent.deadline_at = datetime(2099, 1, 1, tzinfo=UTC)
        parent.creation_request_digest = orchestration_request_digest(
            target_id=run.target_id,
            idempotency_key=parent.idempotency_key,
            deadline_iso=parent.deadline_at.isoformat(),
            profile_digest=parent.profile_digest,
            plan_digest=parent.plan_digest,
            roster_digest=parent.roster_digest,
        )
    tokens = iter(
        UUID(f"bbbbbbbb-bbbb-4bbb-8bbb-{value:012d}") for value in range(1, 10)
    )
    environment.attempts = SourceScannerAttemptService(
        environment.factory,
        environment.store,
        environment.projections,
        clock=lambda: _NOW,
        token_factory=lambda: next(tokens),
    )
    for authority in (
        SourceAuthority.GITLEAKS,
        SourceAuthority.SYFT,
        SourceAuthority.CHECKOV,
        SourceAuthority.SEMGREP,
    ):
        if authority is SourceAuthority.SEMGREP:
            node, job = environment.create(authority)
            with environment.factory.begin() as session:
                durable_job = session.get(JobRow, job.job_id)
                assert durable_job is not None
                durable_job.status = JobStatus.RUNNING.value
                durable_job.attempt_count = 1
                durable_job.leased_by = "worker-pc1"
                durable_job.lease_token = _LEASE_TOKEN
                durable_job.lease_expires_at = _DEADLINE
                durable_job.started_at = _NOW
            attempt = environment.attempts.register_attempt(
                job_id=job.job_id,
                worker_id="worker-pc1",
                lease_token=_LEASE_TOKEN,
            )
            environment.attempts.record_sandbox_cleanup(
                SourceSandboxCleanupReceipt(
                    job_id=job.job_id,
                    attempt_number=attempt.attempt_number,
                    attempt_token=attempt.attempt_token,
                    execution_backend="docker-sandbox",
                    execution_id=job.job_id,
                    sandbox_identity=source_sandbox_execution_identity(
                        job.job_id, attempt.attempt_number, attempt.attempt_token
                    ),
                    cleanup_outcome=AttemptContainmentOutcome.CLEAN,
                    execution_removed=True,
                )
            )
        else:
            node, job, _attempt = environment.start_attempt(authority)
        native = environment.native_result(node, job)
        if authority is SourceAuthority.GITLEAKS:
            native = _with_controlled_finding(native, authority)
        environment.attempts.accept_result(
            native,
            lease_token=_LEASE_TOKEN,
            execution_outcome=(
                ExecutionOutcome.SUCCEEDED_WITH_OBSERVATIONS
                if authority is SourceAuthority.GITLEAKS
                else ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS
            ),
            return_code=1 if authority is SourceAuthority.GITLEAKS else 0,
            duration_ms=1,
        )
    coordinator = SourceOrchestrationCoordinatorService(
        environment.factory,
        environment.store,
        frozen_source_v1_authority_roster(),
        environment.projections,
    )
    assert coordinator.advance(run_id=str(_RUN_ID)).lifecycle_state is (
        OrchestrationLifecycleState.ASSEMBLY_READY
    )
    SourceResultAssemblyService(
        environment.factory, environment.store, clock=lambda: _INDEXED_AT
    ).assemble_and_publish(str(_RUN_ID))


@pytest.fixture
def published_environment(tmp_path: Path):
    environment = _Environment(tmp_path)
    _publish_environment(environment)
    try:
        yield environment
    finally:
        environment.close()


@pytest.fixture
def indexed_context(published_environment: _Environment):
    ids = iter(_LINEAGE_IDS)
    service = SourceFindingIndexService(
        published_environment.factory,
        published_environment.store,
        clock=lambda: _INDEXED_AT,
        lineage_id_factory=lambda: next(ids),
    )
    with published_environment.factory() as session:
        run = session.get(AnalysisRunRow, str(_RUN_ID))
        assert run is not None
        target = session.get(TargetRow, run.target_id)
        assert target is not None
        project_id = target.project_id
    lineage = service.create_lineage(project_id=project_id)
    return published_environment, service, lineage


def test_lineage_creation_is_explicit_and_server_owned(indexed_context) -> None:
    environment, _service, lineage = indexed_context
    with environment.factory() as session:
        row = session.get(SourceTargetLineageRow, lineage.lineage_id)
        assert row is not None
        assert row.project_id == lineage.project_id
    assert lineage.lineage_id == str(_LINEAGE_IDS[0])
    assert lineage.created is True


def test_verified_read_gateway_rejects_wrong_scope_and_published_json_tampering(
    published_environment: _Environment,
) -> None:
    gateway = VerifiedPublishedRunGateway(
        published_environment.factory, published_environment.store
    )
    trusted = gateway.load(run_id=str(_RUN_ID))
    assert trusted.run_id == str(_RUN_ID)
    with pytest.raises(VerifiedPublishedRunError):
        gateway.load(
            run_id=str(_RUN_ID),
            expected_project_id="ffffffff-ffff-4fff-8fff-ffffffffffff",
        )

    with published_environment.factory.begin() as session:
        row = session.get(AnalysisRunRow, str(_RUN_ID))
        assert row is not None and row.report_json is not None
        row.report_json = {**row.report_json, "tampered": True}
    with pytest.raises(VerifiedPublishedRunError):
        gateway.load(run_id=str(_RUN_ID))


def test_interoperability_exports_use_real_verified_planning_and_execution_facts(
    published_environment: _Environment,
) -> None:
    service = SourceInteroperabilityService(
        published_environment.factory, published_environment.store
    )
    cyclonedx = service.cyclonedx(run_id=str(_RUN_ID))
    manifest = service.toolchain_manifest(run_id=str(_RUN_ID))
    assert cyclonedx["bomFormat"] == "CycloneDX"
    assert cyclonedx["specVersion"] == "1.7"
    assert manifest["run_id"] == str(_RUN_ID)
    assert manifest["planned_authorities"]
    assert manifest["planned_nodes"]
    assert all("selected_paths" not in node for node in manifest["planned_nodes"])


def test_toolchain_manifest_ignores_unaccepted_poison_execution_row(
    published_environment: _Environment,
) -> None:
    service = SourceInteroperabilityService(
        published_environment.factory, published_environment.store
    )
    before = service.toolchain_manifest(run_id=str(_RUN_ID))
    with published_environment.factory.begin() as session:
        session.add(
            ToolExecutionRow(
                run_id=str(_RUN_ID),
                job_id=None,
                attempt_number=None,
                adapter_id="untrusted-poison",
                tool_version="999",
                adapter_version="999",
                outcome="SUCCEEDED_NO_OBSERVATIONS",
                exit_code=0,
                duration_ms=1,
                warning_json=[],
            )
        )
    assert service.toolchain_manifest(run_id=str(_RUN_ID)) == before


def test_attach_sequence_one_and_exact_duplicate_are_idempotent(indexed_context) -> None:
    _environment, service, lineage = indexed_context
    first = service.attach_published_run(
        lineage_id=lineage.lineage_id,
        run_id=str(_RUN_ID),
        expected_predecessor_run_id=None,
    )
    duplicate = service.attach_published_run(
        lineage_id=lineage.lineage_id,
        run_id=str(_RUN_ID),
        expected_predecessor_run_id=None,
    )
    assert first.sequence_number == 1
    assert first.predecessor_run_id is None
    assert first.created is True
    assert replace(first, created=False) == duplicate


def _clone_published_run(
    environment: _Environment, report: SecureScanEvidenceReport, run_id: str
) -> SecureScanEvidenceReport:
    cloned = replace(report, scope=replace(report.scope, source_run_id=run_id))
    artifact = environment.store.put(
        cloned.canonical_json(),
        kind=ArtifactKind.SOURCE_FINAL_RESULT,
        media_type="application/vnd.securescan.source-result+json",
        sanitized=True,
    )
    with environment.factory.begin() as session:
        original_run = session.get(AnalysisRunRow, str(_RUN_ID))
        original_parent = session.get(SourceOrchestrationRow, str(_RUN_ID))
        assert original_run is not None and original_parent is not None
        session.add(
            AnalysisRunRow(
                id=run_id,
                target_id=original_run.target_id,
                status=original_run.status,
                report_json=cloned.canonical_data(),
                created_at=original_run.created_at,
            )
        )
        values = {
            column.name: getattr(original_parent, column.name)
            for column in SourceOrchestrationRow.__table__.columns
            if column.name != "run_id"
        }
        values.update(
            idempotency_key=run_id.replace("-", "").ljust(64, "0")[:64],
            creation_request_digest="c" * 64,
            assembly_artifact_sha256=artifact.sha256,
            assembly_artifact_size_bytes=artifact.size_bytes,
            assembly_artifact_storage_path=artifact.storage_path,
        )
        session.add(SourceOrchestrationRow(run_id=run_id, **values))
    return cloned


def test_sequence_two_uses_locked_tail_as_predecessor(indexed_context, monkeypatch) -> None:
    environment, service, lineage = indexed_context
    first = service.attach_published_run(
        lineage_id=lineage.lineage_id, run_id=str(_RUN_ID)
    )
    report = service._rebuild_trusted_report(str(_RUN_ID))
    second_run_id = "22222222-2222-4222-8222-222222222222"
    second_report = _clone_published_run(environment, report, second_run_id)
    reports = {str(_RUN_ID): report, second_run_id: second_report}
    monkeypatch.setattr(service, "_rebuild_trusted_report", reports.__getitem__)
    second = service.attach_published_run(
        lineage_id=lineage.lineage_id,
        run_id=second_run_id,
        expected_predecessor_run_id=str(_RUN_ID),
    )
    assert (first.sequence_number, second.sequence_number) == (1, 2)
    assert second.predecessor_run_id == str(_RUN_ID)


def test_wrong_or_conflicting_lineage_membership_is_rejected(indexed_context) -> None:
    _environment, service, lineage = indexed_context
    service.attach_published_run(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))
    other = service.create_lineage(project_id=lineage.project_id)
    with pytest.raises(ProductCoreIndexError):
        service.attach_published_run(lineage_id=other.lineage_id, run_id=str(_RUN_ID))
    with pytest.raises(ProductCoreIndexError):
        service.attach_published_run(
            lineage_id=lineage.lineage_id,
            run_id=str(_RUN_ID),
            expected_predecessor_run_id="33333333-3333-4333-8333-333333333333",
        )


def test_predecessor_from_another_lineage_is_rejected(indexed_context, monkeypatch) -> None:
    environment, service, lineage = indexed_context
    service.attach_published_run(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))
    other = service.create_lineage(project_id=lineage.project_id)
    report = service._rebuild_trusted_report(str(_RUN_ID))
    second_run_id = "22222222-2222-4222-8222-222222222222"
    second_report = _clone_published_run(environment, report, second_run_id)
    monkeypatch.setattr(
        service,
        "_rebuild_trusted_report",
        {second_run_id: second_report}.__getitem__,
    )
    with pytest.raises(ProductCoreIndexError):
        service.attach_published_run(
            lineage_id=other.lineage_id,
            run_id=second_run_id,
            expected_predecessor_run_id=str(_RUN_ID),
        )


@pytest.mark.parametrize("mutation", ["cancelled", "unpublished"])
def test_cancelled_or_unpublished_run_cannot_attach(indexed_context, mutation: str) -> None:
    environment, service, lineage = indexed_context
    with environment.factory.begin() as session:
        parent = session.get(SourceOrchestrationRow, str(_RUN_ID))
        assert parent is not None
        if mutation == "cancelled":
            parent.cancel_requested = True
            parent.cancel_requested_at = _INDEXED_AT
        else:
            parent.published_at = None
    with pytest.raises(ProductCoreIndexError):
        service.attach_published_run(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))


def test_published_engine_closure_report_indexes_exact_s4_findings(indexed_context) -> None:
    _environment, service, lineage = indexed_context
    report = service._rebuild_trusted_report(str(_RUN_ID))
    attached = service.attach_published_run(
        lineage_id=lineage.lineage_id, run_id=str(_RUN_ID)
    )
    indexed = service.index_attached_run(
        lineage_id=lineage.lineage_id, run_id=str(_RUN_ID)
    )
    occurrences = service.list_indexed_occurrences(
        lineage_id=lineage.lineage_id, run_id=str(_RUN_ID)
    )
    assert attached.indexing_state == "ATTACHED"
    assert indexed.indexing_state == "INDEXED"
    assert indexed.indexed_at == _INDEXED_AT
    assert len(occurrences) == len(report.findings) == 1
    assert tuple(item.finding_id for item in occurrences) == tuple(
        item.finding_id for item in report.findings
    )


def test_duplicate_indexing_converges_and_occurrence_drift_fails_closed(
    indexed_context,
) -> None:
    environment, service, lineage = indexed_context
    service.attach_published_run(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))
    first = service.index_attached_run(
        lineage_id=lineage.lineage_id, run_id=str(_RUN_ID)
    )
    duplicate = service.index_attached_run(
        lineage_id=lineage.lineage_id, run_id=str(_RUN_ID)
    )
    assert first.created is True
    assert replace(first, created=False) == duplicate
    with environment.factory.begin() as session:
        occurrence = session.scalar(select(SourceFindingOccurrenceRow))
        assert occurrence is not None
        occurrence.native_identity_schema = "tampered-schema"
    with pytest.raises(ProductCoreIndexError):
        service.index_attached_run(
            lineage_id=lineage.lineage_id, run_id=str(_RUN_ID)
        )


def test_cas_tampering_and_report_json_mismatch_fail_closed(indexed_context) -> None:
    environment, service, lineage = indexed_context
    with environment.factory() as session:
        parent = session.get(SourceOrchestrationRow, str(_RUN_ID))
        assert parent is not None and parent.assembly_artifact_storage_path is not None
        artifact_path = environment.store.root / parent.assembly_artifact_storage_path
    original = artifact_path.read_bytes()
    artifact_path.write_bytes(original + b"tamper")
    with pytest.raises(ProductCoreIndexError):
        service.attach_published_run(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))


def test_report_json_cas_mismatch_fails_closed(indexed_context) -> None:
    environment, service, lineage = indexed_context
    with environment.factory.begin() as session:
        run = session.get(AnalysisRunRow, str(_RUN_ID))
        assert run is not None and run.report_json is not None
        document = dict(run.report_json)
        document["findings"] = []
        run.report_json = document
    with pytest.raises(ProductCoreIndexError):
        service.attach_published_run(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))


def test_duplicate_s4_finding_id_is_rejected(indexed_context) -> None:
    _environment, service, _lineage = indexed_context
    report = service._rebuild_trusted_report(str(_RUN_ID))
    duplicate = SimpleNamespace(findings=(report.findings[0], report.findings[0]))
    with pytest.raises(ProductCoreIndexError):
        service._occurrence_material(duplicate)


def test_index_contains_only_query_safe_summaries(indexed_context) -> None:
    environment, service, lineage = indexed_context
    service.attach_published_run(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))
    service.index_attached_run(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))
    occurrences = service.list_indexed_occurrences(
        lineage_id=lineage.lineage_id, run_id=str(_RUN_ID)
    )
    rendered = json.dumps(
        [
            {
                "authority": item.authority,
                "category": item.category,
                "location": dict(item.primary_location or {}),
                "subject": dict(item.subject_summary),
            }
            for item in occurrences
        ],
        sort_keys=True,
    )
    forbidden = {
        "evidence_json",
        "component_json",
        "native_output",
        "stdout_bytes",
        "stderr_bytes",
        "source_snippet",
    }
    columns = {
        column["name"]
        for column in inspect(environment.engine).get_columns(
            "source_finding_occurrences"
        )
    }
    assert forbidden.isdisjoint(columns)
    assert _CONTROLLED_SECRET.decode() not in rendered
    assert "/not-persisted-in-native-result" not in rendered
    assert "scanner stdout sentinel" not in rendered
    assert "raw osv http sentinel" not in rendered


def test_index_failure_rolls_back_all_occurrences(indexed_context, monkeypatch) -> None:
    environment, service, lineage = indexed_context
    service.attach_published_run(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))

    original = service._occurrence_material

    def invalid_material(report):
        material = original(report)
        return (replace(material[0], finding_ordinal=-1),)

    monkeypatch.setattr(service, "_occurrence_material", invalid_material)
    with pytest.raises(ProductCoreIndexError):
        service.index_attached_run(
            lineage_id=lineage.lineage_id, run_id=str(_RUN_ID)
        )
    with environment.factory() as session:
        membership = session.get(SourceLineageRunRow, str(_RUN_ID))
        assert membership is not None
        assert membership.indexing_state == "ATTACHED"
        assert tuple(session.scalars(select(SourceFindingOccurrenceRow))) == ()
