from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from securescan.adapters.base import ToolAdapter
from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.domain.enums import ArtifactKind, ExecutionOutcome, RunStatus
from securescan.domain.models import (
    AnalysisGap,
    ScanReport,
    TargetProfile,
    ToolExecutionRecord,
)
from securescan.execution.local_executor import LocalProcessExecutor


class ScanService:
    def __init__(
        self,
        *,
        executor: LocalProcessExecutor,
        artifact_store: ContentAddressedArtifactStore,
    ) -> None:
        self.executor = executor
        self.artifact_store = artifact_store

    def run(
        self,
        adapter: ToolAdapter,
        target: TargetProfile,
        *,
        run_id: UUID | None = None,
        **options: object,
    ) -> ScanReport:
        run_id = run_id or uuid4()
        started_at = datetime.now(UTC)
        observations = []
        artifacts = []
        warnings: list[str] = []
        error: str | None = None
        gaps: list[AnalysisGap] = []

        if not adapter.probe():
            return self._terminal_report(
                run_id,
                target,
                adapter,
                started_at,
                ExecutionOutcome.TOOL_NOT_AVAILABLE,
                "Tool is not available",
            )
        if not adapter.supports(target):
            return self._terminal_report(
                run_id,
                target,
                adapter,
                started_at,
                ExecutionOutcome.UNSUPPORTED_TARGET,
                "Adapter does not support this target",
            )

        plan = adapter.build_plan(target, **options)
        captured = self.executor.execute(plan)
        finished_at = datetime.now(UTC)

        sanitized_stdout = adapter.sanitize(captured.stdout)
        sanitized_stderr = adapter.sanitize(captured.stderr)

        artifacts.append(
            self.artifact_store.put(
                sanitized_stdout,
                kind=ArtifactKind.SANITIZED_NATIVE_REPORT,
                media_type="application/json",
                sanitized=True,
            )
        )
        if sanitized_stderr:
            artifacts.append(
                self.artifact_store.put(
                    sanitized_stderr,
                    kind=ArtifactKind.STDERR,
                    media_type="text/plain",
                    sanitized=True,
                )
            )

        if captured.timed_out:
            outcome = ExecutionOutcome.TIMEOUT
            error = "Tool exceeded its timeout"
        elif captured.output_limit_exceeded:
            outcome = ExecutionOutcome.OUTPUT_LIMIT_EXCEEDED
            error = "Tool exceeded the configured output-size limit"
        else:
            validation = adapter.validate_output(sanitized_stdout)
            warnings.extend(validation.warnings)
            if not validation.valid:
                outcome = ExecutionOutcome.INVALID_OUTPUT
                error = validation.error
            else:
                observations = adapter.parse(sanitized_stdout)
                if warnings:
                    outcome = ExecutionOutcome.SUCCEEDED_WITH_WARNINGS
                elif observations:
                    outcome = ExecutionOutcome.SUCCEEDED_WITH_OBSERVATIONS
                else:
                    outcome = ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS

        if outcome not in {
            ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS,
            ExecutionOutcome.SUCCEEDED_WITH_OBSERVATIONS,
            ExecutionOutcome.SUCCEEDED_WITH_WARNINGS,
        }:
            gaps.append(
                AnalysisGap(
                    code=outcome.value.upper(),
                    message=error or "Analysis did not complete",
                    adapter_id=adapter.adapter_id,
                )
            )

        execution = ToolExecutionRecord(
            run_id=run_id,
            adapter_id=adapter.adapter_id,
            tool_version=adapter.tool_version,
            adapter_version=adapter.adapter_version,
            status=RunStatus.COMPLETED if not gaps else RunStatus.FAILED,
            outcome=outcome,
            exit_code=captured.exit_code,
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=captured.duration_ms,
            warnings=warnings,
            error=error,
            artifacts=artifacts,
            observations=observations,
        )

        report_status = RunStatus.COMPLETED if not gaps else RunStatus.PARTIAL
        return ScanReport(
            run_id=run_id,
            target=target,
            status=report_status,
            executions=[execution],
            observations=observations,
            analysis_gaps=gaps,
        )

    @staticmethod
    def _terminal_report(
        run_id: UUID,
        target: TargetProfile,
        adapter: ToolAdapter,
        started_at: datetime,
        outcome: ExecutionOutcome,
        message: str,
    ) -> ScanReport:
        finished_at = datetime.now(UTC)
        execution = ToolExecutionRecord(
            run_id=run_id,
            adapter_id=adapter.adapter_id,
            tool_version=adapter.tool_version,
            adapter_version=adapter.adapter_version,
            status=RunStatus.FAILED,
            outcome=outcome,
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=0,
            error=message,
        )
        return ScanReport(
            run_id=run_id,
            target=target,
            status=RunStatus.PARTIAL,
            executions=[execution],
            observations=[],
            analysis_gaps=[
                AnalysisGap(
                    code=outcome.value.upper(),
                    message=message,
                    adapter_id=adapter.adapter_id,
                )
            ],
        )
