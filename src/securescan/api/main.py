from __future__ import annotations

import hashlib
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from securescan.adapters.fake_scanner import FakeScannerAdapter
from securescan.api.job_routes import router as job_router
from securescan.api.operations_routes import router as operations_router
from securescan.api.run_routes import router as run_router
from securescan.api.source_scan_routes import router as source_scan_router
from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.config import get_settings
from securescan.domain.enums import TargetType
from securescan.domain.models import ScanReport, TargetProfile
from securescan.execution.local_executor import LocalProcessExecutor
from securescan.jobs import (
    JobCancellationService,
    JobRepository,
    JobSubmissionService,
)
from securescan.observability.context import CorrelationIdMiddleware
from securescan.observability.logging import configure_structured_logging
from securescan.observability.metrics import OperationalMetricsService
from securescan.observability.readiness import (
    DatabaseReadinessService,
    _bootstrap_database_schema,
)
from securescan.orchestration.coordinator import SourceOrchestrationCoordinatorService
from securescan.orchestration.models import frozen_source_v1_authority_roster
from securescan.orchestration.service import SourceOrchestrationService
from securescan.persistence.database import create_session_factory
from securescan.product_core import (
    SourceScanQueryService,
    SourceScanSubmissionService,
    SourceTrustedTargetSubmissionService,
)
from securescan.runs import RunQueryService
from securescan.runtime_storage import initialize_source_runtime_storage
from securescan.services.scan_service import ScanService
from securescan.source.projection import SourceProjectionManager
from securescan.web.routes import router as frontend_router
from securescan.workspaces import RepositoryWorkspaceManager

_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
_ALEMBIC_CONFIG_PATH = _REPOSITORY_ROOT / "alembic.ini"


@asynccontextmanager
async def lifespan(application: FastAPI):
    configure_structured_logging()
    settings = get_settings()
    initialize_source_runtime_storage(settings, allow_empty_projection=False)
    engine, session_factory = create_session_factory(settings)
    try:
        _bootstrap_database_schema(
            engine,
            allow_sqlite_schema_bootstrap=settings.allow_sqlite_schema_bootstrap,
        )
        application.state.job_submission_service = JobSubmissionService(session_factory)
        application.state.job_repository = JobRepository(session_factory)
        application.state.job_cancellation_service = JobCancellationService(session_factory)
        application.state.run_query_service = RunQueryService(session_factory)
        application.state.database_readiness_service = DatabaseReadinessService(
            engine,
            _ALEMBIC_CONFIG_PATH,
        )
        application.state.operational_metrics_service = OperationalMetricsService(session_factory)
        artifact_store = ContentAddressedArtifactStore(settings.artifact_root)
        workspace_manager = RepositoryWorkspaceManager(settings.source_workspace_root)
        roster = frozen_source_v1_authority_roster()
        source_submissions = SourceScanSubmissionService(
            session_factory, artifact_store, workspace_manager
        )
        source_orchestrations = SourceOrchestrationService(session_factory, artifact_store, roster)
        application.state.source_trusted_target_submission_service = (
            SourceTrustedTargetSubmissionService(
                session_factory, source_submissions, source_orchestrations
            )
        )
        application.state.source_scan_query_service = SourceScanQueryService(
            session_factory, artifact_store
        )
        application.state.source_orchestration_coordinator_service = (
            SourceOrchestrationCoordinatorService(
                session_factory,
                artifact_store,
                roster,
                SourceProjectionManager(settings.source_projection_root),
            )
        )
        application.state.database_engine = engine
        yield
    finally:
        engine.dispose()


app = FastAPI(title="SecureScan Core", version="0.1.0", lifespan=lifespan)
app.add_middleware(CorrelationIdMiddleware)
app.include_router(job_router)
app.include_router(run_router)
app.include_router(operations_router)
app.include_router(source_scan_router)
app.include_router(frontend_router)


class FakeScanRequest(BaseModel):
    path: str = "."
    mode: str = Field(default="findings")
    timeout_seconds: int = Field(default=5, ge=1, le=60)
    max_output_bytes: int = Field(default=262_144, ge=1_024, le=10_485_760)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/test-scans/fake", response_model=ScanReport)
def run_fake_scan(request: FakeScanRequest) -> ScanReport:
    target_path = Path(request.path).resolve()
    if not target_path.exists() or not target_path.is_dir():
        raise HTTPException(status_code=400, detail="path must be an existing directory")

    digest = hashlib.sha256(str(target_path).encode()).hexdigest()
    target = TargetProfile(
        target_type=TargetType.SOURCE_REPOSITORY,
        path=target_path,
        content_digest=digest,
        metadata={"test_only": True},
    )
    settings = get_settings()
    service = ScanService(
        executor=LocalProcessExecutor(),
        artifact_store=ContentAddressedArtifactStore(settings.artifact_root),
    )
    return service.run(
        FakeScannerAdapter(settings.hmac_key),
        target,
        mode=request.mode,
        timeout_seconds=request.timeout_seconds,
        max_output_bytes=request.max_output_bytes,
    )
