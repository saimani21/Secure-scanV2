from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request

from securescan.api.job_schemas import ApiErrorResponse
from securescan.api.source_scan_schemas import (
    CancellationResponse,
    ComponentPageResponse,
    CoverageResponse,
    DependencyPageResponse,
    FindingPageResponse,
    GapPageResponse,
    PublishedReportResponse,
    ScanPageResponse,
    ScanStagesResponse,
    ScanSubmissionRequest,
    ScanSubmissionResponse,
    ScanSummaryResponse,
)
from securescan.orchestration.coordinator import (
    SourceCoordinatorError,
    SourceOrchestrationCoordinatorService,
)
from securescan.orchestration.models import (
    OrchestrationLifecycleState,
    SourceOrchestrationIntegrityError,
)
from securescan.orchestration.service import (
    SourceOrchestrationError,
    SourceOrchestrationNotFoundError,
)
from securescan.product_core import (
    InvalidScanFilterError,
    InvalidScanPaginationError,
    ProductCoreNotReadyError,
    ScanNotFoundError,
    ScanNotPublishedError,
    SourceHttpLineageNotFoundError,
    SourceHttpSubmissionConflictError,
    SourceHttpSubmissionError,
    SourceHttpTargetNotFoundError,
    SourceProductStatus,
    SourceScanQueryError,
    SourceScanQueryPersistenceError,
    SourceScanQueryService,
    SourceTrustedTargetScanRequest,
    SourceTrustedTargetSubmissionService,
)

router = APIRouter(prefix="/v1/scans", tags=["Source scans"])


def get_source_submission_service(request: Request) -> SourceTrustedTargetSubmissionService:
    return _state(request, "source_trusted_target_submission_service")


def get_source_query_service(request: Request) -> SourceScanQueryService:
    return _state(request, "source_scan_query_service")


def get_source_cancellation_service(
    request: Request,
) -> SourceOrchestrationCoordinatorService:
    return _state(request, "source_orchestration_coordinator_service")


def _state(request: Request, name: str):
    value = getattr(request.app.state, name, None)
    if value is None:
        raise RuntimeError("Source scan application service is not configured")
    return value


def _error(code: str, message: str, http_status: int) -> HTTPException:
    return HTTPException(http_status, detail={"code": code, "message": message})


def _query_error(exc: SourceScanQueryError) -> HTTPException:
    if isinstance(exc, ScanNotFoundError):
        return _error("SCAN_NOT_FOUND", "Source scan was not found", 404)
    if isinstance(exc, ScanNotPublishedError):
        return _error("SCAN_NOT_PUBLISHED", "Source scan report is not published", 409)
    if isinstance(exc, ProductCoreNotReadyError):
        return _error("PRODUCT_CORE_NOT_READY", "Source Product Core data is not ready", 409)
    if isinstance(exc, (InvalidScanFilterError, InvalidScanPaginationError)):
        return _error(exc.code.value, str(exc), 422)
    if isinstance(exc, SourceScanQueryPersistenceError):
        return _error("QUERY_UNAVAILABLE", "Source scan query is unavailable", 503)
    return _error("QUERY_UNAVAILABLE", "Source scan query is unavailable", 503)


_QUERY_RESPONSES = {
    404: {"model": ApiErrorResponse},
    409: {"model": ApiErrorResponse},
    422: {"model": ApiErrorResponse},
    503: {"model": ApiErrorResponse},
}


@router.post("", status_code=202, response_model=ScanSubmissionResponse, responses=_QUERY_RESPONSES)
def submit_scan(
    body: ScanSubmissionRequest,
    service: Annotated[
        SourceTrustedTargetSubmissionService, Depends(get_source_submission_service)
    ],
    queries: Annotated[SourceScanQueryService, Depends(get_source_query_service)],
) -> ScanSubmissionResponse:
    try:
        result = service.submit(
            SourceTrustedTargetScanRequest(
                project_id=str(body.project_id),
                trusted_target_id=str(body.trusted_target_id),
                lineage_id=None if body.lineage_id is None else str(body.lineage_id),
                idempotency_key=body.idempotency_key,
                deadline_at=body.deadline_at,
            )
        )
    except SourceHttpTargetNotFoundError as exc:
        raise _error("TARGET_NOT_FOUND", "Trusted Source target was not found", 404) from exc
    except SourceHttpLineageNotFoundError as exc:
        raise _error("LINEAGE_NOT_FOUND", "Source lineage was not found", 404) from exc
    except SourceHttpSubmissionConflictError as exc:
        raise _error(
            "CONFLICT", "Source scan submission conflicts with durable state", 409
        ) from exc
    except SourceHttpSubmissionError as exc:
        raise _error(
            "SUBMISSION_UNAVAILABLE", "Source scan submission is unavailable", 503
        ) from exc
    summary = _call(queries.get_scan, result.run_id)
    return ScanSubmissionResponse(
        run_id=result.run_id,
        lineage_id=result.lineage_id,
        submission_sequence_number=result.submission_sequence_number,
        predecessor_run_id=result.predecessor_run_id,
        status=summary.product_status,
    )


def _call(method, *args, **kwargs):
    try:
        return method(*args, **kwargs)
    except SourceScanQueryError as exc:
        raise _query_error(exc) from exc


@router.get("", response_model=ScanPageResponse, responses=_QUERY_RESPONSES)
def list_scans(
    service: Annotated[SourceScanQueryService, Depends(get_source_query_service)],
    limit: int = 50,
    offset: int = 0,
) -> ScanPageResponse:
    return ScanPageResponse.model_validate(
        _call(service.list_scans, limit=limit, offset=offset)
    )


@router.get("/{run_id}", response_model=ScanSummaryResponse, responses=_QUERY_RESPONSES)
def get_scan(
    run_id: UUID, service: Annotated[SourceScanQueryService, Depends(get_source_query_service)]
):
    return ScanSummaryResponse.model_validate(_call(service.get_scan, str(run_id)))


@router.get("/{run_id}/stages", response_model=ScanStagesResponse, responses=_QUERY_RESPONSES)
def get_stages(
    run_id: UUID, service: Annotated[SourceScanQueryService, Depends(get_source_query_service)]
):
    return ScanStagesResponse.model_validate(_call(service.get_stages, str(run_id)))


@router.get("/{run_id}/findings", response_model=FindingPageResponse, responses=_QUERY_RESPONSES)
def list_findings(
    run_id: UUID,
    service: Annotated[SourceScanQueryService, Depends(get_source_query_service)],
    authority: str | None = None,
    category: str | None = None,
    priority: str | None = None,
    lifecycle_state: str | None = None,
    limit: int = 50,
    offset: int = 0,
):
    result = _call(
        service.list_findings,
        str(run_id),
        authority=authority,
        category=category,
        priority=priority,
        lifecycle_state=lifecycle_state,
        limit=limit,
        offset=offset,
    )
    return FindingPageResponse.model_validate(result)


@router.get(
    "/{run_id}/components", response_model=ComponentPageResponse, responses=_QUERY_RESPONSES
)
def list_components(
    run_id: UUID,
    service: Annotated[SourceScanQueryService, Depends(get_source_query_service)],
    limit: int = 50,
    offset: int = 0,
):
    return ComponentPageResponse.model_validate(
        _call(service.list_components, str(run_id), limit=limit, offset=offset)
    )


@router.get(
    "/{run_id}/dependencies", response_model=DependencyPageResponse, responses=_QUERY_RESPONSES
)
def list_dependencies(
    run_id: UUID,
    service: Annotated[SourceScanQueryService, Depends(get_source_query_service)],
    limit: int = 50,
    offset: int = 0,
):
    return DependencyPageResponse.model_validate(
        _call(service.list_dependencies, str(run_id), limit=limit, offset=offset)
    )


@router.get("/{run_id}/coverage", response_model=CoverageResponse, responses=_QUERY_RESPONSES)
def get_coverage(
    run_id: UUID, service: Annotated[SourceScanQueryService, Depends(get_source_query_service)]
):
    return CoverageResponse.model_validate(_call(service.get_coverage, str(run_id)))


@router.get("/{run_id}/gaps", response_model=GapPageResponse, responses=_QUERY_RESPONSES)
def list_gaps(
    run_id: UUID,
    service: Annotated[SourceScanQueryService, Depends(get_source_query_service)],
    authority: str | None = None,
    limit: int = 50,
    offset: int = 0,
):
    return GapPageResponse.model_validate(
        _call(service.list_gaps, str(run_id), authority=authority, limit=limit, offset=offset)
    )


@router.get("/{run_id}/report", response_model=PublishedReportResponse, responses=_QUERY_RESPONSES)
def get_report(
    run_id: UUID, service: Annotated[SourceScanQueryService, Depends(get_source_query_service)]
):
    return PublishedReportResponse.model_validate(_call(service.get_report, str(run_id)))


@router.post(
    "/{run_id}/cancel",
    status_code=202,
    response_model=CancellationResponse,
    responses=_QUERY_RESPONSES,
)
def cancel_scan(
    run_id: UUID,
    cancellation: Annotated[
        SourceOrchestrationCoordinatorService, Depends(get_source_cancellation_service)
    ],
    queries: Annotated[SourceScanQueryService, Depends(get_source_query_service)],
):
    try:
        queries.get_scan(str(run_id))
        result = cancellation.request_cancellation(str(run_id))
        summary = queries.get_scan(str(run_id))
    except SourceOrchestrationNotFoundError as exc:
        raise _error("SCAN_NOT_FOUND", "Source scan was not found", 404) from exc
    except (
        SourceCoordinatorError,
        SourceOrchestrationError,
        SourceOrchestrationIntegrityError,
    ) as exc:
        raise _error(
            "CANCELLATION_UNAVAILABLE", "Source scan cancellation is unavailable", 503
        ) from exc
    except SourceScanQueryError as exc:
        raise _query_error(exc) from exc
    requested = (
        result.lifecycle_state is OrchestrationLifecycleState.CANCELLATION_REQUESTED
        or summary.product_status is SourceProductStatus.CANCELLED
    )
    return CancellationResponse(
        run_id=str(run_id),
        status=summary.product_status,
        cancellation_requested=requested,
        already_terminal=result.lifecycle_state is OrchestrationLifecycleState.TERMINAL
        and not requested,
    )
