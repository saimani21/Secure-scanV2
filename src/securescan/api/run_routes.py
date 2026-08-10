from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from securescan.api.job_schemas import ApiErrorResponse
from securescan.api.run_schemas import (
    AnalysisRunApiResponse,
    PaginatedRunJobsApiResponse,
    PaginatedToolExecutionsApiResponse,
    RunJobSummaryApiResponse,
    RunReportApiResponse,
    ToolExecutionSummaryApiResponse,
)
from securescan.runs import (
    RunNotFoundError,
    RunQueryError,
    RunQueryPersistenceError,
    RunQueryService,
    RunReportNotReadyError,
)

router = APIRouter()


def get_run_query_service(request: Request) -> RunQueryService:
    service = getattr(request.app.state, "run_query_service", None)
    if service is None:
        raise RuntimeError("Run query service has not been configured")
    return service


def _translate_query_error(exc: RunQueryError) -> HTTPException:
    if isinstance(exc, RunNotFoundError):
        return HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "RUN_NOT_FOUND",
                "message": "Analysis run was not found.",
            },
        )
    if isinstance(exc, RunReportNotReadyError):
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "RUN_REPORT_NOT_READY",
                "message": "The analysis report is not available yet.",
            },
        )
    if isinstance(exc, RunQueryPersistenceError):
        return HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "RUN_QUERY_UNAVAILABLE",
                "message": "Analysis results are temporarily unavailable.",
            },
        )
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={
            "code": "RUN_QUERY_INVALID",
            "message": "The run query is invalid.",
        },
    )


@router.get(
    "/v1/runs/{run_id}",
    response_model=AnalysisRunApiResponse,
    responses={
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse},
        status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ApiErrorResponse},
    },
)
def get_run(
    run_id: UUID,
    service: Annotated[RunQueryService, Depends(get_run_query_service)],
) -> AnalysisRunApiResponse:
    try:
        record = service.get_run(str(run_id))
    except RunQueryError as exc:
        raise _translate_query_error(exc) from exc
    return AnalysisRunApiResponse.model_validate(record, from_attributes=True)


@router.get(
    "/v1/runs/{run_id}/jobs",
    response_model=PaginatedRunJobsApiResponse,
    responses={
        status.HTTP_400_BAD_REQUEST: {"model": ApiErrorResponse},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse},
        status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ApiErrorResponse},
    },
)
def list_run_jobs(
    run_id: UUID,
    service: Annotated[RunQueryService, Depends(get_run_query_service)],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=1_000_000_000)] = 0,
) -> PaginatedRunJobsApiResponse:
    try:
        result = service.list_jobs(str(run_id), limit=limit, offset=offset)
    except RunQueryError as exc:
        raise _translate_query_error(exc) from exc
    return PaginatedRunJobsApiResponse(
        items=[
            RunJobSummaryApiResponse.model_validate(item, from_attributes=True)
            for item in result.items
        ],
        total=result.total,
        limit=result.limit,
        offset=result.offset,
    )


@router.get(
    "/v1/runs/{run_id}/executions",
    response_model=PaginatedToolExecutionsApiResponse,
    responses={
        status.HTTP_400_BAD_REQUEST: {"model": ApiErrorResponse},
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse},
        status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ApiErrorResponse},
    },
)
def list_run_executions(
    run_id: UUID,
    service: Annotated[RunQueryService, Depends(get_run_query_service)],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=1_000_000_000)] = 0,
) -> PaginatedToolExecutionsApiResponse:
    try:
        result = service.list_tool_executions(
            str(run_id),
            limit=limit,
            offset=offset,
        )
    except RunQueryError as exc:
        raise _translate_query_error(exc) from exc
    return PaginatedToolExecutionsApiResponse(
        items=[
            ToolExecutionSummaryApiResponse.model_validate(
                item,
                from_attributes=True,
            )
            for item in result.items
        ],
        total=result.total,
        limit=result.limit,
        offset=result.offset,
    )


@router.get(
    "/v1/runs/{run_id}/report",
    response_model=RunReportApiResponse,
    responses={
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse},
        status.HTTP_409_CONFLICT: {"model": ApiErrorResponse},
        status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ApiErrorResponse},
    },
)
def get_run_report(
    run_id: UUID,
    service: Annotated[RunQueryService, Depends(get_run_query_service)],
) -> RunReportApiResponse:
    try:
        record = service.get_report(str(run_id))
    except RunQueryError as exc:
        raise _translate_query_error(exc) from exc
    return RunReportApiResponse(
        run_id=record.run_id,
        status=record.status,
        report_json=record.report_json,
    )
