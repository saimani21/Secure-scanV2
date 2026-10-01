from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request

from securescan.api.job_schemas import ApiErrorResponse
from securescan.api.project_schemas import (
    ProjectCreateRequest,
    ProjectPageResponse,
    ProjectSummaryResponse,
)
from securescan.api.source_scan_routes import get_source_query_service
from securescan.api.source_scan_schemas import ScanPageResponse
from securescan.product_core import (
    InvalidProjectIdentifierError,
    InvalidProjectPaginationError,
    InvalidScanPaginationError,
    SourceProjectError,
    SourceProjectNotFoundError,
    SourceProjectPersistenceError,
    SourceProjectService,
    SourceScanQueryError,
    SourceScanQueryPersistenceError,
    SourceScanQueryService,
)

router = APIRouter(prefix="/v1/projects", tags=["Source projects"])


def get_source_project_service(request: Request) -> SourceProjectService:
    service = getattr(request.app.state, "source_project_service", None)
    if service is None:
        raise RuntimeError("Source project application service is not configured")
    return service


def _error(code: str, message: str, status: int) -> HTTPException:
    return HTTPException(status, detail={"code": code, "message": message})


def _project_error(error: SourceProjectError) -> HTTPException:
    if isinstance(error, SourceProjectNotFoundError):
        return _error("PROJECT_NOT_FOUND", "Source project was not found", 404)
    if isinstance(error, (InvalidProjectIdentifierError, InvalidProjectPaginationError)):
        return _error("INVALID_PROJECT_QUERY", str(error), 422)
    if isinstance(error, SourceProjectPersistenceError):
        return _error("PROJECT_QUERY_UNAVAILABLE", "Source project query is unavailable", 503)
    return _error("PROJECT_QUERY_UNAVAILABLE", "Source project query is unavailable", 503)


def _scan_error(error: SourceScanQueryError) -> HTTPException:
    if isinstance(error, InvalidScanPaginationError):
        return _error("INVALID_PAGINATION", str(error), 422)
    if isinstance(error, SourceScanQueryPersistenceError):
        return _error("QUERY_UNAVAILABLE", "Source scan query is unavailable", 503)
    return _error("QUERY_UNAVAILABLE", "Source scan query is unavailable", 503)


_RESPONSES = {
    404: {"model": ApiErrorResponse},
    422: {"model": ApiErrorResponse},
    503: {"model": ApiErrorResponse},
}


@router.post("", response_model=ProjectSummaryResponse, responses=_RESPONSES, status_code=201)
def create_project(
    body: ProjectCreateRequest,
    service: Annotated[SourceProjectService, Depends(get_source_project_service)],
) -> ProjectSummaryResponse:
    # Use the frozen Product Core name validator; H adds no naming policy.
    try:
        service._name(body.name)
    except SourceProjectError as error:
        raise _error("INVALID_PROJECT_NAME", "Project name is invalid", 422) from error
    try:
        project = service.create(name=body.name)
    except SourceProjectError as error:
        raise _error(
            "PROJECT_CREATE_UNAVAILABLE", "Source project creation is unavailable", 503
        ) from error
    return ProjectSummaryResponse.model_validate(project)


@router.get("", response_model=ProjectPageResponse, responses=_RESPONSES)
def list_projects(
    service: Annotated[SourceProjectService, Depends(get_source_project_service)],
    limit: int = 50,
    offset: int = 0,
) -> ProjectPageResponse:
    try:
        page = service.list_page(limit=limit, offset=offset)
    except SourceProjectError as error:
        raise _project_error(error) from error
    return ProjectPageResponse.model_validate(page)


@router.get("/{project_id}", response_model=ProjectSummaryResponse, responses=_RESPONSES)
def get_project(
    project_id: UUID,
    service: Annotated[SourceProjectService, Depends(get_source_project_service)],
) -> ProjectSummaryResponse:
    try:
        project = service.get(str(project_id))
    except SourceProjectError as error:
        raise _project_error(error) from error
    return ProjectSummaryResponse.model_validate(project)


@router.get("/{project_id}/scans", response_model=ScanPageResponse, responses=_RESPONSES)
def list_project_scans(
    project_id: UUID,
    scans: Annotated[SourceScanQueryService, Depends(get_source_query_service)],
    limit: int = 50,
    offset: int = 0,
) -> ScanPageResponse:
    try:
        page = scans.list_scans(project_id=str(project_id), limit=limit, offset=offset)
    except SourceProjectError as error:
        raise _project_error(error) from error
    except SourceScanQueryError as error:
        raise _scan_error(error) from error
    return ScanPageResponse.model_validate(page)
