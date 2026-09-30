from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Request

from securescan.api.job_schemas import ApiErrorResponse
from securescan.api.suppression_schemas import (
    FindingSuppressionEventPageResponse,
    FindingSuppressionMutationRequest,
    FindingSuppressionResponse,
    FindingSuppressionRevokeRequest,
)
from securescan.product_core import (
    FindingSuppressionConflictError,
    FindingSuppressionError,
    FindingSuppressionNotFoundError,
    FindingSuppressionPersistenceError,
    FindingSuppressionStateError,
    FindingSuppressionValidationError,
    SourceFindingSuppressionService,
)

router = APIRouter(prefix="/v1/projects", tags=["Source finding suppression"])
FindingId = Annotated[str, Path(pattern=r"^[0-9a-f]{64}$")]


def get_source_suppression_service(request: Request) -> SourceFindingSuppressionService:
    service = getattr(request.app.state, "source_finding_suppression_service", None)
    if service is None:
        raise RuntimeError("Source suppression application service is not configured")
    return service


def _error(code: str, message: str, status: int) -> HTTPException:
    return HTTPException(status, detail={"code": code, "message": message})


def _suppression_error(error: FindingSuppressionError) -> HTTPException:
    if isinstance(error, FindingSuppressionNotFoundError):
        return _error("FINDING_SUPPRESSION_NOT_FOUND", "Suppressible finding was not found", 404)
    if isinstance(error, FindingSuppressionConflictError):
        return _error(
            "SUPPRESSION_REVISION_CONFLICT",
            "Suppression revision conflicts with durable state",
            409,
        )
    if isinstance(error, FindingSuppressionStateError):
        return _error("SUPPRESSION_STATE_CONFLICT", str(error), 409)
    if isinstance(error, FindingSuppressionValidationError):
        return _error("INVALID_SUPPRESSION", str(error), 422)
    if isinstance(error, FindingSuppressionPersistenceError):
        return _error("SUPPRESSION_UNAVAILABLE", "Finding suppression is unavailable", 503)
    return _error("SUPPRESSION_UNAVAILABLE", "Finding suppression is unavailable", 503)


_RESPONSES = {
    404: {"model": ApiErrorResponse},
    409: {"model": ApiErrorResponse},
    422: {"model": ApiErrorResponse},
    503: {"model": ApiErrorResponse},
}


@router.get(
    "/{project_id}/lineages/{lineage_id}/findings/{finding_id}/suppression",
    response_model=FindingSuppressionResponse,
    responses=_RESPONSES,
)
def get_finding_suppression(
    project_id: UUID,
    lineage_id: UUID,
    finding_id: FindingId,
    service: Annotated[SourceFindingSuppressionService, Depends(get_source_suppression_service)],
) -> FindingSuppressionResponse:
    try:
        state = service.get(
            project_id=str(project_id), lineage_id=str(lineage_id), finding_id=finding_id
        )
    except FindingSuppressionError as error:
        raise _suppression_error(error) from error
    return FindingSuppressionResponse.model_validate(state)


@router.put(
    "/{project_id}/lineages/{lineage_id}/findings/{finding_id}/suppression",
    response_model=FindingSuppressionResponse,
    responses=_RESPONSES,
)
def mutate_finding_suppression(
    project_id: UUID,
    lineage_id: UUID,
    finding_id: FindingId,
    body: FindingSuppressionMutationRequest,
    service: Annotated[SourceFindingSuppressionService, Depends(get_source_suppression_service)],
) -> FindingSuppressionResponse:
    try:
        state = service.suppress(
            project_id=str(project_id),
            lineage_id=str(lineage_id),
            finding_id=finding_id,
            reason=body.reason,
            expires_at=body.expires_at,
            expected_revision=body.expected_revision,
        )
    except FindingSuppressionError as error:
        raise _suppression_error(error) from error
    return FindingSuppressionResponse.model_validate(state)


@router.post(
    "/{project_id}/lineages/{lineage_id}/findings/{finding_id}/suppression/revoke",
    response_model=FindingSuppressionResponse,
    responses=_RESPONSES,
)
def revoke_finding_suppression(
    project_id: UUID,
    lineage_id: UUID,
    finding_id: FindingId,
    body: FindingSuppressionRevokeRequest,
    service: Annotated[SourceFindingSuppressionService, Depends(get_source_suppression_service)],
) -> FindingSuppressionResponse:
    try:
        state = service.revoke(
            project_id=str(project_id),
            lineage_id=str(lineage_id),
            finding_id=finding_id,
            expected_revision=body.expected_revision,
        )
    except FindingSuppressionError as error:
        raise _suppression_error(error) from error
    return FindingSuppressionResponse.model_validate(state)


@router.get(
    "/{project_id}/lineages/{lineage_id}/findings/{finding_id}/suppression/events",
    response_model=FindingSuppressionEventPageResponse,
    responses=_RESPONSES,
)
def list_finding_suppression_events(
    project_id: UUID,
    lineage_id: UUID,
    finding_id: FindingId,
    service: Annotated[SourceFindingSuppressionService, Depends(get_source_suppression_service)],
    limit: int = 50,
    offset: int = 0,
) -> FindingSuppressionEventPageResponse:
    try:
        page = service.list_events(
            project_id=str(project_id),
            lineage_id=str(lineage_id),
            finding_id=finding_id,
            limit=limit,
            offset=offset,
        )
    except FindingSuppressionError as error:
        raise _suppression_error(error) from error
    return FindingSuppressionEventPageResponse.model_validate(page)
