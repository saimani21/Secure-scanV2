from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Request

from securescan.api.governance_schemas import (
    FindingGovernanceEventPageResponse,
    FindingGovernanceMutationRequest,
    FindingGovernanceResponse,
)
from securescan.api.job_schemas import ApiErrorResponse
from securescan.product_core import (
    FindingGovernanceConflictError,
    FindingGovernanceError,
    FindingGovernanceNotFoundError,
    FindingGovernancePersistenceError,
    FindingGovernanceValidationError,
    SourceFindingGovernanceService,
)

router = APIRouter(prefix="/v1/projects", tags=["Source finding governance"])
FindingId = Annotated[str, Path(pattern=r"^[0-9a-f]{64}$")]


def get_source_governance_service(request: Request) -> SourceFindingGovernanceService:
    service = getattr(request.app.state, "source_finding_governance_service", None)
    if service is None:
        raise RuntimeError("Source governance application service is not configured")
    return service


def _error(code: str, message: str, status: int) -> HTTPException:
    return HTTPException(status, detail={"code": code, "message": message})


def _governance_error(error: FindingGovernanceError) -> HTTPException:
    if isinstance(error, FindingGovernanceNotFoundError):
        return _error("FINDING_GOVERNANCE_NOT_FOUND", "Governed finding was not found", 404)
    if isinstance(error, FindingGovernanceConflictError):
        return _error(
            "GOVERNANCE_REVISION_CONFLICT", "Governance revision conflicts with durable state", 409
        )
    if isinstance(error, FindingGovernanceValidationError):
        return _error("INVALID_GOVERNANCE", str(error), 422)
    if isinstance(error, FindingGovernancePersistenceError):
        return _error("GOVERNANCE_UNAVAILABLE", "Finding governance is unavailable", 503)
    return _error("GOVERNANCE_UNAVAILABLE", "Finding governance is unavailable", 503)


_RESPONSES = {
    404: {"model": ApiErrorResponse},
    409: {"model": ApiErrorResponse},
    422: {"model": ApiErrorResponse},
    503: {"model": ApiErrorResponse},
}


@router.get(
    "/{project_id}/lineages/{lineage_id}/findings/{finding_id}/governance",
    response_model=FindingGovernanceResponse,
    responses=_RESPONSES,
)
def get_finding_governance(
    project_id: UUID,
    lineage_id: UUID,
    finding_id: FindingId,
    service: Annotated[SourceFindingGovernanceService, Depends(get_source_governance_service)],
) -> FindingGovernanceResponse:
    try:
        state = service.get(
            project_id=str(project_id), lineage_id=str(lineage_id), finding_id=finding_id
        )
    except FindingGovernanceError as error:
        raise _governance_error(error) from error
    return FindingGovernanceResponse.model_validate(state)


@router.put(
    "/{project_id}/lineages/{lineage_id}/findings/{finding_id}/governance",
    response_model=FindingGovernanceResponse,
    responses=_RESPONSES,
)
def mutate_finding_governance(
    project_id: UUID,
    lineage_id: UUID,
    finding_id: FindingId,
    body: FindingGovernanceMutationRequest,
    service: Annotated[SourceFindingGovernanceService, Depends(get_source_governance_service)],
) -> FindingGovernanceResponse:
    try:
        state = service.mutate(
            project_id=str(project_id),
            lineage_id=str(lineage_id),
            finding_id=finding_id,
            disposition=body.disposition,
            reason=body.reason,
            expires_at=body.expires_at,
            expected_revision=body.expected_revision,
        )
    except FindingGovernanceError as error:
        raise _governance_error(error) from error
    return FindingGovernanceResponse.model_validate(state)


@router.get(
    "/{project_id}/lineages/{lineage_id}/findings/{finding_id}/governance/events",
    response_model=FindingGovernanceEventPageResponse,
    responses=_RESPONSES,
)
def list_finding_governance_events(
    project_id: UUID,
    lineage_id: UUID,
    finding_id: FindingId,
    service: Annotated[SourceFindingGovernanceService, Depends(get_source_governance_service)],
    limit: int = 50,
    offset: int = 0,
) -> FindingGovernanceEventPageResponse:
    try:
        page = service.list_events(
            project_id=str(project_id),
            lineage_id=str(lineage_id),
            finding_id=finding_id,
            limit=limit,
            offset=offset,
        )
    except FindingGovernanceError as error:
        raise _governance_error(error) from error
    return FindingGovernanceEventPageResponse.model_validate(page)
