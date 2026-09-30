from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Request

from securescan.api.effective_governance_schemas import EffectiveGovernanceResponse
from securescan.api.job_schemas import ApiErrorResponse
from securescan.product_core import (
    EffectiveGovernanceError,
    EffectiveGovernanceNotFoundError,
    EffectiveGovernancePersistenceError,
    EffectiveGovernanceService,
    EffectiveGovernanceValidationError,
)

router = APIRouter(prefix="/v1/projects", tags=["Source effective governance"])
FindingId = Annotated[str, Path(pattern=r"^[0-9a-f]{64}$")]


def get_effective_governance_service(request: Request) -> EffectiveGovernanceService:
    service = getattr(request.app.state, "effective_governance_service", None)
    if service is None:
        raise RuntimeError("Effective governance application service is not configured")
    return service


def _error(code: str, message: str, status: int) -> HTTPException:
    return HTTPException(status, detail={"code": code, "message": message})


def _effective_governance_error(error: EffectiveGovernanceError) -> HTTPException:
    if isinstance(error, EffectiveGovernanceNotFoundError):
        return _error(
            "EFFECTIVE_GOVERNANCE_NOT_FOUND",
            "Effective governance target was not found",
            404,
        )
    if isinstance(error, EffectiveGovernanceValidationError):
        return _error("INVALID_EFFECTIVE_GOVERNANCE", str(error), 422)
    if isinstance(error, EffectiveGovernancePersistenceError):
        return _error(
            "EFFECTIVE_GOVERNANCE_UNAVAILABLE",
            "Effective governance is unavailable",
            503,
        )
    return _error(
        "EFFECTIVE_GOVERNANCE_UNAVAILABLE",
        "Effective governance is unavailable",
        503,
    )


_RESPONSES = {
    404: {"model": ApiErrorResponse},
    422: {"model": ApiErrorResponse},
    503: {"model": ApiErrorResponse},
}


@router.get(
    "/{project_id}/lineages/{lineage_id}/findings/{finding_id}/effective-governance",
    response_model=EffectiveGovernanceResponse,
    responses=_RESPONSES,
)
def get_effective_governance(
    project_id: UUID,
    lineage_id: UUID,
    finding_id: FindingId,
    service: Annotated[EffectiveGovernanceService, Depends(get_effective_governance_service)],
) -> EffectiveGovernanceResponse:
    try:
        state = service.get(
            project_id=str(project_id), lineage_id=str(lineage_id), finding_id=finding_id
        )
    except EffectiveGovernanceError as error:
        raise _effective_governance_error(error) from error
    return EffectiveGovernanceResponse.model_validate(state)
