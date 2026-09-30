from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Request

from securescan.api.guidance_schemas import FindingGuidanceResponse
from securescan.api.job_schemas import ApiErrorResponse
from securescan.product_core.guidance import (
    FindingGuidanceNotFoundError,
    FindingGuidanceService,
    FindingGuidanceUnavailableError,
    FindingGuidanceValidationError,
)

router = APIRouter(prefix="/v1/projects", tags=["Source finding guidance"])
FindingId = Annotated[str, Path(pattern=r"^[0-9a-f]{64}$")]


def get_guidance_service(request: Request) -> FindingGuidanceService:
    service = getattr(request.app.state, "finding_guidance_service", None)
    if service is None:
        raise RuntimeError("Finding guidance service is not configured")
    return service


_RESPONSES = {
    404: {"model": ApiErrorResponse},
    422: {"model": ApiErrorResponse},
    503: {"model": ApiErrorResponse},
}


@router.get(
    "/{project_id}/lineages/{lineage_id}/runs/{run_id}/findings/{finding_id}/guidance",
    response_model=FindingGuidanceResponse,
    responses=_RESPONSES,
)
def get_finding_guidance(
    project_id: UUID,
    lineage_id: UUID,
    run_id: UUID,
    finding_id: FindingId,
    service: Annotated[FindingGuidanceService, Depends(get_guidance_service)],
) -> FindingGuidanceResponse:
    try:
        guidance = service.get_for_run(
            project_id=str(project_id),
            lineage_id=str(lineage_id),
            run_id=str(run_id),
            finding_id=finding_id,
        )
    except FindingGuidanceNotFoundError as error:
        raise HTTPException(
            404,
            detail={"code": "GUIDANCE_NOT_FOUND", "message": "Finding occurrence was not found"},
        ) from error
    except FindingGuidanceValidationError as error:
        raise HTTPException(
            422,
            detail={"code": "INVALID_GUIDANCE_TARGET", "message": "Guidance target is invalid"},
        ) from error
    except FindingGuidanceUnavailableError as error:
        raise HTTPException(
            503,
            detail={
                "code": "GUIDANCE_UNAVAILABLE",
                "message": "Verified finding evidence is unavailable",
            },
        ) from error
    return FindingGuidanceResponse.model_validate(guidance)
