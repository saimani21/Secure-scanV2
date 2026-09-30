from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request

from securescan.api.job_schemas import ApiErrorResponse
from securescan.api.trusted_baseline_schemas import (
    SecurityDeltaResponse,
    TrustedBaselineHistoryPageResponse,
    TrustedBaselinePromotionRequest,
    TrustedBaselineResponse,
    TrustedBaselineStateResponse,
)
from securescan.product_core import (
    SecurityDeltaError,
    SecurityDeltaNotFoundError,
    SecurityDeltaPersistenceError,
    SecurityDeltaValidationError,
    SourceSecurityDeltaService,
    SourceTrustedBaselineService,
    TrustedBaselineConflictError,
    TrustedBaselineError,
    TrustedBaselineIneligibleError,
    TrustedBaselineNotFoundError,
    TrustedBaselinePersistenceError,
    TrustedBaselineValidationError,
)

router = APIRouter(prefix="/v1/projects", tags=["Source trusted baseline"])


def get_trusted_baseline_service(request: Request) -> SourceTrustedBaselineService:
    service = getattr(request.app.state, "source_trusted_baseline_service", None)
    if service is None:
        raise RuntimeError("Trusted baseline application service is not configured")
    return service


def get_security_delta_service(request: Request) -> SourceSecurityDeltaService:
    service = getattr(request.app.state, "source_security_delta_service", None)
    if service is None:
        raise RuntimeError("Security Delta application service is not configured")
    return service


def _error(code: str, message: str, status: int) -> HTTPException:
    return HTTPException(status, detail={"code": code, "message": message})


def _baseline_error(error: TrustedBaselineError) -> HTTPException:
    if isinstance(error, TrustedBaselineNotFoundError):
        return _error("TRUSTED_BASELINE_NOT_FOUND", "Trusted baseline target was not found", 404)
    if isinstance(error, TrustedBaselineConflictError):
        return _error(
            "TRUSTED_BASELINE_REVISION_CONFLICT",
            "Trusted baseline revision conflicts with durable state",
            409,
        )
    if isinstance(error, TrustedBaselineIneligibleError):
        return _error(
            "TRUSTED_BASELINE_RUN_INELIGIBLE",
            "Run is not eligible for trusted baseline promotion",
            422,
        )
    if isinstance(error, TrustedBaselineValidationError):
        return _error("INVALID_TRUSTED_BASELINE", str(error), 422)
    if isinstance(error, TrustedBaselinePersistenceError):
        return _error("TRUSTED_BASELINE_UNAVAILABLE", "Trusted baseline is unavailable", 503)
    return _error("TRUSTED_BASELINE_UNAVAILABLE", "Trusted baseline is unavailable", 503)


def _delta_error(error: SecurityDeltaError) -> HTTPException:
    if isinstance(error, SecurityDeltaNotFoundError):
        return _error("SECURITY_DELTA_NOT_FOUND", "Security Delta target was not found", 404)
    if isinstance(error, SecurityDeltaValidationError):
        return _error("INVALID_SECURITY_DELTA", str(error), 422)
    if isinstance(error, SecurityDeltaPersistenceError):
        return _error("SECURITY_DELTA_UNAVAILABLE", "Security Delta is unavailable", 503)
    return _error("SECURITY_DELTA_UNAVAILABLE", "Security Delta is unavailable", 503)


_BASELINE_RESPONSES = {
    404: {"model": ApiErrorResponse},
    409: {"model": ApiErrorResponse},
    422: {"model": ApiErrorResponse},
    503: {"model": ApiErrorResponse},
}
_DELTA_RESPONSES = {
    404: {"model": ApiErrorResponse},
    422: {"model": ApiErrorResponse},
    503: {"model": ApiErrorResponse},
}


@router.get(
    "/{project_id}/lineages/{lineage_id}/baseline",
    response_model=TrustedBaselineStateResponse,
    responses=_BASELINE_RESPONSES,
)
def get_current_trusted_baseline(
    project_id: UUID,
    lineage_id: UUID,
    service: Annotated[SourceTrustedBaselineService, Depends(get_trusted_baseline_service)],
) -> TrustedBaselineStateResponse:
    try:
        state = service.get_current(project_id=str(project_id), lineage_id=str(lineage_id))
    except TrustedBaselineError as error:
        raise _baseline_error(error) from error
    return TrustedBaselineStateResponse.model_validate(state)


@router.put(
    "/{project_id}/lineages/{lineage_id}/baseline",
    response_model=TrustedBaselineResponse,
    responses=_BASELINE_RESPONSES,
)
def promote_trusted_baseline(
    project_id: UUID,
    lineage_id: UUID,
    body: TrustedBaselinePromotionRequest,
    service: Annotated[SourceTrustedBaselineService, Depends(get_trusted_baseline_service)],
) -> TrustedBaselineResponse:
    try:
        baseline = service.promote(
            project_id=str(project_id),
            lineage_id=str(lineage_id),
            run_id=body.run_id,
            expected_revision=body.expected_revision,
        )
    except TrustedBaselineError as error:
        raise _baseline_error(error) from error
    return TrustedBaselineResponse.model_validate(baseline)


@router.get(
    "/{project_id}/lineages/{lineage_id}/baseline/history",
    response_model=TrustedBaselineHistoryPageResponse,
    responses=_BASELINE_RESPONSES,
)
def list_trusted_baseline_history(
    project_id: UUID,
    lineage_id: UUID,
    service: Annotated[SourceTrustedBaselineService, Depends(get_trusted_baseline_service)],
    limit: int = 50,
    offset: int = 0,
) -> TrustedBaselineHistoryPageResponse:
    try:
        page = service.list_history(
            project_id=str(project_id),
            lineage_id=str(lineage_id),
            limit=limit,
            offset=offset,
        )
    except TrustedBaselineError as error:
        raise _baseline_error(error) from error
    return TrustedBaselineHistoryPageResponse.model_validate(page)


@router.get(
    "/{project_id}/lineages/{lineage_id}/runs/{candidate_run_id}/security-delta",
    response_model=SecurityDeltaResponse,
    responses=_DELTA_RESPONSES,
)
def get_security_delta(
    project_id: UUID,
    lineage_id: UUID,
    candidate_run_id: UUID,
    service: Annotated[SourceSecurityDeltaService, Depends(get_security_delta_service)],
) -> SecurityDeltaResponse:
    try:
        delta = service.evaluate(
            project_id=str(project_id),
            lineage_id=str(lineage_id),
            candidate_run_id=str(candidate_run_id),
        )
    except SecurityDeltaError as error:
        raise _delta_error(error) from error
    return SecurityDeltaResponse.model_validate(delta)
