from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request

from securescan.api.job_schemas import ApiErrorResponse
from securescan.api.policy_schemas import (
    PolicyEvaluationResponse,
    PolicyUpdateRequest,
    TrustedPolicyResponse,
)
from securescan.product_core import (
    PolicyConflictError,
    PolicyError,
    PolicyNotFoundError,
    PolicyValidationError,
    SourcePolicyService,
)

router = APIRouter(prefix="/v1/projects", tags=["Source deterministic policy"])


def get_policy_service(request: Request) -> SourcePolicyService:
    service = getattr(request.app.state, "source_policy_service", None)
    if service is None:
        raise RuntimeError("Policy application service is not configured")
    return service


def _policy_error(error: PolicyError) -> HTTPException:
    if isinstance(error, PolicyNotFoundError):
        return HTTPException(
            404,
            detail={"code": "POLICY_TARGET_NOT_FOUND", "message": "Policy target was not found"},
        )
    if isinstance(error, PolicyConflictError):
        return HTTPException(
            409,
            detail={
                "code": "POLICY_VERSION_CONFLICT",
                "message": "Trusted policy version conflicts with durable state",
            },
        )
    if isinstance(error, PolicyValidationError):
        return HTTPException(422, detail={"code": "INVALID_POLICY", "message": str(error)})
    return HTTPException(
        503, detail={"code": "POLICY_UNAVAILABLE", "message": "Policy is unavailable"}
    )


_RESPONSES = {
    404: {"model": ApiErrorResponse},
    409: {"model": ApiErrorResponse},
    422: {"model": ApiErrorResponse},
    503: {"model": ApiErrorResponse},
}


@router.get(
    "/{project_id}/lineages/{lineage_id}/policy",
    response_model=TrustedPolicyResponse,
    responses=_RESPONSES,
)
def get_trusted_policy(
    project_id: UUID,
    lineage_id: UUID,
    service: Annotated[SourcePolicyService, Depends(get_policy_service)],
) -> TrustedPolicyResponse:
    try:
        policy = service.get_policy(project_id=str(project_id), lineage_id=str(lineage_id))
    except PolicyError as error:
        raise _policy_error(error) from error
    return TrustedPolicyResponse.model_validate(policy)


@router.put(
    "/{project_id}/lineages/{lineage_id}/policy",
    response_model=TrustedPolicyResponse,
    responses=_RESPONSES,
)
def update_trusted_policy(
    project_id: UUID,
    lineage_id: UUID,
    body: PolicyUpdateRequest,
    service: Annotated[SourcePolicyService, Depends(get_policy_service)],
) -> TrustedPolicyResponse:
    try:
        policy = service.update_policy(
            project_id=str(project_id),
            lineage_id=str(lineage_id),
            expected_version=body.expected_version,
            definition=body.definition.model_dump(mode="json"),
        )
    except PolicyError as error:
        raise _policy_error(error) from error
    return TrustedPolicyResponse.model_validate(policy)


@router.post(
    "/{project_id}/lineages/{lineage_id}/runs/{candidate_run_id}/policy-evaluations",
    response_model=PolicyEvaluationResponse,
    responses=_RESPONSES,
)
def evaluate_trusted_policy(
    project_id: UUID,
    lineage_id: UUID,
    candidate_run_id: UUID,
    service: Annotated[SourcePolicyService, Depends(get_policy_service)],
) -> PolicyEvaluationResponse:
    try:
        evaluation = service.evaluate(
            project_id=str(project_id),
            lineage_id=str(lineage_id),
            candidate_run_id=str(candidate_run_id),
        )
    except PolicyError as error:
        raise _policy_error(error) from error
    return PolicyEvaluationResponse.model_validate(evaluation)


@router.get(
    "/{project_id}/lineages/{lineage_id}/policy-evaluations/{evaluation_id}",
    response_model=PolicyEvaluationResponse,
    responses=_RESPONSES,
)
def get_policy_evaluation(
    project_id: UUID,
    lineage_id: UUID,
    evaluation_id: UUID,
    service: Annotated[SourcePolicyService, Depends(get_policy_service)],
) -> PolicyEvaluationResponse:
    try:
        evaluation = service.get_evaluation(
            project_id=str(project_id),
            lineage_id=str(lineage_id),
            evaluation_id=str(evaluation_id),
        )
    except PolicyError as error:
        raise _policy_error(error) from error
    return PolicyEvaluationResponse.model_validate(evaluation)
