from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from securescan.api.job_schemas import ApiErrorResponse
from securescan.api.operations_schemas import (
    LivenessApiResponse,
    OperationalMetricsApiResponse,
    ReadinessApiResponse,
)
from securescan.observability.metrics import (
    OperationalMetricsError,
    OperationalMetricsPersistenceError,
    OperationalMetricsService,
)
from securescan.observability.readiness import DatabaseReadinessService

router = APIRouter()


def get_database_readiness_service(request: Request) -> DatabaseReadinessService:
    service = getattr(request.app.state, "database_readiness_service", None)
    if service is None:
        raise RuntimeError("Database readiness service has not been configured")
    return service


def get_operational_metrics_service(request: Request) -> OperationalMetricsService:
    service = getattr(request.app.state, "operational_metrics_service", None)
    if service is None:
        raise RuntimeError("Operational metrics service has not been configured")
    return service


@router.get(
    "/health/live",
    response_model=LivenessApiResponse,
)
def get_liveness() -> LivenessApiResponse:
    return LivenessApiResponse(status="alive")


@router.get(
    "/health/ready",
    response_model=ReadinessApiResponse,
    responses={status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ReadinessApiResponse}},
)
@router.get(
    "/ready",
    response_model=ReadinessApiResponse,
    responses={status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ReadinessApiResponse}},
)
def get_readiness(
    response: Response,
    service: Annotated[
        DatabaseReadinessService,
        Depends(get_database_readiness_service),
    ],
) -> ReadinessApiResponse:
    snapshot = service.check()
    if not snapshot.ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return ReadinessApiResponse(
        status="ready" if snapshot.ready else "not_ready",
        database_reachable=snapshot.database_reachable,
        schema_at_head=snapshot.schema_at_head,
        reason=snapshot.reason,
        checked_at=snapshot.checked_at,
    )


@router.get("/version")
def get_version(request: Request) -> dict[str, str]:
    return {"version": request.app.version}


@router.get(
    "/v1/operations/metrics",
    response_model=OperationalMetricsApiResponse,
    responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"model": ApiErrorResponse},
        status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ApiErrorResponse},
    },
)
def get_operational_metrics(
    service: Annotated[
        OperationalMetricsService,
        Depends(get_operational_metrics_service),
    ],
) -> OperationalMetricsApiResponse:
    try:
        snapshot = service.collect()
    except OperationalMetricsPersistenceError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "OPERATIONS_METRICS_UNAVAILABLE",
                "message": "Operational metrics are temporarily unavailable.",
            },
        ) from exc
    except OperationalMetricsError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "code": "OPERATIONS_METRICS_INVALID",
                "message": "Operational metrics could not be produced.",
            },
        ) from exc
    return OperationalMetricsApiResponse.model_validate(snapshot, from_attributes=True)
