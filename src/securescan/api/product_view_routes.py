"""Additive H exact-run product reads; legacy scan routes remain unchanged."""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict

from securescan.api.job_schemas import ApiErrorResponse
from securescan.product_core.product_view import (
    ProductViewError,
    ProductViewNotFoundError,
    ProductViewNotReadyError,
    ProductViewValidationError,
    SourceFindingProductViewService,
)

router = APIRouter(prefix="/v1/projects", tags=["Source product views"])


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)


class FindingProductResponse(_StrictModel):
    project_id: str
    lineage_id: str
    run_id: str
    finding_id: str
    authority: str
    category: str
    severity: str | None
    priority_band: str
    priority_reason_codes: tuple[str, ...]
    subject: dict[str, Any]
    primary_location: dict[str, Any] | None
    lifecycle_state_at_run: str
    lifecycle_event_kind: str
    lifecycle_transition_version: int
    lifecycle_reason_codes: tuple[str, ...]


class FindingProductPageResponse(_StrictModel):
    items: tuple[FindingProductResponse, ...]
    total: int
    limit: int
    offset: int


def get_product_view_service(request: Request) -> SourceFindingProductViewService:
    service = getattr(request.app.state, "source_finding_product_view_service", None)
    if service is None:
        raise RuntimeError("Product view service is not configured")
    return service


_RESPONSES = {
    404: {"model": ApiErrorResponse},
    409: {"model": ApiErrorResponse},
    422: {"model": ApiErrorResponse},
    503: {"model": ApiErrorResponse},
}


@router.get(
    "/{project_id}/lineages/{lineage_id}/runs/{run_id}/findings",
    response_model=FindingProductPageResponse,
    responses=_RESPONSES,
)
def list_run_product_findings(
    project_id: UUID,
    lineage_id: UUID,
    run_id: UUID,
    service: Annotated[SourceFindingProductViewService, Depends(get_product_view_service)],
    authority: str | None = None,
    category: str | None = None,
    priority: str | None = None,
    lifecycle_state: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> FindingProductPageResponse:
    try:
        page = service.list_for_run(
            project_id=str(project_id),
            lineage_id=str(lineage_id),
            run_id=str(run_id),
            authority=authority,
            category=category,
            priority=priority,
            lifecycle_state=lifecycle_state,
            limit=limit,
            offset=offset,
        )
    except ProductViewNotFoundError as error:
        raise HTTPException(
            404, detail={"code": "PRODUCT_RUN_NOT_FOUND", "message": "Run not found"}
        ) from error
    except ProductViewNotReadyError as error:
        raise HTTPException(
            409, detail={"code": "PRODUCT_RUN_NOT_READY", "message": "Run findings are not ready"}
        ) from error
    except ProductViewValidationError as error:
        raise HTTPException(
            422, detail={"code": "INVALID_PRODUCT_VIEW", "message": "Product view query is invalid"}
        ) from error
    except ProductViewError as error:
        raise HTTPException(
            503,
            detail={"code": "PRODUCT_VIEW_UNAVAILABLE", "message": "Product view is unavailable"},
        ) from error
    return FindingProductPageResponse.model_validate(page)
