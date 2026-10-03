from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict, Field

from securescan.product_release import (
    AIContextBuilder,
    AIProviderError,
    AITask,
    ProductAssuranceError,
    ProductAssuranceService,
    render_assessment_html,
)

router = APIRouter(prefix="/v1/assurance", tags=["V1.5 product assurance"])


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AssistantRequest(_StrictModel):
    project_id: str
    lineage_id: str
    bundle_id: str
    proof_id: str
    task: AITask
    question: str = Field(min_length=1, max_length=2_000)
    finding_id: str | None = None


def get_product_service(request: Request) -> ProductAssuranceService:
    service = getattr(request.app.state, "product_assurance_service", None)
    if not isinstance(service, ProductAssuranceService):
        raise HTTPException(503, detail="Product assurance is unavailable")
    return service


def _error(error: Exception) -> HTTPException:
    if isinstance(error, ProductAssuranceError):
        return HTTPException(409, detail=str(error))
    if isinstance(error, AIProviderError):
        return HTTPException(503, detail=str(error))
    return HTTPException(503, detail="Product assurance is unavailable")


@router.get("/runs/{run_id}")
def assurance_dashboard(
    run_id: str,
    project_id: str,
    lineage_id: str,
    bundle_id: str,
    proof_id: str,
    service: Annotated[ProductAssuranceService, Depends(get_product_service)],
) -> dict:
    try:
        return service.dashboard(
            project_id=project_id,
            lineage_id=lineage_id,
            run_id=run_id,
            bundle_id=bundle_id,
            proof_id=proof_id,
        )
    except Exception as error:
        raise _error(error) from None


@router.get("/runs/{run_id}/findings/{finding_id}")
def finding_knowledge_card(
    run_id: str,
    finding_id: str,
    project_id: str,
    lineage_id: str,
    bundle_id: str,
    proof_id: str,
    service: Annotated[ProductAssuranceService, Depends(get_product_service)],
) -> dict:
    try:
        return service.knowledge_card(
            project_id=project_id,
            lineage_id=lineage_id,
            run_id=run_id,
            finding_id=finding_id,
            bundle_id=bundle_id,
            proof_id=proof_id,
        )
    except Exception as error:
        raise _error(error) from None


@router.get("/runs/{run_id}/assessment.html", response_class=HTMLResponse)
def html_assessment(
    run_id: str,
    project_id: str,
    lineage_id: str,
    bundle_id: str,
    proof_id: str,
    service: Annotated[ProductAssuranceService, Depends(get_product_service)],
) -> HTMLResponse:
    try:
        dashboard = service.dashboard(
            project_id=project_id,
            lineage_id=lineage_id,
            run_id=run_id,
            bundle_id=bundle_id,
            proof_id=proof_id,
        )
        return HTMLResponse(
            render_assessment_html(dashboard),
            headers={
                "Content-Security-Policy": (
                    "default-src 'none'; img-src 'none'; style-src 'unsafe-inline'; "
                    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
                ),
                "X-Content-Type-Options": "nosniff",
            },
        )
    except Exception as error:
        raise _error(error) from None


@router.post("/runs/{run_id}/assistant")
def assistant(
    run_id: str,
    body: AssistantRequest,
    request: Request,
    service: Annotated[ProductAssuranceService, Depends(get_product_service)],
) -> dict:
    provider = getattr(request.app.state, "ai_provider", None)
    builder = getattr(request.app.state, "ai_context_builder", None)
    if provider is None or not isinstance(builder, AIContextBuilder):
        raise HTTPException(503, detail="AI Assistant is not configured")
    try:
        dashboard = service.dashboard(
            project_id=body.project_id,
            lineage_id=body.lineage_id,
            run_id=run_id,
            bundle_id=body.bundle_id,
            proof_id=body.proof_id,
        )
        card = None
        if body.finding_id is not None:
            card = service.knowledge_card(
                project_id=body.project_id,
                lineage_id=body.lineage_id,
                run_id=run_id,
                finding_id=body.finding_id,
                bundle_id=body.bundle_id,
                proof_id=body.proof_id,
            )
        context = builder.build(
            task=body.task,
            question=body.question,
            dashboard=dashboard,
            knowledge_card=card,
            allow_source_snippets=request.app.state.ai_allow_source_snippets,
        )
        return provider.explain(
            task=body.task,
            question=body.question,
            context=context,
        ).canonical_data()
    except Exception as error:
        raise _error(error) from None
