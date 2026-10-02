from __future__ import annotations

import base64
import binascii
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, ConfigDict, Field

from securescan.intelligence import (
    AssuranceService,
    IntelligenceService,
    IntelligenceSource,
    ThreatPolicySpec,
)
from securescan.intelligence.models import IntelligenceSnapshot
from securescan.intelligence.service import IntelligenceServiceError

router = APIRouter(prefix="/v1/intelligence", tags=["intelligence"])


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ImportRequest(_StrictModel):
    source: Literal["CISA_KEV", "FIRST_EPSS", "NVD"]
    content_base64: str = Field(min_length=1)
    cve_id: str | None = None
    retrieved_at: datetime | None = None


class BundleRequest(_StrictModel):
    kev_snapshot_id: str | None = None
    epss_snapshot_id: str | None = None
    nvd_enrichment_ids: tuple[str, ...] = ()


class EvaluateRequest(_StrictModel):
    project_id: str
    lineage_id: str
    run_id: str
    bundle_id: str
    evaluated_at: datetime | None = None


class PolicyProofRequest(EvaluateRequest):
    threat_policy: ThreatPolicySpec


def get_intelligence_service(request: Request) -> IntelligenceService:
    service = getattr(request.app.state, "intelligence_service", None)
    if not isinstance(service, IntelligenceService):
        raise HTTPException(status_code=503, detail="Intelligence service is unavailable")
    return service


def get_assurance_service(request: Request) -> AssuranceService:
    service = getattr(request.app.state, "assurance_service", None)
    if not isinstance(service, AssuranceService):
        raise HTTPException(status_code=503, detail="Assurance service is unavailable")
    return service


def _fail(error: Exception) -> HTTPException:
    if isinstance(error, (ValueError, binascii.Error)):
        return HTTPException(status_code=422, detail="Intelligence request is invalid")
    if isinstance(error, IntelligenceServiceError):
        return HTTPException(status_code=409, detail=str(error))
    return HTTPException(status_code=503, detail="Intelligence operation is unavailable")


def _snapshot_data(snapshot: IntelligenceSnapshot) -> dict:
    data = jsonable_encoder(snapshot)
    data.pop("records", None)
    return data


@router.post("/imports")
def import_intelligence(
    body: ImportRequest,
    service: Annotated[IntelligenceService, Depends(get_intelligence_service)],
) -> dict:
    try:
        payload = base64.b64decode(body.content_base64, validate=True)
        if body.source == "CISA_KEV":
            if body.cve_id is not None:
                raise ValueError
            result = service.import_kev(payload, retrieved_at=body.retrieved_at)
        elif body.source == "FIRST_EPSS":
            if body.cve_id is not None:
                raise ValueError
            result = service.import_epss(payload, retrieved_at=body.retrieved_at)
        else:
            if body.cve_id is None:
                raise ValueError
            result = service.import_nvd(
                payload,
                expected_cve=body.cve_id,
                retrieved_at=body.retrieved_at,
            )
        return (
            _snapshot_data(result)
            if isinstance(result, IntelligenceSnapshot)
            else jsonable_encoder(result)
        )
    except Exception as error:
        raise _fail(error) from None


@router.get("/snapshots")
def list_snapshots(
    service: Annotated[IntelligenceService, Depends(get_intelligence_service)],
    source: Annotated[IntelligenceSource | None, Query()] = None,
) -> list[dict]:
    try:
        return [_snapshot_data(item) for item in service.list_snapshots(source)]
    except Exception as error:
        raise _fail(error) from None


@router.post("/bundles")
def create_bundle(
    body: BundleRequest,
    service: Annotated[IntelligenceService, Depends(get_intelligence_service)],
) -> dict:
    try:
        return jsonable_encoder(service.create_bundle(**body.model_dump()))
    except Exception as error:
        raise _fail(error) from None


@router.post("/threat-assessments")
def evaluate_threat(
    body: EvaluateRequest,
    service: Annotated[IntelligenceService, Depends(get_intelligence_service)],
) -> list[dict]:
    try:
        return jsonable_encoder(service.evaluate_run(**body.model_dump()))
    except Exception as error:
        raise _fail(error) from None


@router.get("/runs/{run_id}/findings")
def finding_intelligence(
    run_id: str,
    project_id: str,
    lineage_id: str,
    service: Annotated[AssuranceService, Depends(get_assurance_service)],
    bundle_id: str | None = None,
) -> list[dict]:
    try:
        return jsonable_encoder(
            service.finding_intelligence(
                project_id=project_id,
                lineage_id=lineage_id,
                run_id=run_id,
                bundle_id=bundle_id,
            )
        )
    except Exception as error:
        raise _fail(error) from None


@router.get("/runs/{run_id}/assurance")
def run_assurance(
    run_id: str,
    project_id: str,
    lineage_id: str,
    service: Annotated[AssuranceService, Depends(get_assurance_service)],
    bundle_id: str | None = None,
) -> dict:
    try:
        return jsonable_encoder(
            service.run_assurance_view(
                project_id=project_id,
                lineage_id=lineage_id,
                run_id=run_id,
                bundle_id=bundle_id,
            )
        )
    except Exception as error:
        raise _fail(error) from None


@router.post("/policy-proofs")
def evaluate_policy_proof(
    body: PolicyProofRequest,
    service: Annotated[AssuranceService, Depends(get_assurance_service)],
) -> dict:
    try:
        return jsonable_encoder(service.evaluate_policy(**body.model_dump()))
    except Exception as error:
        raise _fail(error) from None
