from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status

from securescan.api.job_schemas import (
    ApiErrorResponse,
    JobCancellationApiResponse,
    JobStatusApiResponse,
    JobSubmissionApiRequest,
    JobSubmissionApiResponse,
)
from securescan.jobs import (
    AnalysisRunNotFoundError,
    IdempotencyConflictError,
    JobCancellationConflictError,
    JobCancellationError,
    JobCancellationService,
    JobNotFoundError,
    JobRepository,
    JobRepositoryError,
    JobSubmissionError,
    JobSubmissionRequest,
    JobSubmissionService,
    TargetNotFoundError,
)

router = APIRouter()


def get_job_submission_service(request: Request) -> JobSubmissionService:
    service = getattr(request.app.state, "job_submission_service", None)
    if service is None:
        raise RuntimeError("Job submission service has not been configured")
    return service


def get_job_repository(request: Request) -> JobRepository:
    repository = getattr(request.app.state, "job_repository", None)
    if repository is None:
        raise RuntimeError("Job repository has not been configured")
    return repository


def get_job_cancellation_service(request: Request) -> JobCancellationService:
    service = getattr(request.app.state, "job_cancellation_service", None)
    if service is None:
        raise RuntimeError("Job cancellation service has not been configured")
    return service


@router.post(
    "/v1/jobs",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=JobSubmissionApiResponse,
    responses={
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse},
        status.HTTP_409_CONFLICT: {"model": ApiErrorResponse},
        status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ApiErrorResponse},
    },
)
def submit_job(
    request: JobSubmissionApiRequest,
    service: Annotated[
        JobSubmissionService,
        Depends(get_job_submission_service),
    ],
) -> JobSubmissionApiResponse:
    try:
        result = service.submit(
            JobSubmissionRequest(
                target_id=request.target_id,
                adapter_id=request.adapter_id,
                idempotency_key=request.idempotency_key,
                payload_json=request.payload_json,
                priority=request.priority,
                max_attempts=request.max_attempts,
            )
        )
    except TargetNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "TARGET_NOT_FOUND",
                "message": str(exc),
            },
        ) from exc
    except IdempotencyConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "IDEMPOTENCY_CONFLICT",
                "message": str(exc),
            },
        ) from exc
    except JobSubmissionError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "JOB_SUBMISSION_UNAVAILABLE",
                "message": "Job submission is temporarily unavailable",
            },
        ) from exc

    return JobSubmissionApiResponse(
        run_id=result.run_id,
        job_id=result.job_id,
        status=result.status,
        idempotency_key=result.idempotency_key,
        created=result.created,
    )


@router.get(
    "/v1/jobs/{job_id}",
    status_code=status.HTTP_200_OK,
    response_model=JobStatusApiResponse,
    responses={
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse},
        status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ApiErrorResponse},
    },
)
def get_job_status(
    job_id: UUID,
    repository: Annotated[
        JobRepository,
        Depends(get_job_repository),
    ],
) -> JobStatusApiResponse:
    try:
        record = repository.get_job(str(job_id))
    except JobRepositoryError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "JOB_STATUS_UNAVAILABLE",
                "message": "Job status is temporarily unavailable.",
            },
        ) from exc

    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "JOB_NOT_FOUND",
                "message": "Job was not found.",
            },
        )

    return JobStatusApiResponse(
        job_id=record.id,
        run_id=record.run_id,
        adapter_id=record.adapter_id,
        status=record.status,
        priority=record.priority,
        attempt_count=record.attempt_count,
        max_attempts=record.max_attempts,
        available_at=record.available_at,
        cancel_requested=record.cancel_requested,
        idempotency_key=record.idempotency_key,
        created_at=record.created_at,
        updated_at=record.updated_at,
        started_at=record.started_at,
        finished_at=record.finished_at,
    )


@router.post(
    "/v1/jobs/{job_id}/cancel",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=JobCancellationApiResponse,
    responses={
        status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse},
        status.HTTP_409_CONFLICT: {"model": ApiErrorResponse},
        status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ApiErrorResponse},
    },
)
def cancel_job(
    job_id: UUID,
    service: Annotated[
        JobCancellationService,
        Depends(get_job_cancellation_service),
    ],
) -> JobCancellationApiResponse:
    try:
        result = service.request_cancellation(str(job_id))
    except JobNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "JOB_NOT_FOUND",
                "message": "Job was not found.",
            },
        ) from exc
    except JobCancellationConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "JOB_CANCELLATION_CONFLICT",
                "message": "The job can no longer be cancelled.",
            },
        ) from exc
    except AnalysisRunNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "JOB_CANCELLATION_UNAVAILABLE",
                "message": "Job cancellation is temporarily unavailable.",
            },
        ) from exc
    except JobCancellationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "JOB_CANCELLATION_UNAVAILABLE",
                "message": "Job cancellation is temporarily unavailable.",
            },
        ) from exc

    return JobCancellationApiResponse(
        job_id=result.job.id,
        run_id=result.job.run_id,
        status=result.job.status,
        cancel_requested=result.job.cancel_requested,
        cancel_requested_at=result.job.cancel_requested_at,
        finished_at=result.job.finished_at,
        immediate=result.immediate,
        already_requested=result.already_requested,
    )
