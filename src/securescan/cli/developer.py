from __future__ import annotations

from typing import Any

from securescan.product_core import (
    SourceCoverageSummary,
    SourceDependencySummary,
    SourceGapSummary,
    SourceProductStatus,
    SourceProjectError,
    SourceProjectNotFoundError,
    SourceProjectPage,
    SourceScanListItem,
    SourceScanPage,
    SourceScanQueryError,
    SourceScanStages,
    SourceScanSummary,
)

from .source import (
    SourceCliError,
    SourceCliServices,
    _canonical_uuid,
    _datetime,
    _plain,
    query_scan,
    scan_summary_data,
    translate_query_error,
)

DEFAULT_POLL_SECONDS = 2.0
FINALIZATION_ALLOWANCE_SECONDS = 60
MAX_WAIT_TIMEOUT_SECONDS = 86_460
MIN_POLL_SECONDS = 0.1
MAX_POLL_SECONDS = 60.0

_WAITING_STATUSES = frozenset(
    {
        SourceProductStatus.QUEUED,
        SourceProductStatus.RUNNING,
        SourceProductStatus.PUBLISHED_PENDING_FINALIZATION,
    }
)
_FAILED_STATUSES = frozenset(
    {
        SourceProductStatus.FAILED,
        SourceProductStatus.CANCELLED,
        SourceProductStatus.BLOCKED_BY_PREDECESSOR,
    }
)


def resolved_wait_timeout(
    *, analysis_deadline_seconds: int, wait_timeout_seconds: int | None
) -> int:
    value = (
        analysis_deadline_seconds + FINALIZATION_ALLOWANCE_SECONDS
        if wait_timeout_seconds is None
        else wait_timeout_seconds
    )
    if type(value) is not int or not 1 <= value <= MAX_WAIT_TIMEOUT_SECONDS:
        raise SourceCliError(
            "INVALID_WAIT_TIMEOUT",
            f"Wait timeout must be between 1 and {MAX_WAIT_TIMEOUT_SECONDS} seconds",
            2,
        )
    return value


def validated_poll_seconds(value: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, int | float)
        or not MIN_POLL_SECONDS <= value <= MAX_POLL_SECONDS
    ):
        raise SourceCliError(
            "INVALID_POLL_INTERVAL",
            "Poll interval must be between 0.1 and 60 seconds",
            2,
        )
    return float(value)


def wait_for_scan(
    services: SourceCliServices,
    run_id: str,
    *,
    timeout_seconds: int,
    poll_seconds: float,
) -> SourceScanSummary:
    timeout = resolved_wait_timeout(
        analysis_deadline_seconds=timeout_seconds,
        wait_timeout_seconds=timeout_seconds,
    )
    interval = validated_poll_seconds(poll_seconds)
    started = services.monotonic()
    while True:
        summary = query_scan(services, run_id)
        if summary.product_status is SourceProductStatus.COMPLETED:
            return summary
        if summary.product_status in _FAILED_STATUSES:
            raise SourceCliError(
                f"SCAN_{summary.product_status.value}",
                (
                    f"Source scan ended in {summary.product_status.value}; "
                    "findings were not treated as policy failure"
                ),
                5,
            )
        if summary.product_status not in _WAITING_STATUSES:
            raise SourceCliError(
                "WAIT_UNAVAILABLE", "Source scan wait is unavailable", 5
            )
        elapsed = services.monotonic() - started
        remaining = timeout - elapsed
        if remaining <= 0:
            raise SourceCliError(
                "WAIT_TIMEOUT",
                "Waiting stopped; the durable scan was not cancelled.",
                5,
            )
        try:
            services.sleep(min(interval, remaining))
        except KeyboardInterrupt:
            raise SourceCliError(
                "WAIT_INTERRUPTED",
                "Waiting stopped; the durable scan was not cancelled.",
                130,
            ) from None


def query_scans(
    services: SourceCliServices,
    *,
    project_id: str | None,
    limit: int,
    offset: int,
) -> SourceScanPage[SourceScanListItem]:
    project = (
        None
        if project_id is None
        else _canonical_uuid(project_id, code="INVALID_PROJECT")
    )
    try:
        return services.queries.list_scans(
            project_id=project, limit=limit, offset=offset
        )
    except SourceProjectNotFoundError:
        raise SourceCliError("PROJECT_NOT_FOUND", "Source project was not found", 3) from None
    except SourceProjectError:
        raise SourceCliError(
            "PROJECT_QUERY_UNAVAILABLE", "Source project query is unavailable", 5
        ) from None
    except SourceScanQueryError as exc:
        raise translate_query_error(exc) from None


def query_stages(services: SourceCliServices, run_id: str) -> SourceScanStages:
    try:
        return services.queries.get_stages(
            _canonical_uuid(run_id, code="SCAN_NOT_FOUND")
        )
    except SourceCliError:
        raise
    except SourceScanQueryError as exc:
        raise translate_query_error(exc) from None


def query_dependencies(
    services: SourceCliServices, run_id: str, *, limit: int, offset: int
) -> SourceScanPage[SourceDependencySummary]:
    try:
        return services.queries.list_dependencies(
            _canonical_uuid(run_id, code="SCAN_NOT_FOUND"),
            limit=limit,
            offset=offset,
        )
    except SourceCliError:
        raise
    except SourceScanQueryError as exc:
        raise translate_query_error(exc) from None


def query_coverage(services: SourceCliServices, run_id: str) -> SourceCoverageSummary:
    try:
        return services.queries.get_coverage(
            _canonical_uuid(run_id, code="SCAN_NOT_FOUND")
        )
    except SourceCliError:
        raise
    except SourceScanQueryError as exc:
        raise translate_query_error(exc) from None


def query_gaps(
    services: SourceCliServices,
    run_id: str,
    *,
    authority: str | None,
    limit: int,
    offset: int,
) -> SourceScanPage[SourceGapSummary]:
    try:
        return services.queries.list_gaps(
            _canonical_uuid(run_id, code="SCAN_NOT_FOUND"),
            authority=authority,
            limit=limit,
            offset=offset,
        )
    except SourceCliError:
        raise
    except SourceScanQueryError as exc:
        raise translate_query_error(exc) from None


def project_page_data(page: SourceProjectPage) -> dict[str, Any]:
    return {
        "items": [
            {
                "created_at": _datetime(item.created_at),
                "name": item.name,
                "project_id": item.project_id,
            }
            for item in page.items
        ],
        "limit": page.limit,
        "offset": page.offset,
        "total": page.total,
    }


def scan_page_data(page: SourceScanPage[SourceScanListItem]) -> dict[str, Any]:
    return {
        "items": [
            {
                "created_at": _datetime(item.created_at),
                "finalized_at": _datetime(item.finalized_at),
                "indexed": item.indexed,
                "lifecycle_evaluated": item.lifecycle_evaluated,
                "lineage_id": item.lineage_id,
                "predecessor_run_id": item.predecessor_run_id,
                "product_status": item.product_status.value,
                "project_id": item.project_id,
                "published_at": _datetime(item.published_at),
                "run_id": item.run_id,
                "submission_sequence_number": item.submission_sequence_number,
                "target_id": item.target_id,
            }
            for item in page.items
        ],
        "limit": page.limit,
        "offset": page.offset,
        "total": page.total,
    }


def stages_data(value: SourceScanStages) -> dict[str, Any]:
    return {
        "finalized_at": _datetime(value.finalized_at),
        "product_status": value.product_status.value,
        "published_at": _datetime(value.published_at),
        "run_id": value.run_id,
        "stages": [
            {
                "authority": item.authority,
                "capability": item.capability,
                "coverage_states": (
                    None if item.coverage_states is None else list(item.coverage_states)
                ),
                "progress_state": item.progress_state.value,
                "reason_code": item.reason_code,
            }
            for item in value.stages
        ],
    }


def dependency_page_data(
    page: SourceScanPage[SourceDependencySummary],
) -> dict[str, Any]:
    return {
        "items": [
            {
                "advisories": [
                    {
                        "aliases": list(advisory.aliases),
                        "canonical_advisory_id": advisory.canonical_advisory_id,
                        "cve_aliases": list(advisory.cve_aliases),
                        "finding_id": advisory.finding_id,
                        "fixed_versions": list(advisory.fixed_versions),
                        "ghsa_aliases": list(advisory.ghsa_aliases),
                        "osv_record_ids": list(advisory.osv_record_ids),
                        "priority_band": advisory.priority_band,
                    }
                    for advisory in item.advisories
                ],
                "advisory_aliases": list(item.advisory_aliases),
                "component_ref": item.component_ref,
                "fixed_versions": list(item.fixed_versions),
                "known_vulnerability_count": item.known_vulnerability_count,
                "locations": _plain(item.locations),
                "name": item.name,
                "package_type": item.package_type,
                "priority_bands": list(item.priority_bands),
                "purl": item.purl,
                "version": item.version,
                "vulnerability_evaluation": item.vulnerability_evaluation,
                "vulnerability_evaluation_reason": item.vulnerability_evaluation_reason,
            }
            for item in page.items
        ],
        "limit": page.limit,
        "offset": page.offset,
        "total": page.total,
    }


def coverage_data(value: SourceCoverageSummary) -> dict[str, Any]:
    return {
        "complete": value.complete,
        "counts_by_state": dict(value.counts_by_state),
        "outcomes": [_plain(item) for item in value.outcomes],
    }


def gap_page_data(page: SourceScanPage[SourceGapSummary]) -> dict[str, Any]:
    return {
        "items": [
            {
                "authority": item.authority,
                "code": item.code,
                "gap_id": item.gap_id,
                "message": item.message,
                "scope": _plain(item.scope),
            }
            for item in page.items
        ],
        "limit": page.limit,
        "offset": page.offset,
        "total": page.total,
    }


def waited_scan_data(summary: SourceScanSummary) -> dict[str, Any]:
    data = scan_summary_data(summary)
    data["submission_status"] = "SUBMITTED"
    return data
