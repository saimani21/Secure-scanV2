"""Explicit exact-run finding presentation over the H read-only projection."""

from __future__ import annotations

from dataclasses import asdict

import typer

from securescan.product_core.product_view import (
    FindingProductPage,
    ProductViewError,
    ProductViewNotFoundError,
    ProductViewNotReadyError,
    ProductViewValidationError,
)

from .presentation import terminal_text
from .source import SourceCliError, SourceCliServices, canonical_json, query_scan


def query_exact_run_findings(
    services: SourceCliServices,
    run_id: str,
    *,
    authority: str | None,
    category: str | None,
    priority: str | None,
    lifecycle_state: str | None,
    limit: int,
    offset: int,
) -> FindingProductPage:
    summary = query_scan(services, run_id)
    if services.product_findings is None:
        raise SourceCliError("PRODUCT_VIEW_UNAVAILABLE", "Exact-run findings are unavailable", 5)
    try:
        return services.product_findings.list_for_run(
            project_id=summary.project_id,
            lineage_id=summary.lineage_id,
            run_id=summary.run_id,
            authority=authority,
            category=category,
            priority=priority,
            lifecycle_state=lifecycle_state,
            limit=limit,
            offset=offset,
        )
    except ProductViewNotFoundError:
        raise SourceCliError("PRODUCT_RUN_NOT_FOUND", "Run was not found", 3) from None
    except ProductViewNotReadyError:
        raise SourceCliError("PRODUCT_RUN_NOT_READY", "Run findings are not ready", 3) from None
    except ProductViewValidationError:
        raise SourceCliError("INVALID_PRODUCT_VIEW", "Finding query is invalid", 2) from None
    except ProductViewError:
        raise SourceCliError(
            "PRODUCT_VIEW_UNAVAILABLE", "Exact-run findings are unavailable", 5
        ) from None


def display_exact_run_findings(page: FindingProductPage, *, json_output: bool) -> None:
    if json_output:
        typer.echo(canonical_json(asdict(page)))
        return
    typer.echo(f"Findings at this scan: {page.total} (limit {page.limit}, offset {page.offset})")
    for item in page.items:
        typer.echo(
            " | ".join(
                (
                    item.finding_id,
                    item.authority,
                    item.priority_band,
                    item.lifecycle_state_at_run,
                    terminal_text(canonical_json(item.subject), limit=4_096),
                )
            )
        )
