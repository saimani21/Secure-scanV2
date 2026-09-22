from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path
from typing import Annotated

import typer

from securescan.adapters.fake_scanner import FakeScannerAdapter
from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.config import get_settings
from securescan.domain.enums import TargetType
from securescan.domain.models import TargetProfile
from securescan.execution.local_executor import LocalProcessExecutor
from securescan.persistence.database import initialize_database
from securescan.runtime import shutdown_signal_handlers
from securescan.runtime_storage import (
    RuntimeStorageInitializationError,
    initialize_source_runtime_storage,
)
from securescan.services.scan_service import ScanService
from securescan.source_runtime import (
    SourceRuntimeCycleSummary,
    SourceRuntimeError,
    SourceRuntimeLoop,
    create_source_runtime,
)

from .source import (
    SourceCliError,
    canonical_json,
    create_project,
    create_source_cli_services,
    finding_page_data,
    list_projects,
    query_findings,
    query_report,
    query_scan,
    report_data,
    scan_result_data,
    scan_summary_data,
    submit_local_scan,
)

app = typer.Typer(no_args_is_help=True, help="SecureScan execution-kernel CLI")
project_app = typer.Typer(no_args_is_help=True, help="Manage durable Source projects")
app.add_typer(project_app, name="project")


def _fail(error: SourceCliError, *, json_output: bool) -> None:
    if json_output:
        typer.echo(
            canonical_json(
                {"error": {"code": error.code, "message": str(error)}}
            ),
            err=True,
        )
    else:
        typer.echo(f"Error [{error.code}]: {error}", err=True)
    raise typer.Exit(error.exit_code)


def _display_scan_result(data: dict[str, object], *, json_output: bool) -> None:
    if json_output:
        typer.echo(canonical_json(data))
        return
    typer.echo("Source scan submitted")
    typer.echo(f"Run ID: {data['run_id']}")
    typer.echo(f"Lineage ID: {data['lineage_id']}")
    typer.echo(f"Sequence: {data['submission_sequence']}")
    typer.echo(f"Status: {data['submission_status']}")


def _display_status(data: dict[str, object], *, json_output: bool) -> None:
    if json_output:
        typer.echo(canonical_json(data))
        return
    typer.echo(f"Run ID: {data['run_id']}")
    typer.echo(f"Lineage ID: {data['lineage_id']}")
    typer.echo(f"Sequence: {data['submission_sequence']}")
    typer.echo(f"Status: {data['product_status']}")
    typer.echo(f"Published at: {data['published_at'] or '-'}")
    typer.echo(f"Finalized at: {data['finalized_at'] or '-'}")
    typer.echo(f"Findings: {data['finding_count']}")
    typer.echo(f"Priority counts: {canonical_json(data['priority_counts'])}")
    coverage = data["coverage_complete"]
    coverage_label = "PENDING" if coverage is None else ("COMPLETE" if coverage else "INCOMPLETE")
    typer.echo(f"Coverage: {coverage_label}")
    typer.echo(f"Coverage counts: {canonical_json(data['coverage_counts'])}")
    typer.echo(f"Gaps: {data['gap_count'] if data['gap_count'] is not None else '-'}")


def _display_findings(data: dict[str, object], *, json_output: bool) -> None:
    if json_output:
        typer.echo(canonical_json(data))
        return
    typer.echo(
        f"Findings: {data['total']} (limit {data['limit']}, offset {data['offset']})"
    )
    for item in data["items"]:  # type: ignore[union-attr]
        typer.echo(
            " | ".join(
                (
                    str(item["finding_id"]),
                    str(item["authority"]),
                    str(item["category"]),
                    str(item["severity"] or "-"),
                    str(item["priority"]),
                    str(item["lifecycle"]),
                    canonical_json(item["subject"]),
                    canonical_json(item["primary_location"]),
                )
            )
        )


@project_app.command("create")
def project_create(
    name: Annotated[str, typer.Argument()],
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Create a durable project identity for Source scans."""

    try:
        with create_source_cli_services() as services:
            project = create_project(services, name=name)
        data = {
            "created_at": project.created_at.isoformat(),
            "name": project.name,
            "project_id": project.project_id,
        }
        if json_output:
            typer.echo(canonical_json(data))
        else:
            typer.echo(f"Project ID: {project.project_id}")
            typer.echo(f"Name: {project.name}")
    except SourceCliError as exc:
        _fail(exc, json_output=json_output)
    except Exception:
        _fail(
            SourceCliError("PROJECT_UNAVAILABLE", "Source project service is unavailable", 5),
            json_output=json_output,
        )


@project_app.command("list")
def project_list(
    limit: Annotated[int, typer.Option("--limit", min=1, max=200)] = 100,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """List bounded durable project identities."""

    try:
        with create_source_cli_services() as services:
            projects = list_projects(services, limit=limit)
        items = [
            {
                "created_at": project.created_at.isoformat(),
                "name": project.name,
                "project_id": project.project_id,
            }
            for project in projects
        ]
        if json_output:
            typer.echo(canonical_json({"items": items, "limit": limit, "total": len(items)}))
        else:
            for project in projects:
                typer.echo(f"{project.project_id}  {project.name}")
    except SourceCliError as exc:
        _fail(exc, json_output=json_output)
    except Exception:
        _fail(
            SourceCliError("PROJECT_UNAVAILABLE", "Source project service is unavailable", 5),
            json_output=json_output,
        )


@app.command("scan")
def scan(
    path: Annotated[Path, typer.Argument()] = Path("."),
    project_id: Annotated[
        str,
        typer.Option("--project-id", help="Existing durable project UUID"),
    ] = "",
    lineage_id: Annotated[
        str | None,
        typer.Option("--lineage-id", help="Existing Source lineage UUID"),
    ] = None,
    deadline_seconds: Annotated[
        int | None,
        typer.Option("--deadline-seconds", min=300, max=86_400),
    ] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Prepare a local repository and submit an asynchronous Source scan."""

    if not project_id:
        _fail(
            SourceCliError(
                "SUBMISSION_CONFLICT", "An existing --project-id is required", 2
            ),
            json_output=json_output,
        )
    try:
        with create_source_cli_services() as services:
            result = submit_local_scan(
                services,
                source_path=path,
                project_id=project_id,
                lineage_id=lineage_id,
                deadline_seconds=deadline_seconds,
            )
        _display_scan_result(scan_result_data(result), json_output=json_output)
    except SourceCliError as exc:
        _fail(exc, json_output=json_output)
    except Exception:
        _fail(
            SourceCliError(
                "SUBMISSION_UNAVAILABLE", "Source scan submission is unavailable", 5
            ),
            json_output=json_output,
        )


@app.command("status")
def status(
    run_id: Annotated[str, typer.Argument()],
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Show durable Product Core status and coverage for a Source scan."""

    try:
        with create_source_cli_services() as services:
            summary = query_scan(services, run_id)
        _display_status(scan_summary_data(summary), json_output=json_output)
    except SourceCliError as exc:
        _fail(exc, json_output=json_output)
    except Exception:
        _fail(
            SourceCliError("QUERY_UNAVAILABLE", "Source scan query is unavailable", 5),
            json_output=json_output,
        )


@app.command("findings")
def findings(
    run_id: Annotated[str, typer.Argument()],
    authority: Annotated[str | None, typer.Option("--authority")] = None,
    category: Annotated[str | None, typer.Option("--category")] = None,
    priority: Annotated[str | None, typer.Option("--priority")] = None,
    lifecycle: Annotated[str | None, typer.Option("--lifecycle")] = None,
    limit: Annotated[int, typer.Option("--limit")] = 50,
    offset: Annotated[int, typer.Option("--offset")] = 0,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """List bounded Product Core finding summaries for a Source scan."""

    try:
        with create_source_cli_services() as services:
            page = query_findings(
                services,
                run_id,
                authority=authority,
                category=category,
                priority=priority,
                lifecycle_state=lifecycle,
                limit=limit,
                offset=offset,
            )
        _display_findings(finding_page_data(page), json_output=json_output)
    except SourceCliError as exc:
        _fail(exc, json_output=json_output)
    except Exception:
        _fail(
            SourceCliError("QUERY_UNAVAILABLE", "Source scan query is unavailable", 5),
            json_output=json_output,
        )


@app.command("report")
def report(
    run_id: Annotated[str, typer.Argument()],
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Print the verified published S4 report for a Source scan."""

    try:
        with create_source_cli_services() as services:
            published = query_report(services, run_id)
        typer.echo(canonical_json(report_data(published), pretty=not json_output))
    except SourceCliError as exc:
        _fail(exc, json_output=json_output)
    except Exception:
        _fail(
            SourceCliError("QUERY_UNAVAILABLE", "Source scan query is unavailable", 5),
            json_output=json_output,
        )


@app.command("worker")
def worker(
    once: Annotated[
        bool,
        typer.Option("--once", help="Execute one bounded durable runtime cycle"),
    ] = False,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Progress durable Source scans continuously or through one bounded cycle."""

    def summary_failed(summary: SourceRuntimeCycleSummary) -> bool:
        return bool(summary.assembly_failed_count or summary.finalization_failed_count)

    def emit_summary(summary: SourceRuntimeCycleSummary) -> None:
        rendered = canonical_json(summary.canonical_data())
        typer.echo(rendered, err=summary_failed(summary))

    try:
        if once:
            with create_source_runtime() as composition:
                summary = composition.runtime.run_once()
            emit_summary(summary)
            if summary_failed(summary):
                raise typer.Exit(5)
            return

        stop_event = threading.Event()
        settings = get_settings()
        with (
            shutdown_signal_handlers(stop_event),
            create_source_runtime(settings) as composition,
        ):
            SourceRuntimeLoop(
                composition.runtime,
                stop_event,
                poll_seconds=settings.source_worker_poll_seconds,
                on_cycle=emit_summary,
            ).run()
    except typer.Exit:
        raise
    except SourceRuntimeError as exc:
        if exc.code == "RUNTIME_UNAVAILABLE" and exc.phase == "runtime_cycle":
            typer.echo(
                "Error [RUNTIME_UNAVAILABLE]: Source runtime cycle is unavailable",
                err=True,
            )
            raise typer.Exit(5) from None
        data = {
            "error": {
                "code": exc.code,
                "message": str(exc),
                "phase": exc.phase,
                "remediation": exc.remediation,
            }
        }
        if json_output:
            typer.echo(canonical_json(data), err=True)
        else:
            typer.echo(f"Error [{exc.code}]: {exc}", err=True)
            typer.echo(f"Phase: {exc.phase}", err=True)
            typer.echo(f"Remediation: {exc.remediation}", err=True)
        raise typer.Exit(5) from None
    except Exception:
        typer.echo(
            "Error [RUNTIME_UNAVAILABLE]: Source runtime cycle is unavailable",
            err=True,
        )
        raise typer.Exit(5) from None


@app.command("init")
def initialize_runtime(
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Initialize and validate private Source runtime storage."""

    try:
        initialized = initialize_source_runtime_storage(get_settings())
    except RuntimeStorageInitializationError as exc:
        error = SourceCliError(exc.code, f"{exc} (phase: {exc.phase})", 5)
        _fail(error, json_output=json_output)
    data = initialized.canonical_data()
    if json_output:
        typer.echo(canonical_json(data))
    else:
        typer.echo("SecureScan runtime storage initialized")
        typer.echo(f"Deployment root: {data['deployment_root'] or '-'}")
        typer.echo(f"Artifact root: {data['artifact_root']}")
        typer.echo(f"Workspace root: {data['workspace_root']}")
        typer.echo(f"Projection root: {data['projection_root']}")
        typer.echo(f"Runtime receipt root: {data['receipt_root']}")


@app.command("init-db")
def init_db() -> None:
    initialize_database(get_settings())
    typer.echo("Database initialized")


@app.command("run-fake")
def run_fake(
    path: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=False,
            resolve_path=True,
        ),
    ] = Path("."),
    mode: Annotated[str, typer.Option(help="Fake scanner behavior mode")] = "findings",
    timeout_seconds: Annotated[int, typer.Option(min=1, max=60)] = 5,
    max_output_bytes: Annotated[int, typer.Option(min=1024)] = 262_144,
) -> None:
    settings = get_settings()
    target = TargetProfile(
        target_type=TargetType.SOURCE_REPOSITORY,
        path=path,
        content_digest=hashlib.sha256(str(path).encode()).hexdigest(),
        metadata={"test_only": True},
    )
    service = ScanService(
        executor=LocalProcessExecutor(),
        artifact_store=ContentAddressedArtifactStore(settings.artifact_root),
    )
    report = service.run(
        FakeScannerAdapter(settings.hmac_key),
        target,
        mode=mode,
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
    )
    typer.echo(json.dumps(report.model_dump(mode="json"), indent=2))


if __name__ == "__main__":
    app()
