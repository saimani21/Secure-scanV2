from __future__ import annotations

import hashlib
import json
import threading
import webbrowser
from pathlib import Path
from typing import Annotated

import typer

from securescan.adapters.fake_scanner import FakeScannerAdapter
from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.config import Settings, get_operator_settings, get_settings
from securescan.domain.enums import TargetType
from securescan.domain.models import TargetProfile
from securescan.execution.local_executor import LocalProcessExecutor
from securescan.operator.doctor import Doctor
from securescan.operator.manager import OperatorManager
from securescan.operator.models import DoctorReport, OperatorError, SystemStatus
from securescan.operator.profile import (
    OperatorProfileError,
    parse_operator_env_file,
    write_operator_profile,
)
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

from .developer import (
    DEFAULT_POLL_SECONDS,
    project_page_data,
    resolved_wait_timeout,
    validated_poll_seconds,
    wait_for_scan,
    waited_scan_data,
)
from .developer_commands import register_developer_commands
from .presentation import terminal_text
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
system_app = typer.Typer(no_args_is_help=True, help="Operate the local Source service")
app.add_typer(project_app, name="project")
app.add_typer(system_app, name="system")


def _operator_manager() -> OperatorManager:
    return OperatorManager(get_operator_settings())


def _operator_fail(error: Exception, *, json_output: bool) -> None:
    code = error.code if isinstance(error, OperatorError) else "OPERATOR_UNAVAILABLE"
    if isinstance(error, (OperatorError, OperatorProfileError)):
        message = str(error)
    else:
        message = "Operator configuration is invalid"
    if json_output:
        typer.echo(
            canonical_json({"error": {"code": code, "message": message}}),
            err=True,
        )
    else:
        typer.echo(f"Error [{code}]: {message}", err=True)
    raise typer.Exit(5)


def _display_system_status(status: SystemStatus, *, json_output: bool) -> None:
    if json_output:
        typer.echo(canonical_json(status.canonical_data()))
        return
    typer.echo("SecureScan Source v1.1")
    typer.echo("------------------------------")
    typer.echo(f"Database      {status.database.value}")
    typer.echo(f"API           {status.api.value}")
    typer.echo(f"Schema        {status.schema.value}")
    typer.echo(f"Worker        {status.worker.value}")
    typer.echo(f"System        {status.system_status.value}")
    typer.echo(f"UI            {status.ui_url}/")


def _display_doctor(report: DoctorReport, *, json_output: bool) -> None:
    if json_output:
        typer.echo(canonical_json(report.canonical_data()))
        return
    typer.echo("SecureScan Doctor")
    typer.echo("---------------------------------------")
    for check in report.checks:
        typer.echo(f"{check.name:<28} {check.status.value:<4}  {check.detail}")
    typer.echo(f"\nResult: {'READY' if report.ready else 'BLOCKED'}")


@system_app.command("up")
def system_up(
    json_output: Annotated[bool, typer.Option("--json")] = False,
    open_browser: Annotated[bool, typer.Option("--open")] = False,
) -> None:
    """Start PostgreSQL, migrate, start the API, and manage one host worker."""

    try:
        manager = _operator_manager()
        status = manager.up()
        _display_system_status(status, json_output=json_output)
        if not json_output:
            typer.echo("\nSecureScan is ready.")
        if open_browser:
            _open_ui(manager.ui_url)
    except Exception as exc:
        _operator_fail(exc, json_output=json_output)


@system_app.command("down")
def system_down(
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Stop the managed worker and deployment while preserving persistent data."""

    try:
        status = _operator_manager().down()
        _display_system_status(status, json_output=json_output)
        if not json_output:
            typer.echo("\nSecureScan stopped. Persistent data preserved.")
    except Exception as exc:
        _operator_fail(exc, json_output=json_output)


@system_app.command("status")
def system_status(
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Show truthful database, API, schema, and managed-worker state."""

    try:
        _display_system_status(_operator_manager().status(), json_output=json_output)
    except Exception as exc:
        _operator_fail(exc, json_output=json_output)


_PROFILE_PATH_FIELDS = frozenset(
    {
        "deploy_data_root",
        "artifact_root",
        "source_projection_root",
        "source_workspace_root",
        "source_runtime_receipt_root",
        "source_enry_helper_path",
        "source_gitleaks_executable_path",
        "source_syft_executable_path",
        "source_checkov_executable_path",
        "operator_compose_file",
    }
)


@system_app.command("configure")
def system_configure(
    from_env_file: Annotated[
        Path,
        typer.Option("--from-env-file", exists=True, dir_okay=False, readable=True),
    ],
) -> None:
    """Import a controlled KEY=VALUE file into the private operator profile."""

    try:
        values = parse_operator_env_file(from_env_file)
        if not values.keys() <= Settings.model_fields.keys():
            raise OperatorProfileError(
                "Configuration contains unsupported SecureScan settings"
            )
        base = from_env_file.resolve().parent
        for name in _PROFILE_PATH_FIELDS & values.keys():
            path = Path(values[name]).expanduser()
            values[name] = str(
                path if path.is_absolute() else (base / path).resolve()
            )
        settings = Settings(**values, _env_file=None)
        profile = write_operator_profile(settings.model_dump(mode="json"))
        get_operator_settings.cache_clear()
        typer.echo("SecureScan operator profile configured.")
        typer.echo(f"Profile: {profile}")
        typer.echo("Permissions: directory 0700, file 0600")
    except Exception as exc:
        _operator_fail(exc, json_output=False)


@app.command("doctor")
def doctor(
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Run read-only operator prerequisite checks."""

    try:
        report = Doctor(get_operator_settings()).run()
        _display_doctor(report, json_output=json_output)
        if not report.ready:
            raise typer.Exit(5)
    except typer.Exit:
        raise
    except Exception as exc:
        _operator_fail(exc, json_output=json_output)


def _open_ui(url: str) -> None:
    target = f"{url.rstrip('/')}/"
    typer.echo(f"Opening SecureScan:\n{target}")
    try:
        opened = webbrowser.open(target, new=2)
    except Exception:
        opened = False
    if not opened:
        typer.echo(
            "Browser launch was unavailable; open the URL above manually.", err=True
        )
        raise typer.Exit(5)


@app.command("open")
def open_ui() -> None:
    """Open the configured local Source UI in the default browser."""

    try:
        _open_ui(_operator_manager().ui_url)
    except typer.Exit:
        raise
    except Exception as exc:
        _operator_fail(exc, json_output=False)


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
                    terminal_text(item["finding_id"]),
                    terminal_text(item["authority"]),
                    terminal_text(item["category"]),
                    terminal_text(item["severity"] or "-"),
                    terminal_text(item["priority"]),
                    terminal_text(item["lifecycle"]),
                    terminal_text(canonical_json(item["subject"]), limit=4_096),
                    terminal_text(canonical_json(item["primary_location"]), limit=4_096),
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
            typer.echo(f"Name: {terminal_text(project.name)}")
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
    offset: Annotated[int, typer.Option("--offset", min=0)] = 0,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """List bounded durable project identities."""

    try:
        with create_source_cli_services() as services:
            page = list_projects(services, limit=limit, offset=offset)
        data = project_page_data(page)
        if json_output:
            typer.echo(canonical_json(data))
        else:
            typer.echo("Projects")
            for project in page.items:
                created = project.created_at.isoformat()
                typer.echo(
                    f"{terminal_text(project.name)}    {project.project_id}    {created}"
                )
            first = 0 if page.total == 0 else page.offset + 1
            last = page.offset + len(page.items)
            typer.echo(f"Showing {first}–{last} of {page.total}")
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
    wait: Annotated[bool, typer.Option("--wait")] = False,
    wait_timeout_seconds: Annotated[
        int | None,
        typer.Option("--wait-timeout-seconds", min=1, max=86_460),
    ] = None,
    poll_seconds: Annotated[
        float,
        typer.Option("--poll-seconds", min=0.1, max=60.0),
    ] = DEFAULT_POLL_SECONDS,
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
    if not wait and (
        wait_timeout_seconds is not None or poll_seconds != DEFAULT_POLL_SECONDS
    ):
        _fail(
            SourceCliError("INVALID_WAIT_OPTIONS", "Wait options require --wait", 2),
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
            if wait:
                analysis_deadline = (
                    services.default_deadline_seconds
                    if deadline_seconds is None
                    else deadline_seconds
                )
                timeout = resolved_wait_timeout(
                    analysis_deadline_seconds=analysis_deadline,
                    wait_timeout_seconds=wait_timeout_seconds,
                )
                interval = validated_poll_seconds(poll_seconds)
                summary = wait_for_scan(
                    services,
                    result.submission.run_id,
                    timeout_seconds=timeout,
                    poll_seconds=interval,
                )
        if not wait:
            _display_scan_result(scan_result_data(result), json_output=json_output)
            return
        data = waited_scan_data(summary)
        if json_output:
            typer.echo(canonical_json(data))
        else:
            typer.echo("Source scan completed")
            _display_status(data, json_output=False)
    except SourceCliError as exc:
        _fail(exc, json_output=json_output)
    except KeyboardInterrupt:
        _fail(
            SourceCliError(
                "WAIT_INTERRUPTED",
                "Waiting stopped; the durable scan was not cancelled.",
                130,
            ),
            json_output=json_output,
        )
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
        typer.echo(
            canonical_json(
                report_data(published),
                pretty=not json_output,
                ensure_ascii=not json_output,
            )
        )
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


register_developer_commands(app, lambda: create_source_cli_services(), _fail)


if __name__ == "__main__":
    app()
