from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Annotated, Any

import typer

from .developer import (
    coverage_data,
    dependency_page_data,
    gap_page_data,
    query_coverage,
    query_dependencies,
    query_gaps,
    query_scans,
    query_stages,
    scan_page_data,
    stages_data,
)
from .output import write_private_atomic
from .presentation import terminal_text
from .sarif import build_sarif_bytes
from .source import SourceCliError, SourceCliServices, canonical_json

_CAPABILITY_LABELS = {
    "python_sast": "SAST",
    "secret_detection": "Secrets",
    "package_inventory": "Package inventory",
    "dependency_advisory_matching": "Dependency vulnerabilities",
    "configuration_security": "Configuration security",
}


def register_developer_commands(
    app: typer.Typer,
    services_factory: Callable[[], AbstractContextManager[SourceCliServices]],
    fail: Callable[..., Any],
) -> None:
    @app.command("scans")
    def scans(
        project_id: Annotated[str | None, typer.Option("--project-id")] = None,
        limit: Annotated[int, typer.Option("--limit", min=1, max=200)] = 50,
        offset: Annotated[int, typer.Option("--offset", min=0)] = 0,
        json_output: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        """List bounded global or project-filtered Source scan history."""

        try:
            with services_factory() as services:
                page = query_scans(
                    services, project_id=project_id, limit=limit, offset=offset
                )
            data = scan_page_data(page)
            if json_output:
                typer.echo(canonical_json(data))
                return
            typer.echo("Scans")
            typer.echo("Run | Project | Status | Created | Published | Finalized | Sequence")
            for item in page.items:
                typer.echo(
                    " | ".join(
                        (
                            item.run_id,
                            item.project_id,
                            item.product_status.value,
                            item.created_at.isoformat(),
                            "-" if item.published_at is None else item.published_at.isoformat(),
                            "-" if item.finalized_at is None else item.finalized_at.isoformat(),
                            str(item.submission_sequence_number),
                        )
                    )
                )
            _showing(page.offset, len(page.items), page.total)
        except SourceCliError as exc:
            fail(exc, json_output=json_output)
        except Exception:
            fail(_query_unavailable(), json_output=json_output)

    @app.command("stages")
    def stages(
        run_id: Annotated[str, typer.Argument()],
        json_output: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        """Show exact execution progress and separate coverage states."""

        try:
            with services_factory() as services:
                value = query_stages(services, run_id)
            if json_output:
                typer.echo(canonical_json(stages_data(value)))
                return
            typer.echo("Analysis")
            for item in value.stages:
                label = _CAPABILITY_LABELS.get(item.capability, item.capability)
                typer.echo(f"{terminal_text(label):<30} {item.progress_state.value}")
                if item.coverage_states is not None:
                    coverage = ", ".join(item.coverage_states) or "NONE"
                    typer.echo(f"  Coverage                    {coverage}")
                if item.reason_code is not None:
                    typer.echo(f"  Reason                      {item.reason_code}")
        except SourceCliError as exc:
            fail(exc, json_output=json_output)
        except Exception:
            fail(_query_unavailable(), json_output=json_output)

    @app.command("dependencies")
    def dependencies(
        run_id: Annotated[str, typer.Argument()],
        limit: Annotated[int, typer.Option("--limit", min=1, max=200)] = 50,
        offset: Annotated[int, typer.Option("--offset", min=0)] = 0,
        json_output: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        """List bounded Product Core dependency projections."""

        try:
            with services_factory() as services:
                page = query_dependencies(
                    services, run_id, limit=limit, offset=offset
                )
            if json_output:
                typer.echo(canonical_json(dependency_page_data(page)))
                return
            typer.echo("Dependencies")
            for item in page.items:
                version = item.version or "unknown version"
                typer.echo(f"{terminal_text(item.name)} {terminal_text(version)}")
                typer.echo(f"  Evaluation             {item.vulnerability_evaluation}")
                known = _known_vulnerabilities(
                    item.vulnerability_evaluation, item.known_vulnerability_count
                )
                typer.echo(
                    f"  Known vulnerabilities  {known}"
                )
                typer.echo(f"  Observed advisories    {len(item.advisories)}")
                if item.vulnerability_evaluation_reason is not None:
                    reason = terminal_text(item.vulnerability_evaluation_reason)
                    typer.echo(
                        f"  Reason                 {reason}"
                    )
            _showing(page.offset, len(page.items), page.total)
        except SourceCliError as exc:
            fail(exc, json_output=json_output)
        except Exception:
            fail(_query_unavailable(), json_output=json_output)

    @app.command("coverage")
    def coverage(
        run_id: Annotated[str, typer.Argument()],
        json_output: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        """Show exact Product Core coverage outcomes without scores."""

        try:
            with services_factory() as services:
                value = query_coverage(services, run_id)
            if json_output:
                typer.echo(canonical_json(coverage_data(value)))
                return
            typer.echo("Coverage")
            for outcome in value.outcomes:
                capability = str(outcome.get("capability", "unknown"))
                label = _CAPABILITY_LABELS.get(capability, capability)
                state = str(outcome.get("state", "UNKNOWN"))
                qualifier = _coverage_qualifier(outcome)
                typer.echo(
                    f"{terminal_text(label):<30} {terminal_text(state)}{qualifier}"
                )
            typer.echo(f"Complete                      {'YES' if value.complete else 'NO'}")
        except SourceCliError as exc:
            fail(exc, json_output=json_output)
        except Exception:
            fail(_query_unavailable(), json_output=json_output)

    @app.command("gaps")
    def gaps(
        run_id: Annotated[str, typer.Argument()],
        authority: Annotated[str | None, typer.Option("--authority")] = None,
        limit: Annotated[int, typer.Option("--limit", min=1, max=200)] = 50,
        offset: Annotated[int, typer.Option("--offset", min=0)] = 0,
        json_output: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        """List bounded Product Core analysis gaps."""

        try:
            with services_factory() as services:
                page = query_gaps(
                    services,
                    run_id,
                    authority=authority,
                    limit=limit,
                    offset=offset,
                )
            if json_output:
                typer.echo(canonical_json(gap_page_data(page)))
                return
            typer.echo("Gaps")
            for item in page.items:
                capability = (
                    item.scope.get("value", "-")
                    if item.scope.get("kind") == "CAPABILITY"
                    else "-"
                )
                message = "-" if item.message is None else terminal_text(item.message)
                scope = terminal_text(canonical_json(item.scope), limit=4_096)
                typer.echo(
                    " | ".join(
                        (
                            terminal_text(item.authority),
                            terminal_text(capability),
                            terminal_text(item.code),
                            scope,
                            message,
                        )
                    )
                )
            _showing(page.offset, len(page.items), page.total)
            if page.total == 0:
                typer.echo("No recorded gaps; this does not assert complete security coverage.")
        except SourceCliError as exc:
            fail(exc, json_output=json_output)
        except Exception:
            fail(_query_unavailable(), json_output=json_output)

    @app.command("sarif")
    def sarif(
        run_id: Annotated[str, typer.Argument()],
        output: Annotated[str, typer.Option("--output")],
        overwrite: Annotated[bool, typer.Option("--overwrite")] = False,
    ) -> None:
        """Export deterministic SARIF from verified Product Core evidence."""

        try:
            if output == "-" and overwrite:
                raise SourceCliError(
                    "INVALID_OUTPUT", "--overwrite cannot be used with stdout", 2
                )
            with services_factory() as services:
                payload = build_sarif_bytes(services, run_id)
            if output == "-":
                typer.echo(payload.decode("utf-8"), nl=False)
                return
            write_private_atomic(Path(output), payload, overwrite=overwrite)
        except SourceCliError as exc:
            fail(exc, json_output=True)
        except Exception:
            fail(
                SourceCliError("EXPORT_FAILED", "SARIF export is unavailable", 5),
                json_output=True,
            )


def _showing(offset: int, count: int, total: int) -> None:
    first = 0 if total == 0 else offset + 1
    typer.echo(f"Showing {first}–{offset + count} of {total}")


def _known_vulnerabilities(evaluation: str, count: int | None) -> str:
    if evaluation == "COMPLETE" and count is not None:
        return str(count)
    if evaluation == "NOT_APPLICABLE":
        return "N/A"
    return "Unknown"


def _coverage_qualifier(outcome: Any) -> str:
    values = []
    for name in ("framework", "component_ref"):
        value = outcome.get(name)
        if value is not None:
            values.append(f"{name}={terminal_text(value)}")
    return "" if not values else f" ({', '.join(values)})"


def _query_unavailable() -> SourceCliError:
    return SourceCliError("QUERY_UNAVAILABLE", "Source scan query is unavailable", 5)
