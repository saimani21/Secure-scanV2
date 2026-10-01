"""Read-only exact-run guidance command over the frozen G service."""

from __future__ import annotations

import re
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import asdict
from typing import Annotated, Any

import typer

from securescan.product_core.guidance import (
    FindingGuidanceError,
    FindingGuidanceNotFoundError,
    FindingGuidanceValidationError,
)

from .presentation import terminal_text
from .source import SourceCliError, SourceCliServices, canonical_json, query_scan


def register_guidance_commands(
    app: typer.Typer,
    services_factory: Callable[[], AbstractContextManager[SourceCliServices]],
    fail: Callable[..., Any],
) -> None:
    finding_app = typer.Typer(no_args_is_help=True, help="Inspect exact-run findings")
    app.add_typer(finding_app, name="finding")

    @finding_app.command("guidance")
    def finding_guidance(
        run_id: Annotated[str, typer.Argument()],
        finding_id: Annotated[str, typer.Argument()],
        json_output: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        """Read accepted exact-run evidence; never query a scanner or invent a fix."""

        if re.fullmatch(r"[0-9a-f]{64}", finding_id, re.ASCII) is None:
            fail(
                SourceCliError("INVALID_FINDING_ID", "A 64-character finding ID is required", 2),
                json_output=json_output,
            )
            return
        try:
            with services_factory() as services:
                summary = query_scan(services, run_id)
                if services.guidance is None:
                    raise SourceCliError("GUIDANCE_UNAVAILABLE", "Guidance is unavailable", 5)
                guidance = services.guidance.get_for_run(
                    project_id=summary.project_id,
                    lineage_id=summary.lineage_id,
                    run_id=summary.run_id,
                    finding_id=finding_id,
                )
        except SourceCliError as error:
            fail(error, json_output=json_output)
            return
        except FindingGuidanceNotFoundError:
            fail(
                SourceCliError("FINDING_NOT_FOUND", "Finding is not in this run", 3),
                json_output=json_output,
            )
            return
        except FindingGuidanceValidationError:
            fail(
                SourceCliError("INVALID_FINDING_ID", "Finding target is invalid", 2),
                json_output=json_output,
            )
            return
        except FindingGuidanceError:
            fail(
                SourceCliError("GUIDANCE_UNAVAILABLE", "Verified guidance is unavailable", 5),
                json_output=json_output,
            )
            return

        if json_output:
            typer.echo(canonical_json(asdict(guidance)))
            return
        typer.echo(f"Guidance basis  {guidance.basis_level.value}")
        typer.echo(terminal_text(guidance.title))
        typer.echo(terminal_text(guidance.summary))
        for label, values in (
            ("Recommended actions", guidance.remediation_steps),
            ("Verification", guidance.verification_steps),
            ("Limitations", guidance.limitations),
        ):
            typer.echo(label)
            for value in values:
                typer.echo(f"  - {terminal_text(value)}")
