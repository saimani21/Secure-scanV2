"""Thin trusted-host CLI orchestration over frozen assurance services."""

from __future__ import annotations

import re
from collections.abc import Callable
from contextlib import AbstractContextManager
from typing import Annotated, Any

import typer

from securescan.api.effective_governance_schemas import EffectiveGovernanceResponse
from securescan.api.trusted_baseline_schemas import (
    SecurityDeltaResponse,
    TrustedBaselineResponse,
    TrustedBaselineStateResponse,
)
from securescan.product_core import (
    EffectiveGovernanceError,
    EffectiveGovernanceNotFoundError,
    SecurityDeltaError,
    SecurityDeltaNotFoundError,
    TrustedBaselineConflictError,
    TrustedBaselineError,
    TrustedBaselineIneligibleError,
    TrustedBaselineNotFoundError,
)

from .source import SourceCliError, SourceCliServices, canonical_json, query_scan

_FINDING_ID = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


def register_assurance_commands(
    app: typer.Typer,
    services_factory: Callable[[], AbstractContextManager[SourceCliServices]],
    fail: Callable[..., Any],
) -> None:
    baseline_app = typer.Typer(
        no_args_is_help=True, help="Inspect or explicitly promote a trusted baseline"
    )
    governance_app = typer.Typer(no_args_is_help=True, help="Inspect current effective governance")
    app.add_typer(baseline_app, name="baseline")
    app.add_typer(governance_app, name="governance")

    @baseline_app.command("show")
    def baseline_show(
        run_id: Annotated[str, typer.Argument()],
        json_output: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        """Resolve current trusted comparison state from an admitted run's lineage."""
        try:
            with services_factory() as services:
                summary = query_scan(services, run_id)
                if services.baseline is None:
                    raise SourceCliError(
                        "BASELINE_UNAVAILABLE", "Trusted baseline is unavailable", 5
                    )
                state = services.baseline.get_current(
                    project_id=summary.project_id, lineage_id=summary.lineage_id
                )
        except SourceCliError as error:
            fail(error, json_output=json_output)
            return
        except TrustedBaselineNotFoundError:
            fail(
                SourceCliError("BASELINE_NOT_FOUND", "Lineage was not found", 3),
                json_output=json_output,
            )
            return
        except TrustedBaselineError:
            fail(
                SourceCliError("BASELINE_UNAVAILABLE", "Trusted baseline is unavailable", 5),
                json_output=json_output,
            )
            return
        data = TrustedBaselineStateResponse.model_validate(state).model_dump(mode="json")
        if json_output:
            typer.echo(canonical_json(data))
        else:
            typer.echo(f"Trusted baseline revision  {data['revision']}")
            current = data["baseline"]
            baseline_id = current["baseline_id"] if current else "Not configured"
            typer.echo(f"Baseline ID                {baseline_id}")
            typer.echo(
                f"Baseline run               {current['run_id'] if current else 'Not configured'}"
            )
            typer.echo("A trusted baseline is comparison state, not proof of a clean repository.")

    @baseline_app.command("promote")
    def baseline_promote(
        run_id: Annotated[str, typer.Argument()],
        expected_revision: Annotated[int, typer.Option("--expected-revision", min=0)],
        json_output: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        """Promote only after an explicit command with the frozen optimistic revision."""
        try:
            with services_factory() as services:
                summary = query_scan(services, run_id)
                if services.baseline is None:
                    raise SourceCliError(
                        "BASELINE_UNAVAILABLE", "Trusted baseline is unavailable", 5
                    )
                promoted = services.baseline.promote(
                    project_id=summary.project_id,
                    lineage_id=summary.lineage_id,
                    run_id=summary.run_id,
                    expected_revision=expected_revision,
                )
        except SourceCliError as error:
            fail(error, json_output=json_output)
            return
        except TrustedBaselineConflictError:
            fail(
                SourceCliError("BASELINE_REVISION_CONFLICT", "Baseline revision changed", 4),
                json_output=json_output,
            )
            return
        except (TrustedBaselineNotFoundError, TrustedBaselineIneligibleError):
            fail(
                SourceCliError("BASELINE_RUN_INELIGIBLE", "Run is not eligible for promotion", 3),
                json_output=json_output,
            )
            return
        except TrustedBaselineError:
            fail(
                SourceCliError("BASELINE_UNAVAILABLE", "Trusted baseline is unavailable", 5),
                json_output=json_output,
            )
            return
        data = TrustedBaselineResponse.model_validate(promoted).model_dump(mode="json")
        if json_output:
            typer.echo(canonical_json(data))
        else:
            typer.echo(
                f"Promoted run {data['run_id']} as baseline {data['baseline_id']} "
                f"at revision {data['revision']}"
            )

    @app.command("delta")
    def delta_show(
        run_id: Annotated[str, typer.Argument()],
        json_output: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        """Read exact candidate-vs-current-trusted-baseline comparison."""
        try:
            with services_factory() as services:
                summary = query_scan(services, run_id)
                if services.delta is None:
                    raise SourceCliError("DELTA_UNAVAILABLE", "Security Delta is unavailable", 5)
                delta = services.delta.evaluate(
                    project_id=summary.project_id,
                    lineage_id=summary.lineage_id,
                    candidate_run_id=summary.run_id,
                )
        except SourceCliError as error:
            fail(error, json_output=json_output)
            return
        except SecurityDeltaNotFoundError:
            fail(
                SourceCliError("DELTA_NOT_FOUND", "No trusted comparison is available", 3),
                json_output=json_output,
            )
            return
        except SecurityDeltaError:
            fail(
                SourceCliError("DELTA_UNAVAILABLE", "Security Delta is unavailable", 5),
                json_output=json_output,
            )
            return
        data = SecurityDeltaResponse.model_validate(delta).model_dump(mode="json")
        if json_output:
            typer.echo(canonical_json(data))
        else:
            typer.echo(f"Security Delta  {data['comparison_status']}")
            typer.echo(
                f"Baseline        {data['baseline_id']} (revision {data['baseline_revision']})"
            )
            typer.echo(f"Candidate       {data['candidate_run_id']}")
            for item in data["findings"]:
                typer.echo(f"{item['state']:<15} {item['authority']:<12} {item['finding_id']}")

    @governance_app.command("effective")
    def governance_effective(
        run_id: Annotated[str, typer.Argument()],
        finding_id: Annotated[str, typer.Argument()],
        json_output: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        """Read current/evaluation-time state; never relabel it as historical."""
        if _FINDING_ID.fullmatch(finding_id) is None:
            fail(
                SourceCliError("INVALID_FINDING_ID", "A 64-character finding ID is required", 2),
                json_output=json_output,
            )
            return
        try:
            with services_factory() as services:
                summary = query_scan(services, run_id)
                if services.effective_governance is None:
                    raise SourceCliError(
                        "GOVERNANCE_UNAVAILABLE", "Effective governance is unavailable", 5
                    )
                effective = services.effective_governance.get(
                    project_id=summary.project_id,
                    lineage_id=summary.lineage_id,
                    finding_id=finding_id,
                )
        except SourceCliError as error:
            fail(error, json_output=json_output)
            return
        except EffectiveGovernanceNotFoundError:
            fail(
                SourceCliError("FINDING_NOT_FOUND", "Finding was not found", 3),
                json_output=json_output,
            )
            return
        except EffectiveGovernanceError:
            fail(
                SourceCliError("GOVERNANCE_UNAVAILABLE", "Effective governance is unavailable", 5),
                json_output=json_output,
            )
            return
        data = EffectiveGovernanceResponse.model_validate(effective).model_dump(mode="json")
        if json_output:
            typer.echo(canonical_json(data))
        else:
            typer.echo("Current/evaluation-time governance")
            typer.echo(f"Finding       {data['finding_id']}")
            typer.echo(f"Lifecycle     {data['lifecycle_state']}")
            typer.echo(f"Disposition   {data['disposition']}")
            typer.echo(f"Review needed {data['review_required']}")
