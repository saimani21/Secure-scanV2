"""Explicit product commands over frozen trusted-host services."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from contextlib import AbstractContextManager
from typing import Annotated, Any

import typer

from securescan.api.policy_schemas import TrustedPolicyResponse
from securescan.product_core import PolicyError
from securescan.product_core.interoperability import SourceInteroperabilityError

from .product_policy import policy_evaluation_data, policy_exit_code
from .source import SourceCliError, SourceCliServices, canonical_json, query_scan


def register_product_commands(
    app: typer.Typer,
    services_factory: Callable[[], AbstractContextManager[SourceCliServices]],
    fail: Callable[..., Any],
) -> None:
    policy_app = typer.Typer(
        no_args_is_help=True, help="Inspect or explicitly evaluate trusted policy"
    )
    app.add_typer(policy_app, name="policy")

    @app.command("sbom")
    def export_sbom(
        run_id: Annotated[str, typer.Argument()],
        export_format: Annotated[
            str, typer.Option("--format", help="Export format: cyclonedx-json")
        ] = "cyclonedx-json",
    ) -> None:
        """Export one verified published run as deterministic CycloneDX 1.7 JSON."""

        if export_format != "cyclonedx-json":
            fail(
                SourceCliError("EXPORT_INVALID", "Unsupported SBOM export format", 2),
                json_output=True,
            )
            return
        try:
            with services_factory() as services:
                if services.interoperability is None:
                    raise SourceCliError("EXPORT_UNAVAILABLE", "SBOM export is unavailable", 5)
                document = services.interoperability.cyclonedx(run_id=run_id)
        except SourceCliError as error:
            fail(error, json_output=True)
            return
        except SourceInteroperabilityError:
            fail(
                SourceCliError("EXPORT_UNAVAILABLE", "SBOM export is unavailable", 5),
                json_output=True,
            )
            return
        typer.echo(canonical_json(document))

    @app.command("toolchain")
    def export_toolchain(
        run_id: Annotated[str, typer.Argument()],
        json_output: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        """Show the deterministic toolchain facts proven for one published run."""

        try:
            with services_factory() as services:
                if services.interoperability is None:
                    raise SourceCliError(
                        "EXPORT_UNAVAILABLE", "Toolchain manifest is unavailable", 5
                    )
                document = services.interoperability.toolchain_manifest(run_id=run_id)
        except SourceCliError as error:
            fail(error, json_output=json_output)
            return
        except SourceInteroperabilityError:
            fail(
                SourceCliError(
                    "EXPORT_UNAVAILABLE", "Toolchain manifest is unavailable", 5
                ),
                json_output=json_output,
            )
            return
        if json_output:
            typer.echo(canonical_json(document))
        else:
            typer.echo("SecureScan Toolchain Manifest")
            typer.echo(f"Run          {document['run_id']}")
            typer.echo(f"Digest       {document['manifest_sha256']}")
            typer.echo(f"Authorities  {len(document['authorities'])}")

    @policy_app.command("evaluate")
    def policy_evaluate(
        run_id: Annotated[str, typer.Argument()],
        json_output: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        """Persist one frozen F decision for an existing run; never affect plain scan."""

        try:
            with services_factory() as services:
                summary = query_scan(services, run_id)
                if services.policy is None:
                    raise SourceCliError("POLICY_UNAVAILABLE", "Policy service is unavailable", 5)
                evaluation = services.policy.evaluate(
                    project_id=summary.project_id,
                    lineage_id=summary.lineage_id,
                    candidate_run_id=summary.run_id,
                )
        except SourceCliError as error:
            fail(error, json_output=json_output)
            return
        except PolicyError:
            fail(
                SourceCliError("POLICY_UNAVAILABLE", "Policy evaluation is unavailable", 5),
                json_output=json_output,
            )
            return
        except Exception:
            fail(
                SourceCliError("POLICY_UNAVAILABLE", "Policy evaluation is unavailable", 5),
                json_output=json_output,
            )
            return

        data = policy_evaluation_data(evaluation)
        if json_output:
            typer.echo(canonical_json(data))
        else:
            counts = Counter(decision.kind.value for decision in evaluation.decisions)
            typer.echo("SecureScan Policy")
            typer.echo(f"Result       {evaluation.result.value}")
            typer.echo(f"Run          {evaluation.candidate_run_id}")
            typer.echo(f"Baseline     {evaluation.baseline_id or 'Not configured'}")
            typer.echo(f"Policy       {evaluation.policy_id} v{evaluation.policy_version}")
            for kind in ("VIOLATION", "WARNING", "EXCLUSION", "ERROR"):
                typer.echo(f"{kind.title():<13}{counts[kind]}")
            if counts["ERROR"]:
                typer.echo("Required evidence could not be evaluated safely.")
        code = policy_exit_code(evaluation.result)
        if code:
            raise typer.Exit(code)

    @policy_app.command("show")
    def policy_show(
        run_id: Annotated[str, typer.Argument()],
        json_output: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        """Read current trusted policy without evaluating or persisting a decision."""
        try:
            with services_factory() as services:
                summary = query_scan(services, run_id)
                if services.policy is None:
                    raise SourceCliError("POLICY_UNAVAILABLE", "Trusted policy is unavailable", 5)
                policy = services.policy.get_policy(
                    project_id=summary.project_id, lineage_id=summary.lineage_id
                )
        except SourceCliError as error:
            fail(error, json_output=json_output)
            return
        except PolicyError:
            fail(
                SourceCliError("POLICY_UNAVAILABLE", "Trusted policy is unavailable", 5),
                json_output=json_output,
            )
            return
        data = TrustedPolicyResponse.model_validate(policy).model_dump(mode="json")
        if json_output:
            typer.echo(canonical_json(data))
        else:
            typer.echo(f"Trusted policy  {data['policy_id']} v{data['version']}")
            typer.echo(f"Digest          {data['digest']}")
