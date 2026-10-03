from __future__ import annotations

import json
import os
import shutil
import tempfile
from collections.abc import Callable
from contextlib import AbstractContextManager
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import typer

from securescan.intelligence import ThreatPolicySpec
from securescan.product_core import SourceProductStatus
from securescan.product_release import ProductAssuranceService
from securescan.product_release.presentation import (
    canonical_json_bytes,
    render_assessment_html,
    render_ci_summary,
)

from .developer import (
    DEFAULT_POLL_SECONDS,
    resolved_wait_timeout,
    validated_poll_seconds,
    wait_for_scan,
)
from .sarif import build_sarif_bytes
from .source import SourceCliError, SourceCliServices, submit_local_scan

_ARTIFACT_NAMES = frozenset(
    {
        "assessment.html",
        "ci-result.json",
        "decision-proof.json",
        "results.sarif",
        "sbom.cdx.json",
        "summary.md",
    }
)


def _output_path(value: Path) -> Path:
    if not isinstance(value, Path) or any(part == ".." for part in value.parts):
        raise SourceCliError("UNSAFE_CI_OUTPUT", "CI output path is unsafe", 2)
    absolute = Path(os.path.abspath(os.fspath(value.expanduser())))
    if absolute.name in {"", ".", ".."} or absolute.exists() or absolute.is_symlink():
        raise SourceCliError("CI_OUTPUT_EXISTS", "CI output path must not already exist", 2)
    try:
        parent = absolute.parent.resolve(strict=True)
    except OSError:
        raise SourceCliError("UNSAFE_CI_OUTPUT", "CI output parent is unavailable", 2) from None
    if not parent.is_dir() or parent != absolute.parent:
        raise SourceCliError("UNSAFE_CI_OUTPUT", "CI output parent is unsafe", 2)
    return absolute


def write_ci_directory(target: Path, files: dict[str, bytes]) -> Path:
    absolute = _output_path(target)
    invalid_payload = any(not isinstance(value, bytes) for value in files.values())
    if set(files) != _ARTIFACT_NAMES or invalid_payload:
        raise SourceCliError("CI_EXPORT_FAILED", "CI artifact set is invalid", 2)
    staging = Path(tempfile.mkdtemp(prefix=f".{absolute.name}.securescan-", dir=absolute.parent))
    os.chmod(staging, 0o700)
    try:
        for name in sorted(files):
            path = staging / name
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(descriptor, "wb", closefd=True) as stream:
                    stream.write(files[name])
                    stream.flush()
                    os.fsync(stream.fileno())
            except BaseException:
                raise
        os.replace(staging, absolute)
        parent_fd = os.open(absolute.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        return absolute
    except SourceCliError:
        raise
    except OSError:
        raise SourceCliError("CI_EXPORT_FAILED", "CI artifacts could not be written", 2) from None
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)


def build_ci_artifacts(
    services: SourceCliServices,
    *,
    project_id: str,
    lineage_id: str,
    run_id: str,
    bundle_id: str,
    threat_policy: ThreatPolicySpec,
    evaluated_at: datetime,
) -> tuple[dict[str, bytes], dict[str, Any]]:
    if any(
        service is None
        for service in (
            services.intelligence,
            services.assurance,
            services.effective_governance,
            services.guidance,
            services.interoperability,
        )
    ):
        raise SourceCliError("CI_UNAVAILABLE", "CI assurance services are unavailable", 2)
    assert services.intelligence is not None
    assert services.assurance is not None
    assert services.effective_governance is not None
    assert services.guidance is not None
    assert services.interoperability is not None
    services.intelligence.evaluate_run(
        project_id=project_id,
        lineage_id=lineage_id,
        run_id=run_id,
        bundle_id=bundle_id,
        evaluated_at=evaluated_at,
    )
    proof = services.assurance.evaluate_policy(
        project_id=project_id,
        lineage_id=lineage_id,
        run_id=run_id,
        bundle_id=bundle_id,
        threat_policy=threat_policy,
        evaluated_at=evaluated_at,
    )
    product = ProductAssuranceService(
        services.assurance,
        services.intelligence,
        services.effective_governance,
        services.guidance,
        services.interoperability,
    )
    dashboard = product.dashboard(
        project_id=project_id,
        lineage_id=lineage_id,
        run_id=run_id,
        bundle_id=bundle_id,
        proof_id=proof.proof_id,
    )
    result = product.ci_result(dashboard)
    files = {
        "assessment.html": render_assessment_html(dashboard),
        "ci-result.json": canonical_json_bytes(result.canonical_data()),
        "decision-proof.json": canonical_json_bytes(proof.proof),
        "results.sarif": build_sarif_bytes(services, run_id),
        "sbom.cdx.json": canonical_json_bytes(services.interoperability.cyclonedx(run_id=run_id)),
        "summary.md": render_ci_summary(result, dashboard),
    }
    return files, result.canonical_data()


def register_ci_command(
    app: typer.Typer,
    services_factory: Callable[[], AbstractContextManager[SourceCliServices]],
) -> None:
    @app.command("ci")
    def ci(
        path: Annotated[Path, typer.Argument()] = Path("."),
        project_id: Annotated[str, typer.Option("--project-id")] = "",
        bundle_id: Annotated[str, typer.Option("--bundle-id")] = "",
        policy_file: Annotated[
            Path | None, typer.Option("--policy", exists=True, dir_okay=False, readable=True)
        ] = None,
        lineage_id: Annotated[str | None, typer.Option("--lineage-id")] = None,
        output: Annotated[Path, typer.Option("--output")] = Path(".securescan"),
        deadline_seconds: Annotated[
            int | None, typer.Option("--deadline-seconds", min=300, max=86_400)
        ] = None,
        wait_timeout_seconds: Annotated[
            int | None, typer.Option("--wait-timeout-seconds", min=1, max=86_460)
        ] = None,
        poll_seconds: Annotated[
            float, typer.Option("--poll-seconds", min=0.1, max=60.0)
        ] = DEFAULT_POLL_SECONDS,
    ) -> None:
        """Scan one local repository and emit one authoritative CI decision bundle."""
        if not project_id or not bundle_id or policy_file is None:
            typer.echo(
                '{"error":{"code":"CI_CONFIGURATION_INVALID",'
                '"message":"--project-id, --bundle-id and --policy are required"}}',
                err=True,
            )
            raise typer.Exit(2)
        try:
            threat_policy = ThreatPolicySpec.model_validate(
                json.loads(policy_file.read_text(encoding="utf-8"))
            )
            with services_factory() as services:
                submitted = submit_local_scan(
                    services,
                    source_path=path,
                    project_id=project_id,
                    lineage_id=lineage_id,
                    deadline_seconds=deadline_seconds,
                )
                timeout = resolved_wait_timeout(
                    analysis_deadline_seconds=(
                        services.default_deadline_seconds
                        if deadline_seconds is None
                        else deadline_seconds
                    ),
                    wait_timeout_seconds=wait_timeout_seconds,
                )
                summary = wait_for_scan(
                    services,
                    submitted.submission.run_id,
                    timeout_seconds=timeout,
                    poll_seconds=validated_poll_seconds(poll_seconds),
                )
                if summary.product_status is not SourceProductStatus.COMPLETED:
                    raise SourceCliError(
                        "CI_SCAN_INCOMPLETE",
                        "CI requires a completed authoritative scan",
                        2,
                    )
                evaluated_at = services.clock().astimezone(UTC)
                files, result = build_ci_artifacts(
                    services,
                    project_id=summary.project_id,
                    lineage_id=summary.lineage_id,
                    run_id=summary.run_id,
                    bundle_id=bundle_id,
                    threat_policy=threat_policy,
                    evaluated_at=evaluated_at,
                )
                written = write_ci_directory(output, files)
            result["output_directory"] = str(written)
            typer.echo(json.dumps(result, allow_nan=False, separators=(",", ":"), sort_keys=True))
            if result["exit_code"]:
                raise typer.Exit(result["exit_code"])
        except typer.Exit:
            raise
        except KeyboardInterrupt:
            typer.echo(
                '{"error":{"code":"CI_INTERRUPTED",'
                '"message":"CI wait stopped; the durable scan was not cancelled"}}',
                err=True,
            )
            raise typer.Exit(130) from None
        except Exception:
            typer.echo(
                '{"error":{"code":"CI_ERROR",'
                '"message":"SecureScan could not make the required CI decision safely"}}',
                err=True,
            )
            raise typer.Exit(2) from None
