from __future__ import annotations

import hashlib
import json
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
from securescan.services.scan_service import ScanService

app = typer.Typer(no_args_is_help=True, help="SecureScan execution-kernel CLI")


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
