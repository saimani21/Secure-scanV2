from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Annotated, Literal

import typer
from fastapi.encoders import jsonable_encoder

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.config import get_settings
from securescan.intelligence import (
    AssuranceService,
    IntelligenceService,
    IntelligenceSource,
    ThreatPolicySpec,
)
from securescan.intelligence.feeds import SnapshotFeedClient
from securescan.intelligence.models import IntelligenceSnapshot
from securescan.intelligence.nvd import NvdExactCveClient
from securescan.persistence.database import create_session_factory

from .source import canonical_json


def _services() -> tuple[object, IntelligenceService, AssuranceService]:
    settings = get_settings()
    engine, sessions = create_session_factory(settings)
    artifacts = ContentAddressedArtifactStore(settings.artifact_root)
    return engine, IntelligenceService(sessions, artifacts), AssuranceService(sessions, artifacts)


def _emit(value: object) -> None:
    typer.echo(canonical_json(jsonable_encoder(value)))


def _snapshot_data(snapshot: IntelligenceSnapshot) -> dict:
    data = jsonable_encoder(snapshot)
    data.pop("records", None)
    return data


def _fail() -> None:
    typer.echo(
        canonical_json(
            {
                "error": {
                    "code": "INTELLIGENCE_UNAVAILABLE",
                    "message": "Intelligence operation is unavailable",
                }
            }
        ),
        err=True,
    )
    raise typer.Exit(5)


def register_intelligence_commands(app: typer.Typer) -> None:
    intel = typer.Typer(no_args_is_help=True, help="Import and inspect threat intelligence")
    app.add_typer(intel, name="intel")

    @intel.command("import")
    def import_intelligence(
        source: Annotated[LiteralSource, typer.Option("--source")],
        file: Annotated[Path, typer.Option("--file", exists=True, dir_okay=False, readable=True)],
        cve_id: Annotated[str | None, typer.Option("--cve")] = None,
    ) -> None:
        """Import one bounded offline KEV, EPSS, or exact-CVE NVD document."""
        engine = None
        try:
            engine, service, _ = _services()
            payload = file.read_bytes()
            if source == "kev":
                if cve_id is not None:
                    raise ValueError
                result = service.import_kev(payload)
            elif source == "epss":
                if cve_id is not None:
                    raise ValueError
                result = service.import_epss(payload)
            else:
                if cve_id is None:
                    raise ValueError
                result = service.import_nvd(payload, expected_cve=cve_id)
            _emit(_snapshot_data(result) if isinstance(result, IntelligenceSnapshot) else result)
        except Exception:
            _fail()
        finally:
            if engine is not None:
                engine.dispose()

    @intel.command("snapshots")
    def snapshots(
        source: Annotated[LiteralSnapshot | None, typer.Option("--source")] = None,
    ) -> None:
        """List valid CAS-verified KEV and EPSS snapshots."""
        engine = None
        try:
            engine, service, _ = _services()
            selected = None if source is None else IntelligenceSource(source)
            _emit([_snapshot_data(item) for item in service.list_snapshots(selected)])
        except Exception:
            _fail()
        finally:
            if engine is not None:
                engine.dispose()

    @intel.command("refresh")
    def refresh(
        source: Annotated[LiteralSource, typer.Option("--source")],
        cve_id: Annotated[str | None, typer.Option("--cve")] = None,
    ) -> None:
        """Fetch a fixed public source and publish it only after full validation."""
        engine = None
        try:
            engine, service, _ = _services()
            if source == "nvd":
                if cve_id is None:
                    raise ValueError
                with NvdExactCveClient(api_key=os.environ.get("SECURESCAN_NVD_API_KEY")) as client:
                    payload = client.fetch(cve_id)
                result = service.import_nvd(payload, expected_cve=cve_id)
            else:
                if cve_id is not None:
                    raise ValueError
                with SnapshotFeedClient() as client:
                    payload = client.fetch(source)
                result = (
                    service.import_kev(payload) if source == "kev" else service.import_epss(payload)
                )
            _emit(_snapshot_data(result) if isinstance(result, IntelligenceSnapshot) else result)
        except Exception:
            _fail()
        finally:
            if engine is not None:
                engine.dispose()

    @intel.command("bundle")
    def bundle(
        kev_snapshot_id: Annotated[str | None, typer.Option("--kev-snapshot")] = None,
        epss_snapshot_id: Annotated[str | None, typer.Option("--epss-snapshot")] = None,
        nvd_enrichment_id: Annotated[list[str] | None, typer.Option("--nvd-enrichment")] = None,
    ) -> None:
        """Create an immutable selection of concrete intelligence evidence."""
        engine = None
        try:
            engine, service, _ = _services()
            _emit(
                service.create_bundle(
                    kev_snapshot_id=kev_snapshot_id,
                    epss_snapshot_id=epss_snapshot_id,
                    nvd_enrichment_ids=tuple(nvd_enrichment_id or ()),
                )
            )
        except Exception:
            _fail()
        finally:
            if engine is not None:
                engine.dispose()

    @intel.command("evaluate")
    def evaluate(
        run_id: Annotated[str, typer.Argument()],
        project_id: Annotated[str, typer.Option("--project")],
        lineage_id: Annotated[str, typer.Option("--lineage")],
        bundle_id: Annotated[str, typer.Option("--bundle")],
    ) -> None:
        """Evaluate a verified run from stored intelligence only."""
        engine = None
        try:
            engine, service, _ = _services()
            _emit(
                service.evaluate_run(
                    project_id=project_id,
                    lineage_id=lineage_id,
                    run_id=run_id,
                    bundle_id=bundle_id,
                )
            )
        except Exception:
            _fail()
        finally:
            if engine is not None:
                engine.dispose()

    @intel.command("assurance")
    def assurance(
        run_id: Annotated[str, typer.Argument()],
        project_id: Annotated[str, typer.Option("--project")],
        lineage_id: Annotated[str, typer.Option("--lineage")],
        bundle_id: Annotated[str | None, typer.Option("--bundle")] = None,
    ) -> None:
        """Read the authoritative backend assurance aggregation."""
        engine = None
        try:
            engine, _, service = _services()
            _emit(
                service.run_assurance_view(
                    project_id=project_id,
                    lineage_id=lineage_id,
                    run_id=run_id,
                    bundle_id=bundle_id,
                )
            )
        except Exception:
            _fail()
        finally:
            if engine is not None:
                engine.dispose()

    @intel.command("policy-proof")
    def policy_proof(
        run_id: Annotated[str, typer.Argument()],
        project_id: Annotated[str, typer.Option("--project")],
        lineage_id: Annotated[str, typer.Option("--lineage")],
        bundle_id: Annotated[str, typer.Option("--bundle")],
        policy_file: Annotated[
            Path, typer.Option("--policy", exists=True, dir_okay=False, readable=True)
        ],
        evaluated_at: Annotated[datetime | None, typer.Option("--evaluated-at")] = None,
    ) -> None:
        """Evaluate deterministic policy and emit its machine-readable proof."""
        engine = None
        try:
            definition = json.loads(policy_file.read_text(encoding="utf-8"))
            policy = ThreatPolicySpec.model_validate(definition)
            engine, _, service = _services()
            _emit(
                service.evaluate_policy(
                    project_id=project_id,
                    lineage_id=lineage_id,
                    run_id=run_id,
                    bundle_id=bundle_id,
                    threat_policy=policy,
                    evaluated_at=evaluated_at,
                )
            )
        except Exception:
            _fail()
        finally:
            if engine is not None:
                engine.dispose()


LiteralSource = Literal["kev", "epss", "nvd"]
LiteralSnapshot = Literal["CISA_KEV", "FIRST_EPSS"]
