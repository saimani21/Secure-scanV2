"""CycloneDX and toolchain projections over verified published evidence."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from typing import Any
from uuid import UUID, uuid5

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.evidence import (
    ComponentKind,
    LocalScannerProvenance,
    OsvProvenance,
    RepositoryComponentPayload,
    SemgrepProvenance,
)
from securescan.orchestration.models import (
    SourceOrchestrationIntegrityError,
    SourcePlanningSnapshot,
)
from securescan.orchestration.service import SourcePlanningSnapshotStore
from securescan.persistence.database import (
    SourceOrchestrationAttemptRow,
    SourceOrchestrationRow,
    SourceOrchestrationScannerJobRow,
    ToolExecutionRow,
)
from securescan.product_core.component_identity import (
    ComponentIdentityError,
    package_identity,
)
from securescan.product_core.verified_read import (
    VerifiedPublishedRun,
    VerifiedPublishedRunError,
    VerifiedPublishedRunGateway,
)

CYCLONEDX_SPEC_VERSION = "1.7"
TOOLCHAIN_MANIFEST_SCHEMA_VERSION = "securescan-source-toolchain-manifest-v1"
_SERIAL_NAMESPACE = UUID("0b20fba1-c9b8-4a26-9ee1-c908036474b8")


class SourceInteroperabilityError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("SecureScan interoperability export is unavailable")


class SourceInteroperabilityService:
    """Read-only exports whose sole evidence input is the verified-read gateway."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        artifact_store: ContentAddressedArtifactStore,
    ) -> None:
        self._sessions = session_factory
        self._artifacts = artifact_store
        self._verified = VerifiedPublishedRunGateway(session_factory, artifact_store)

    def cyclonedx(self, *, run_id: str) -> dict[str, Any]:
        try:
            verified = self._verified.load(run_id=run_id)
            return _cyclonedx_document(verified)
        except (ComponentIdentityError, VerifiedPublishedRunError, TypeError, ValueError):
            raise SourceInteroperabilityError from None

    def toolchain_manifest(self, *, run_id: str) -> dict[str, Any]:
        try:
            verified = self._verified.load(run_id=run_id)
            with self._sessions() as session:
                parent = session.get(SourceOrchestrationRow, run_id)
                if parent is None:
                    raise SourceInteroperabilityError
                accepted = tuple(
                    session.execute(
                        select(
                            ToolExecutionRow,
                            SourceOrchestrationAttemptRow,
                            SourceOrchestrationScannerJobRow,
                        )
                        .join(
                            SourceOrchestrationAttemptRow,
                            SourceOrchestrationAttemptRow.tool_execution_id
                            == ToolExecutionRow.id,
                        )
                        .join(
                            SourceOrchestrationScannerJobRow,
                            SourceOrchestrationScannerJobRow.job_id
                            == SourceOrchestrationAttemptRow.job_id,
                        )
                        .where(ToolExecutionRow.run_id == run_id)
                        .where(
                            SourceOrchestrationAttemptRow.acceptance_state == "ACCEPTED"
                        )
                        .order_by(
                            ToolExecutionRow.adapter_id,
                            ToolExecutionRow.tool_version,
                            ToolExecutionRow.adapter_version,
                            ToolExecutionRow.id,
                        )
                    )
                )
            snapshot = SourcePlanningSnapshotStore(self._artifacts).read(
                parent.planning_snapshot_sha256,
                parent.snapshot_size_bytes,
                parent.snapshot_storage_path,
            )
            if (
                snapshot.run_id != verified.run_id
                or snapshot.profile.profile_digest() != parent.profile_digest
                or snapshot.plan.plan_digest() != parent.plan_digest
                or snapshot.roster.roster_digest() != parent.roster_digest
            ):
                raise SourceInteroperabilityError
            planned = {node.node_id: node for node in snapshot.nodes}
            executions = []
            for tool, attempt, mapping in accepted:
                node = planned.get(attempt.node_id)
                if (
                    node is None
                    or attempt.run_id != run_id
                    or mapping.run_id != run_id
                    or mapping.node_id != attempt.node_id
                    or mapping.job_id != attempt.job_id
                    or mapping.selected_attempt_number != attempt.attempt_number
                    or mapping.authority != node.authority.value
                    or mapping.capability != node.capability.value
                    or mapping.analyzer_id != node.analyzer_id
                    or mapping.contract_digest != node.contract_digest
                    or tool.job_id != attempt.job_id
                    or tool.attempt_number != attempt.attempt_number
                ):
                    raise SourceInteroperabilityError
                executions.append(tool)
            return _toolchain_manifest(verified, parent, tuple(executions), snapshot)
        except SourceInteroperabilityError:
            raise
        except (
            SQLAlchemyError,
            SourceOrchestrationIntegrityError,
            VerifiedPublishedRunError,
            TypeError,
            ValueError,
        ):
            raise SourceInteroperabilityError from None


def canonical_export_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


def _cyclonedx_document(verified: VerifiedPublishedRun) -> dict[str, Any]:
    root_ref = f"urn:securescan:run:{verified.run_id}"
    components: list[dict[str, Any]] = []
    seen_refs: set[str] = set()
    for component in verified.report.components:
        if component.component_kind is ComponentKind.PACKAGE:
            identity = package_identity(component)
            rendered: dict[str, Any] = {
                "bom-ref": identity.bom_ref,
                "name": identity.name,
                "properties": [
                    {
                        "name": "securescan:identity:source",
                        "value": identity.identity_source,
                    },
                    {
                        "name": "securescan:package:type",
                        "value": identity.package_type,
                    },
                ],
                "type": "library",
            }
            if identity.version is not None:
                rendered["version"] = identity.version
            if identity.purl is not None:
                rendered["purl"] = identity.purl
        elif isinstance(component.payload, RepositoryComponentPayload):
            rendered = {
                "bom-ref": f"urn:securescan:component:{component.component_ref}",
                "name": component.payload.display_name,
                "properties": [
                    {
                        "name": "securescan:repository:root",
                        "value": component.payload.root_path,
                    }
                ],
                "type": "application",
            }
        else:
            raise SourceInteroperabilityError
        reference = rendered["bom-ref"]
        if reference in seen_refs:
            raise SourceInteroperabilityError
        seen_refs.add(reference)
        components.append(rendered)

    serial_material = f"{verified.run_id}:{verified.report_artifact_sha256}"
    document: dict[str, Any] = {
        "$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json",
        "bomFormat": "CycloneDX",
        "components": sorted(components, key=lambda item: item["bom-ref"]),
        "metadata": {
            "component": {
                "bom-ref": root_ref,
                "name": "SecureScan Source repository",
                "properties": [
                    {
                        "name": "securescan:run:id",
                        "value": verified.run_id,
                    },
                    {
                        "name": "securescan:evidence:sha256",
                        "value": verified.report_artifact_sha256,
                    },
                ],
                "type": "application",
            }
        },
        "serialNumber": f"urn:uuid:{uuid5(_SERIAL_NAMESPACE, serial_material)}",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "version": 1,
    }
    return document


def _toolchain_manifest(
    verified: VerifiedPublishedRun,
    parent: SourceOrchestrationRow,
    executions: tuple[ToolExecutionRow, ...],
    snapshot: SourcePlanningSnapshot,
) -> dict[str, Any]:
    authorities: dict[tuple[str, str], dict[str, Any]] = {}
    for evidence in verified.report.evidence:
        provenance = evidence.provenance
        if isinstance(provenance, SemgrepProvenance):
            item = {
                "authority": evidence.authority.value,
                "binding_digest": provenance.binding_digest,
                "projection_digest": provenance.projection_digest,
                "ruleset_digest": provenance.ruleset_digest,
                "ruleset_id": provenance.ruleset_id,
                "ruleset_version": provenance.ruleset_version,
                "tool_version": provenance.scanner_version,
            }
        elif isinstance(provenance, LocalScannerProvenance):
            item = {
                "authority": evidence.authority.value,
                "binding_digest": provenance.binding_digest,
                "projection_digest": provenance.projection_digest,
                "tool_version": provenance.scanner_version,
            }
        elif isinstance(provenance, OsvProvenance):
            item = {
                "api_version": provenance.api_version,
                "authority": provenance.source_service,
                "schema_version": provenance.schema_version,
                "snapshot_digest": provenance.snapshot_digest,
                "syft_binding_digest": provenance.syft_binding_digest,
            }
        else:
            raise SourceInteroperabilityError
        key = (item["authority"], canonical_export_json(item).decode("utf-8"))
        authorities[key] = item

    execution_identities: dict[tuple[str, str, str], int] = defaultdict(int)
    for execution in executions:
        execution_identities[
            (execution.adapter_id, execution.adapter_version, execution.tool_version)
        ] += 1
    execution_items = [
        {
            "adapter_id": adapter_id,
            "adapter_version": adapter_version,
            "accepted_execution_count": count,
            "tool_version": tool_version,
        }
        for (adapter_id, adapter_version, tool_version), count in sorted(
            execution_identities.items()
        )
    ]
    body: dict[str, Any] = {
        "authorities": [authorities[key] for key in sorted(authorities)],
        "execution_identities": execution_items,
        "limitations": [
            "ENRY_RUN_IDENTITY_NOT_PERSISTED_IN_FROZEN_PLANNING_EVIDENCE"
        ],
        "planning": {
            "plan_digest": parent.plan_digest,
            "planning_snapshot_sha256": parent.planning_snapshot_sha256,
            "profile_digest": parent.profile_digest,
            "roster_digest": parent.roster_digest,
        },
        "planned_authorities": [
            authority.canonical_data() for authority in snapshot.roster.authorities
        ],
        "planned_nodes": [
            {
                "analyzer_id": node.analyzer_id,
                "authority": node.authority.value,
                "binding_digest": node.contract_digest,
                "capability": node.capability.value,
                "node_id": node.node_id,
            }
            for node in snapshot.nodes
        ],
        "report_artifact_sha256": verified.report_artifact_sha256,
        "run_id": verified.run_id,
        "schema_version": TOOLCHAIN_MANIFEST_SCHEMA_VERSION,
    }
    body["manifest_sha256"] = hashlib.sha256(canonical_export_json(body)).hexdigest()
    return body
