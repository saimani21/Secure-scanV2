from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.domain.enums import ArtifactKind
from securescan.evidence import (
    EvidenceKind,
    FindingCategory,
    OsvAdvisoryGroupEvidencePayload,
)
from securescan.persistence.database import (
    SourceIntelligenceBundleRow,
    SourceIntelligenceSnapshotRow,
    SourceNvdEnrichmentRow,
    SourceThreatAssessmentRow,
    utc_now,
)
from securescan.product_core.verified_read import (
    VerifiedPublishedRunError,
    VerifiedPublishedRunGateway,
)

from .cve import exact_cve_aliases, validate_cve_id
from .ingestion import (
    NVD_PARSER_CONTRACT,
    IntelligenceIngestionError,
    parse_epss_snapshot,
    parse_kev_snapshot,
    parse_nvd_enrichment,
)
from .models import (
    EpssState,
    IntelligenceBundle,
    IntelligenceSnapshot,
    IntelligenceSource,
    KevState,
    NvdEnrichment,
    ParsedSnapshot,
    ThreatAssessment,
    as_utc,
    identity,
)


class IntelligenceServiceError(RuntimeError):
    pass


class IntelligenceNotFoundError(IntelligenceServiceError):
    pass


class IntelligenceIntegrityError(IntelligenceServiceError):
    pass


class IntelligenceService:
    """Persist complete immutable intelligence and evaluate verified runs offline."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        artifact_store: ContentAddressedArtifactStore,
        *,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._sessions = session_factory
        self._artifacts = artifact_store
        self._verified = VerifiedPublishedRunGateway(session_factory, artifact_store)
        self._clock = clock

    def import_kev(
        self, payload: bytes, *, retrieved_at: datetime | None = None
    ) -> IntelligenceSnapshot:
        return self._import_snapshot(payload, parse_kev_snapshot, retrieved_at)

    def import_epss(
        self, payload: bytes, *, retrieved_at: datetime | None = None
    ) -> IntelligenceSnapshot:
        return self._import_snapshot(payload, parse_epss_snapshot, retrieved_at)

    def _import_snapshot(
        self,
        payload: bytes,
        parser: Callable[[bytes], ParsedSnapshot],
        retrieved_at: datetime | None,
    ) -> IntelligenceSnapshot:
        parsed = parser(payload)
        retrieved = self._time(retrieved_at)
        content_sha = hashlib.sha256(payload).hexdigest()
        snapshot_id = identity(
            b"securescan-intelligence-snapshot-v1\0",
            {
                "content_sha256": content_sha,
                "parser_contract_version": parsed.parser_contract_version,
                "source": parsed.source.value,
            },
        )
        artifact = self._artifacts.put(
            payload,
            kind=ArtifactKind.THREAT_INTELLIGENCE,
            media_type=(
                "application/json"
                if parsed.source is IntelligenceSource.CISA_KEV
                else "application/gzip"
            ),
            sanitized=True,
        )
        row = SourceIntelligenceSnapshotRow(
            snapshot_id=snapshot_id,
            source=parsed.source.value,
            retrieved_at=retrieved,
            source_effective_at=parsed.source_effective_at,
            content_sha256=artifact.sha256,
            artifact_size_bytes=artifact.size_bytes,
            parser_contract_version=parsed.parser_contract_version,
            source_schema=parsed.source_schema,
            source_metadata_json=parsed.source_metadata,
            record_count=len(parsed.records),
            records_json=list(parsed.records),
            validity_state="VALID",
            created_at=retrieved,
        )
        try:
            with self._sessions.begin() as session:
                existing = session.get(SourceIntelligenceSnapshotRow, snapshot_id)
                if existing is None:
                    session.add(row)
                    session.flush()
                    existing = row
                return self._snapshot(existing, verify_artifact=True)
        except (IntegrityError, SQLAlchemyError, OSError, TypeError, ValueError) as error:
            # A concurrent identical insert is deliberately idempotent.
            try:
                with self._sessions() as session:
                    existing = session.get(SourceIntelligenceSnapshotRow, snapshot_id)
                    if existing is not None:
                        return self._snapshot(existing, verify_artifact=True)
            except Exception:
                pass
            raise IntelligenceIntegrityError("intelligence snapshot persistence failed") from error

    def import_nvd(
        self,
        payload: bytes,
        *,
        expected_cve: str,
        retrieved_at: datetime | None = None,
    ) -> NvdEnrichment:
        cve_id = validate_cve_id(expected_cve)
        normalized = parse_nvd_enrichment(payload, expected_cve=cve_id)
        retrieved = self._time(retrieved_at)
        content_sha = hashlib.sha256(payload).hexdigest()
        enrichment_id = identity(
            b"securescan-nvd-enrichment-v1\0",
            {"content_sha256": content_sha, "cve_id": cve_id, "parser": NVD_PARSER_CONTRACT},
        )
        artifact = self._artifacts.put(
            payload,
            kind=ArtifactKind.THREAT_INTELLIGENCE,
            media_type="application/json",
            sanitized=True,
        )
        row = SourceNvdEnrichmentRow(
            enrichment_id=enrichment_id,
            cve_id=cve_id,
            retrieved_at=retrieved,
            content_sha256=artifact.sha256,
            artifact_size_bytes=artifact.size_bytes,
            parser_contract_version=NVD_PARSER_CONTRACT,
            source_schema="nvd-cve-api-2.0",
            normalized_json=normalized,
            created_at=retrieved,
        )
        try:
            with self._sessions.begin() as session:
                existing = session.get(SourceNvdEnrichmentRow, enrichment_id)
                if existing is None:
                    session.add(row)
                    session.flush()
                    existing = row
                return self._nvd(existing, verify_artifact=True)
        except (IntegrityError, SQLAlchemyError, OSError, TypeError, ValueError) as error:
            try:
                with self._sessions() as session:
                    existing = session.get(SourceNvdEnrichmentRow, enrichment_id)
                    if existing is not None:
                        return self._nvd(existing, verify_artifact=True)
            except Exception:
                pass
            raise IntelligenceIntegrityError("NVD enrichment persistence failed") from error

    def list_snapshots(
        self, source: IntelligenceSource | None = None
    ) -> tuple[IntelligenceSnapshot, ...]:
        try:
            with self._sessions() as session:
                statement = select(SourceIntelligenceSnapshotRow)
                if source is not None:
                    statement = statement.where(
                        SourceIntelligenceSnapshotRow.source == source.value
                    )
                rows = session.scalars(
                    statement.order_by(
                        SourceIntelligenceSnapshotRow.retrieved_at.desc(),
                        SourceIntelligenceSnapshotRow.snapshot_id,
                    )
                ).all()
                return tuple(self._snapshot(row, verify_artifact=True) for row in rows)
        except (SQLAlchemyError, OSError, TypeError, ValueError) as error:
            raise IntelligenceIntegrityError("intelligence snapshot read failed") from error

    def get_snapshot(self, snapshot_id: str) -> IntelligenceSnapshot:
        """Load one immutable snapshot and revalidate its CAS artifact."""
        try:
            with self._sessions() as session:
                row = session.get(SourceIntelligenceSnapshotRow, snapshot_id)
                if row is None:
                    raise IntelligenceNotFoundError("intelligence snapshot is unavailable")
                return self._snapshot(row, verify_artifact=True)
        except IntelligenceServiceError:
            raise
        except (SQLAlchemyError, OSError, TypeError, ValueError) as error:
            raise IntelligenceIntegrityError("intelligence snapshot read failed") from error

    def get_nvd(self, enrichment_id: str) -> NvdEnrichment:
        """Load one exact-CVE NVD enrichment and revalidate its CAS artifact."""
        try:
            with self._sessions() as session:
                row = session.get(SourceNvdEnrichmentRow, enrichment_id)
                if row is None:
                    raise IntelligenceNotFoundError("NVD enrichment is unavailable")
                return self._nvd(row, verify_artifact=True)
        except IntelligenceServiceError:
            raise
        except (SQLAlchemyError, OSError, TypeError, ValueError) as error:
            raise IntelligenceIntegrityError("NVD enrichment read failed") from error

    def create_bundle(
        self,
        *,
        kev_snapshot_id: str | None,
        epss_snapshot_id: str | None,
        nvd_enrichment_ids: tuple[str, ...] = (),
    ) -> IntelligenceBundle:
        nvd_ids = tuple(sorted(set(nvd_enrichment_ids)))
        if len(nvd_ids) != len(nvd_enrichment_ids):
            raise IntelligenceIntegrityError("duplicate NVD enrichment")
        bundle_id = identity(
            b"securescan-intelligence-bundle-v1\0",
            {"epss": epss_snapshot_id, "kev": kev_snapshot_id, "nvd": list(nvd_ids)},
        )
        try:
            with self._sessions.begin() as session:
                if kev_snapshot_id is not None:
                    self._require_snapshot(session, kev_snapshot_id, IntelligenceSource.CISA_KEV)
                if epss_snapshot_id is not None:
                    self._require_snapshot(session, epss_snapshot_id, IntelligenceSource.FIRST_EPSS)
                for enrichment_id in nvd_ids:
                    if session.get(SourceNvdEnrichmentRow, enrichment_id) is None:
                        raise IntelligenceNotFoundError("NVD enrichment is unavailable")
                row = session.get(SourceIntelligenceBundleRow, bundle_id)
                if row is None:
                    row = SourceIntelligenceBundleRow(
                        bundle_id=bundle_id,
                        kev_snapshot_id=kev_snapshot_id,
                        epss_snapshot_id=epss_snapshot_id,
                        nvd_enrichment_ids_json=list(nvd_ids),
                        created_at=self._time(None),
                    )
                    session.add(row)
                    session.flush()
                return self._bundle(row)
        except IntelligenceServiceError:
            raise
        except IntegrityError as error:
            try:
                with self._sessions() as session:
                    row = session.get(SourceIntelligenceBundleRow, bundle_id)
                    if row is not None:
                        return self._bundle(row)
            except Exception:
                pass
            raise IntelligenceIntegrityError("intelligence bundle persistence failed") from error
        except (SQLAlchemyError, TypeError, ValueError) as error:
            raise IntelligenceIntegrityError("intelligence bundle persistence failed") from error

    def get_bundle(self, bundle_id: str, *, verify_artifacts: bool = True) -> IntelligenceBundle:
        try:
            with self._sessions() as session:
                row = session.get(SourceIntelligenceBundleRow, bundle_id)
                if row is None:
                    raise IntelligenceNotFoundError("intelligence bundle is unavailable")
                bundle = self._bundle(row)
                if bundle.kev_snapshot_id is not None:
                    self._snapshot(
                        self._require_snapshot(
                            session, bundle.kev_snapshot_id, IntelligenceSource.CISA_KEV
                        ),
                        verify_artifact=verify_artifacts,
                    )
                if bundle.epss_snapshot_id is not None:
                    self._snapshot(
                        self._require_snapshot(
                            session, bundle.epss_snapshot_id, IntelligenceSource.FIRST_EPSS
                        ),
                        verify_artifact=verify_artifacts,
                    )
                for enrichment_id in bundle.nvd_enrichment_ids:
                    enrichment = session.get(SourceNvdEnrichmentRow, enrichment_id)
                    if enrichment is None:
                        raise IntelligenceIntegrityError("bundle NVD evidence is missing")
                    self._nvd(enrichment, verify_artifact=verify_artifacts)
                return bundle
        except IntelligenceServiceError:
            raise
        except (SQLAlchemyError, OSError, TypeError, ValueError) as error:
            raise IntelligenceIntegrityError("intelligence bundle read failed") from error

    def evaluate_run(
        self,
        *,
        project_id: str,
        lineage_id: str,
        run_id: str,
        bundle_id: str,
        evaluated_at: datetime | None = None,
    ) -> tuple[ThreatAssessment, ...]:
        evaluated = self._time(evaluated_at)
        try:
            verified = self._verified.load(
                run_id=run_id,
                expected_project_id=project_id,
                expected_lineage_id=lineage_id,
            )
        except VerifiedPublishedRunError as error:
            raise IntelligenceNotFoundError("verified run is unavailable") from error
        evidence = {item.evidence_id: item for item in verified.report.evidence}
        relationships = []
        for finding in verified.report.findings:
            if finding.category is not FindingCategory.DEPENDENCY_VULNERABILITY:
                continue
            for reference in finding.primary_evidence_refs:
                item = evidence.get(reference)
                if item is None or item.evidence_kind is not EvidenceKind.OSV_ADVISORY_GROUP:
                    continue
                payload = item.payload
                if not isinstance(payload, OsvAdvisoryGroupEvidencePayload):
                    raise IntelligenceIntegrityError("OSV group evidence is invalid")
                cves = exact_cve_aliases(payload.aliases)
                for cve in cves:
                    relationships.append((finding.finding_id, payload.canonical_advisory_id, cve))
        relationships = sorted(set(relationships))
        try:
            with self._sessions.begin() as session:
                if session.get_bind().dialect.name == "postgresql":
                    session.connection(execution_options={"isolation_level": "REPEATABLE READ"})
                bundle_row = session.get(SourceIntelligenceBundleRow, bundle_id)
                if bundle_row is None:
                    raise IntelligenceNotFoundError("intelligence bundle is unavailable")
                kev = self._snapshot_records(
                    session, bundle_row.kev_snapshot_id, IntelligenceSource.CISA_KEV
                )
                epss = self._snapshot_records(
                    session, bundle_row.epss_snapshot_id, IntelligenceSource.FIRST_EPSS
                )
                nvd_by_cve = {}
                for enrichment_id in bundle_row.nvd_enrichment_ids_json:
                    row = session.get(SourceNvdEnrichmentRow, enrichment_id)
                    if row is None:
                        raise IntelligenceIntegrityError("bundle NVD evidence is missing")
                    self._nvd(row, verify_artifact=True)
                    if row.cve_id in nvd_by_cve:
                        raise IntelligenceIntegrityError("bundle has duplicate NVD CVE evidence")
                    nvd_by_cve[row.cve_id] = row
                results = []
                for finding_id, advisory_id, cve_id in relationships:
                    kev_record = kev.get(cve_id) if kev is not None else None
                    epss_record = epss.get(cve_id) if epss is not None else None
                    nvd = nvd_by_cve.get(cve_id)
                    kev_evidence = {
                        "state": (
                            KevState.UNAVAILABLE.value
                            if kev is None
                            else KevState.LISTED.value
                            if kev_record is not None
                            else KevState.NOT_LISTED_IN_SNAPSHOT.value
                        ),
                        "snapshot_id": bundle_row.kev_snapshot_id,
                        "record": kev_record,
                    }
                    epss_evidence = {
                        "state": (
                            EpssState.UNAVAILABLE.value
                            if epss is None
                            else EpssState.SCORED.value
                            if epss_record is not None
                            else EpssState.NOT_SCORED.value
                        ),
                        "snapshot_id": bundle_row.epss_snapshot_id,
                        "record": epss_record,
                    }
                    assessment_id = identity(
                        b"securescan-threat-assessment-v1\0",
                        {
                            "advisory_id": advisory_id,
                            "bundle_id": bundle_id,
                            "cve_id": cve_id,
                            "finding_id": finding_id,
                            "run_id": run_id,
                        },
                    )
                    row = session.get(SourceThreatAssessmentRow, assessment_id)
                    if row is None:
                        row = SourceThreatAssessmentRow(
                            assessment_id=assessment_id,
                            project_id=project_id,
                            lineage_id=lineage_id,
                            run_id=run_id,
                            finding_id=finding_id,
                            advisory_id=advisory_id,
                            cve_id=cve_id,
                            bundle_id=bundle_id,
                            kev_evidence_json=kev_evidence,
                            epss_evidence_json=epss_evidence,
                            nvd_enrichment_id=None if nvd is None else nvd.enrichment_id,
                            evaluated_at=evaluated,
                        )
                        session.add(row)
                        session.flush()
                    results.append(self._assessment(row))
                return tuple(results)
        except IntelligenceServiceError:
            raise
        except (IntegrityError, SQLAlchemyError, OSError, TypeError, ValueError) as error:
            raise IntelligenceIntegrityError("threat evaluation failed") from error

    def list_assessments(self, *, project_id: str, run_id: str) -> tuple[ThreatAssessment, ...]:
        try:
            with self._sessions() as session:
                rows = session.scalars(
                    select(SourceThreatAssessmentRow)
                    .where(
                        SourceThreatAssessmentRow.project_id == project_id,
                        SourceThreatAssessmentRow.run_id == run_id,
                    )
                    .order_by(
                        SourceThreatAssessmentRow.finding_id,
                        SourceThreatAssessmentRow.cve_id,
                        SourceThreatAssessmentRow.evaluated_at,
                    )
                ).all()
                return tuple(self._assessment(row) for row in rows)
        except (SQLAlchemyError, TypeError, ValueError) as error:
            raise IntelligenceIntegrityError("threat assessment read failed") from error

    def _snapshot(
        self, row: SourceIntelligenceSnapshotRow, *, verify_artifact: bool
    ) -> IntelligenceSnapshot:
        try:
            source = IntelligenceSource(row.source)
            records = tuple(row.records_json)
            if row.validity_state != "VALID" or row.record_count != len(records):
                raise ValueError
            if verify_artifact:
                payload = self._artifacts.read_by_sha256(
                    row.content_sha256, expected_size_bytes=row.artifact_size_bytes
                )
                parsed = (
                    parse_kev_snapshot(payload)
                    if source is IntelligenceSource.CISA_KEV
                    else parse_epss_snapshot(payload)
                )
                if (
                    parsed.parser_contract_version != row.parser_contract_version
                    or parsed.source_schema != row.source_schema
                    or parsed.source_metadata != row.source_metadata_json
                    or list(parsed.records) != row.records_json
                ):
                    raise ValueError
            return IntelligenceSnapshot(
                snapshot_id=row.snapshot_id,
                source=source,
                retrieved_at=as_utc(row.retrieved_at),
                source_effective_at=None
                if row.source_effective_at is None
                else as_utc(row.source_effective_at),
                content_sha256=row.content_sha256,
                artifact_size_bytes=row.artifact_size_bytes,
                parser_contract_version=row.parser_contract_version,
                source_schema=row.source_schema,
                source_metadata=dict(row.source_metadata_json),
                record_count=row.record_count,
                records=records,
                validity_state=row.validity_state,
            )
        except (IntelligenceIngestionError, OSError, TypeError, ValueError):
            raise IntelligenceIntegrityError("intelligence snapshot is corrupt") from None

    def _nvd(self, row: SourceNvdEnrichmentRow, *, verify_artifact: bool) -> NvdEnrichment:
        try:
            if verify_artifact:
                payload = self._artifacts.read_by_sha256(
                    row.content_sha256, expected_size_bytes=row.artifact_size_bytes
                )
                if parse_nvd_enrichment(payload, expected_cve=row.cve_id) != row.normalized_json:
                    raise ValueError
            return NvdEnrichment(
                enrichment_id=row.enrichment_id,
                cve_id=validate_cve_id(row.cve_id),
                retrieved_at=as_utc(row.retrieved_at),
                content_sha256=row.content_sha256,
                artifact_size_bytes=row.artifact_size_bytes,
                parser_contract_version=row.parser_contract_version,
                source_schema=row.source_schema,
                normalized=dict(row.normalized_json),
            )
        except (IntelligenceIngestionError, OSError, TypeError, ValueError):
            raise IntelligenceIntegrityError("NVD enrichment is corrupt") from None

    def _snapshot_records(
        self, session: Session, snapshot_id: str | None, source: IntelligenceSource
    ) -> dict[str, dict] | None:
        if snapshot_id is None:
            return None
        row = self._require_snapshot(session, snapshot_id, source)
        snapshot = self._snapshot(row, verify_artifact=True)
        result = {item["cve_id"]: item for item in snapshot.records}
        if len(result) != snapshot.record_count:
            raise IntelligenceIntegrityError("snapshot contains duplicate CVE records")
        return result

    @staticmethod
    def _require_snapshot(
        session: Session, snapshot_id: str, source: IntelligenceSource
    ) -> SourceIntelligenceSnapshotRow:
        row = session.get(SourceIntelligenceSnapshotRow, snapshot_id)
        if row is None or row.source != source.value:
            raise IntelligenceNotFoundError("intelligence snapshot is unavailable")
        return row

    @staticmethod
    def _bundle(row: SourceIntelligenceBundleRow) -> IntelligenceBundle:
        ids = tuple(row.nvd_enrichment_ids_json)
        if ids != tuple(sorted(set(ids))):
            raise IntelligenceIntegrityError("intelligence bundle is invalid")
        expected = identity(
            b"securescan-intelligence-bundle-v1\0",
            {"epss": row.epss_snapshot_id, "kev": row.kev_snapshot_id, "nvd": list(ids)},
        )
        if expected != row.bundle_id:
            raise IntelligenceIntegrityError("intelligence bundle is invalid")
        return IntelligenceBundle(row.bundle_id, row.kev_snapshot_id, row.epss_snapshot_id, ids)

    @staticmethod
    def _assessment(row: SourceThreatAssessmentRow) -> ThreatAssessment:
        expected = identity(
            b"securescan-threat-assessment-v1\0",
            {
                "advisory_id": row.advisory_id,
                "bundle_id": row.bundle_id,
                "cve_id": row.cve_id,
                "finding_id": row.finding_id,
                "run_id": row.run_id,
            },
        )
        if expected != row.assessment_id:
            raise IntelligenceIntegrityError("threat assessment is invalid")
        return ThreatAssessment(
            assessment_id=row.assessment_id,
            project_id=row.project_id,
            lineage_id=row.lineage_id,
            run_id=row.run_id,
            finding_id=row.finding_id,
            advisory_id=row.advisory_id,
            cve_id=row.cve_id,
            intelligence_bundle_id=row.bundle_id,
            kev_evidence=dict(row.kev_evidence_json),
            epss_evidence=dict(row.epss_evidence_json),
            nvd_enrichment_id=row.nvd_enrichment_id,
            evaluated_at=as_utc(row.evaluated_at),
        )

    def _time(self, value: datetime | None) -> datetime:
        return as_utc(self._clock() if value is None else value)
