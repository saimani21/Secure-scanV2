"""Bounded, deterministic V1.5 intelligence performance characterization."""

from __future__ import annotations

import gzip
import json
import resource
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.intelligence.cve import exact_cve_aliases
from securescan.intelligence.ingestion import parse_epss_snapshot, parse_kev_snapshot
from securescan.intelligence.models import canonical_json, identity
from securescan.intelligence.service import IntelligenceService
from securescan.persistence.database import Base


def _cve(index: int) -> str:
    return f"CVE-2026-{index + 10000}"


def _kev(count: int) -> bytes:
    records = [
        {
            "cveID": _cve(index),
            "vendorProject": "Controlled",
            "product": "Widget",
            "vulnerabilityName": "Controlled vulnerability",
            "dateAdded": "2026-10-01",
            "shortDescription": "Bounded benchmark record",
            "requiredAction": "Apply update",
            "dueDate": "2026-10-20",
            "knownRansomwareCampaignUse": "Unknown",
        }
        for index in range(count)
    ]
    return json.dumps(
        {
            "catalogVersion": "2026.10.02",
            "dateReleased": "2026-10-02T00:00:00Z",
            "count": count,
            "vulnerabilities": records,
        },
        separators=(",", ":"),
    ).encode()


def _epss(count: int) -> bytes:
    rows = ["#model_version:v2026.06.15,score_date:2026-10-02", "cve,epss,percentile"]
    rows.extend(f"{_cve(index)},0.1234,0.5678" for index in range(count))
    return gzip.compress(("\n".join(rows) + "\n").encode())


def _timed(operation):
    started = time.perf_counter()
    value = operation()
    return value, time.perf_counter() - started


def characterize(scales: tuple[int, ...] = (100, 1_000, 10_000)) -> dict:
    results = []
    for count in scales:
        kev_bytes = _kev(count)
        epss_bytes = _epss(count)
        kev, kev_parse = _timed(lambda data=kev_bytes: parse_kev_snapshot(data))
        epss, epss_parse = _timed(lambda data=epss_bytes: parse_epss_snapshot(data))
        aliases = tuple(
            alias for index in range(count) for alias in (_cve(index), "GHSA-2222-3333-4444")
        )
        cves, correlation = _timed(lambda values=aliases: exact_cve_aliases(values))
        lookup, projection = _timed(
            lambda kev_data=kev, epss_data=epss: {
                record["cve_id"]: {
                    "kev": kev_data.records[index],
                    "epss": epss_data.records[index],
                }
                for index, record in enumerate(kev_data.records)
            }
        )
        assessments, assessment = _timed(
            lambda cve_values=cves: tuple(
                identity(
                    b"securescan-threat-assessment-v1\0",
                    {
                        "run_id": "00000000-0000-4000-8000-000000000001",
                        "finding_id": f"{index:064x}",
                        "advisory_id": f"OSV-{index}",
                        "cve_id": cve,
                        "bundle_id": "b" * 64,
                    },
                )
                for index, cve in enumerate(cve_values)
            )
        )
        _, assurance = _timed(
            lambda assessment_values=assessments, lookup_values=lookup: {
                "finding_count": len(assessment_values),
                "kev_listed_count": sum(
                    1 for value in lookup_values.values() if value["kev"] is not None
                ),
                "epss_scored_count": sum(
                    1 for value in lookup_values.values() if value["epss"] is not None
                ),
            }
        )
        proof = {
            "schema_version": "securescan-policy-decision-proof-v1",
            "result": "FAIL",
            "decisions": [
                {
                    "kind": "VIOLATION",
                    "rule_id": "INTRODUCED_EPSS_THRESHOLD",
                    "finding_id": f"{index:064x}",
                    "cve_id": cve,
                }
                for index, cve in enumerate(cves)
            ],
        }
        proof_bytes, proof_time = _timed(lambda value=proof: canonical_json(value))
        results.append(
            {
                "relationships": count,
                "kev_bytes": len(kev_bytes),
                "epss_compressed_bytes": len(epss_bytes),
                "kev_parse_seconds": kev_parse,
                "epss_parse_seconds": epss_parse,
                "exact_cve_correlation_seconds": correlation,
                "finding_intelligence_projection_seconds": projection,
                "threat_assessment_identity_seconds": assessment,
                "run_assurance_aggregation_seconds": assurance,
                "policy_decision_proof_seconds": proof_time,
                "policy_decision_proof_bytes": len(proof_bytes),
            }
        )

    with tempfile.TemporaryDirectory(prefix="securescan-v15-benchmark-") as directory:
        root = Path(directory)
        engine = create_engine(f"sqlite:///{root / 'benchmark.db'}")
        Base.metadata.create_all(engine)
        sessions = sessionmaker(bind=engine, expire_on_commit=False)
        queries = 0

        @event.listens_for(engine, "before_cursor_execute")
        def count_query(*_: object) -> None:
            nonlocal queries
            queries += 1

        service = IntelligenceService(
            sessions,
            ContentAddressedArtifactStore(root / "artifacts"),
            clock=lambda: datetime(2026, 10, 2, tzinfo=UTC),
        )
        _, kev_import = _timed(lambda: service.import_kev(_kev(scales[-1])))
        _, epss_import = _timed(lambda: service.import_epss(_epss(scales[-1])))
        engine.dispose()

    return {
        "platform": "local CPython 3.12; single process; SQLite import persistence",
        "scales": results,
        "largest_import": {
            "relationships": scales[-1],
            "kev_import_seconds": kev_import,
            "epss_import_seconds": epss_import,
            "sql_statement_count": queries,
        },
        "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
    }


def main() -> None:
    print(json.dumps(characterize(), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
