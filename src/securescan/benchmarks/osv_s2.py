from __future__ import annotations

import hashlib
import json
import os
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from securescan.advisories.osv import (
    OSV_SCHEMA_SHA256,
    HttpxOsvTransport,
    OsvCandidateMatch,
    OsvHttpResponse,
    TrustedOsvClient,
    build_osv_query_candidates,
    build_osv_service_contract,
    canonical_json,
    group_advisories,
)
from securescan.scanners.syft import PackageObservation

OSV_CONTROLLED_PLAN_SHA256 = "cc1ff201d98bf1162cb9d40f078f5b3512b5c00cdc383337a95a2882c64076c7"
OSV_SERVICE_CONTRACT_SHA256 = "f4e5f14799634e2da927e73fdba18510d15d13996563d0ad436da87179f73c6f"
OSV_SERVICE_SNAPSHOT_SHA256 = "710a2314b65c158fb508530a1fb3c233580bbc5de02ea2a560c015e30c2004f9"
OSV_CONTROLLED_REPORT_SHA256 = "d86b97fd1cb732afe5bcb7947e47353553eb0e877217832ce4b2cecec1d70ef2"

_PROJECTION_ID = "securescan-source-projection-" + "52" * 16
_SNAPSHOT_DIGEST = "52" * 32
_SYFT_BINDING_DIGEST = "392fdda53e1192ca40fb22893e5fce90828a4171e67e28eb09632d9bc8159da0"
_PLAN = (
    (
        "go-fixed-boundary",
        "gopkg.in/yaml.v3",
        "v3.0.1",
        "go-module",
        "go",
        "pkg:golang/gopkg.in/yaml.v3@v3.0.1",
    ),
    ("pypi-affected", "PyYAML", "5.3.1", "python", "python", "pkg:pypi/pyyaml@5.3.1"),
    (
        "pypi-fixed-boundary",
        "PyYAML",
        "5.4",
        "python",
        "python",
        "pkg:pypi/pyyaml@5.4",
    ),
    ("npm-affected", "minimist", "0.0.8", "npm", "javascript", "pkg:npm/minimist@0.0.8"),
    (
        "npm-fixed-boundary",
        "minimist",
        "1.2.6",
        "npm",
        "javascript",
        "pkg:npm/minimist@1.2.6",
    ),
    (
        "go-affected",
        "gopkg.in/yaml.v3",
        "v3.0.0-20200313102051-9f266ea9e77c",
        "go-module",
        "go",
        "pkg:golang/gopkg.in/yaml.v3@v3.0.0-20200313102051-9f266ea9e77c",
    ),
)


class OsvBenchmarkError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("Controlled OSV S2 evaluation failed")


def _plan_data() -> dict[str, Any]:
    candidate_ids = {
        candidate.purl: candidate.candidate_id for candidate in build_controlled_candidates()
    }
    return {
        "packages": [
            {
                "candidate_id": candidate_ids[purl],
                "case_id": case_id,
                "case_role": (
                    "AFFECTED"
                    if case_id.endswith("affected")
                    else "SAME_PACKAGE_FIXED_BOUNDARY"
                ),
                "language": language,
                "package_name": name,
                "package_type": package_type,
                "package_version": package_version,
                "purl": purl,
            }
            for case_id, name, package_version, package_type, language, purl in sorted(
                _PLAN, key=lambda item: candidate_ids[item[5]]
            )
        ],
        "schema_version": "securescan-osv-controlled-query-plan-s2",
    }


def build_controlled_candidates():
    observations = tuple(
        PackageObservation.create(
            package_name=name,
            package_version=package_version,
            package_type=package_type,
            language=language,
            purl=purl,
            found_by="securescan-s2-controlled-plan",
            locations=(f"controlled/{case_id}.lock",),
            projection_id=_PROJECTION_ID,
            snapshot_digest=_SNAPSHOT_DIGEST,
            binding_digest=_SYFT_BINDING_DIGEST,
        )
        for case_id, name, package_version, package_type, language, purl in _PLAN
    )
    candidates, gaps = build_osv_query_candidates(observations)
    if gaps:
        raise OsvBenchmarkError
    return tuple(sorted(candidates, key=lambda item: item.candidate_id))


def _sanitize_advisory(value: dict[str, Any]) -> dict[str, Any]:
    retained = {
        key: value[key]
        for key in (
            "schema_version",
            "id",
            "modified",
            "published",
            "withdrawn",
            "aliases",
            "upstream",
            "related",
            "summary",
            "severity",
        )
        if key in value
    }
    affected_values = []
    for affected in value.get("affected") or ():
        clean = {
            key: affected[key]
            for key in ("package", "severity", "ranges", "versions")
            if key in affected
        }
        affected_values.append(clean)
    if "affected" in value:
        retained["affected"] = affected_values
    return retained


@dataclass
class _RecordingTransport:
    delegate: HttpxOsvTransport
    exchanges: list[dict[str, Any]]

    def request(
        self, method: str, path: str, *, json_body: dict[str, Any] | None, limit: int
    ) -> OsvHttpResponse:
        response = self.delegate.request(method, path, json_body=json_body, limit=limit)
        self.exchanges.append(
            {
                "method": method,
                "path": path,
                "request": json_body,
                "response_body": response.body,
                "status_code": response.status_code,
            }
        )
        return response


def _sanitize_validated_exchanges(
    exchanges: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    result = []
    for exchange in exchanges:
        parsed = json.loads(exchange["response_body"])
        if exchange["method"] == "GET":
            parsed = _sanitize_advisory(parsed)
        result.append(
            {
                "method": exchange["method"],
                "path": exchange["path"],
                "request": exchange["request"],
                "response": parsed,
                "status_code": exchange["status_code"],
            }
        )
    return result


class _SnapshotTransport:
    def __init__(self, exchanges: tuple[dict[str, Any], ...]) -> None:
        self._exchanges = exchanges
        self._index = 0

    def request(
        self, method: str, path: str, *, json_body: dict[str, Any] | None, limit: int
    ) -> OsvHttpResponse:
        if self._index >= len(self._exchanges):
            raise OsvBenchmarkError
        exchange = self._exchanges[self._index]
        self._index += 1
        if (
            exchange.get("method") != method
            or exchange.get("path") != path
            or exchange.get("request") != json_body
        ):
            raise OsvBenchmarkError
        body = canonical_json(exchange["response"])
        if len(body) > limit:
            raise OsvBenchmarkError
        return OsvHttpResponse(exchange["status_code"], body)

    def require_complete(self) -> None:
        if self._index != len(self._exchanges):
            raise OsvBenchmarkError


def _analysis_data(matches: tuple[OsvCandidateMatch, ...]) -> dict[str, Any]:
    findings = tuple(
        sorted(
            (
                finding
                for match in matches
                for finding in group_advisories(match.candidate, match.advisories)
            ),
            key=lambda item: item.finding_id,
        )
    )
    return {
        "advisory_record_count": len(
            {item.osv_record_id for match in matches for item in match.advisories}
        ),
        "alias_group_count": len(findings),
        "candidate_count": len(matches),
        "cve_aliases": sorted({value for item in findings for value in item.cve_aliases}),
        "finding_count": len(findings),
        "findings": [
            {
                "advisory_group_key": item.advisory_group_key,
                "canonical_advisory_id": item.canonical_advisory_id,
                "cve_aliases": list(item.cve_aliases),
                "cvss": [
                    {
                        "base_score": value.base_score,
                        "source": value.source,
                        "scope": value.scope.value,
                        "type": value.cvss_type,
                        "vector": value.vector,
                    }
                    for value in item.cvss
                ],
                "finding_id": item.finding_id,
                "fixed_versions": list(item.fixed_versions),
                "ghsa_aliases": list(item.ghsa_aliases),
                "locations": list(item.locations),
                "osv_record_ids": list(item.osv_record_ids),
                "package_key": item.package_key,
                "purl": item.purl,
            }
            for item in findings
        ],
        "fixed_versions": sorted({value for item in findings for value in item.fixed_versions}),
        "ghsa_aliases": sorted({value for item in findings for value in item.ghsa_aliases}),
        "schema_version": "securescan-osv-controlled-evaluation-s2",
        "zero_advisory_candidate_count": sum(not match.references for match in matches),
    }


def _snapshot_digest(snapshot: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(snapshot)).hexdigest()


def _report_data(snapshot: dict[str, Any], analysis: dict[str, Any]) -> dict[str, Any]:
    return {
        "analysis": analysis,
        "query_plan_sha256": hashlib.sha256(canonical_json(_plan_data())).hexdigest(),
        "schema": {"sha256": OSV_SCHEMA_SHA256, "version": "1.9.0"},
        "schema_version": "securescan-osv-controlled-report-s2",
        "service_snapshot_sha256": _snapshot_digest(snapshot),
    }


def acquire_controlled_snapshot() -> tuple[dict[str, Any], dict[str, Any]]:
    candidates = build_controlled_candidates()
    with HttpxOsvTransport() as transport:
        recording = _RecordingTransport(transport, [])
        live = TrustedOsvClient(recording).query(candidates)
    snapshot = {
        "exchanges": _sanitize_validated_exchanges(recording.exchanges),
        "query_plan_sha256": hashlib.sha256(canonical_json(_plan_data())).hexdigest(),
        "schema": {"sha256": OSV_SCHEMA_SHA256, "version": "1.9.0"},
        "schema_version": "securescan-osv-service-snapshot-s2",
        "service_contract": build_osv_service_contract(),
    }
    replay = evaluate_snapshot(snapshot)
    live_data = _analysis_data(live)
    if replay != live_data:
        raise OsvBenchmarkError
    return snapshot, _report_data(snapshot, replay)


def evaluate_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    if (
        snapshot.get("schema_version") != "securescan-osv-service-snapshot-s2"
        or snapshot.get("schema") != {"sha256": OSV_SCHEMA_SHA256, "version": "1.9.0"}
        or snapshot.get("service_contract") != build_osv_service_contract()
        or snapshot.get("query_plan_sha256")
        != hashlib.sha256(canonical_json(_plan_data())).hexdigest()
        or not isinstance(snapshot.get("exchanges"), list)
    ):
        raise OsvBenchmarkError
    transport = _SnapshotTransport(tuple(snapshot["exchanges"]))
    matches = TrustedOsvClient(transport, sleep=lambda _seconds: None).query(
        build_controlled_candidates()
    )
    transport.require_complete()
    return _analysis_data(matches)


def build_controlled_report(snapshot: dict[str, Any]) -> dict[str, Any]:
    return _report_data(snapshot, evaluate_snapshot(snapshot))


def _write_exclusive_atomic(path: Path, payload: bytes) -> None:
    if os.path.lexists(path):
        raise OsvBenchmarkError
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            raise OsvBenchmarkError from None
        directory_descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        os.unlink(temporary)
    except BaseException:
        with suppress(FileNotFoundError):
            os.unlink(temporary)
        raise


def main() -> int:
    root = Path(__file__).resolve().parents[3]
    directory = root / "benchmarks/osv"
    plan_path = directory / "controlled-query-plan-v1.json"
    contract_path = directory / "service-contract-v1.json"
    snapshot_path = directory / "controlled-service-snapshot-v1.json"
    report_path = directory / "controlled-evaluation-v1.json"
    mode = os.environ.get("SECURESCAN_OSV_MODE", "check")
    if mode == "acquire":
        if (
            plan_path.read_bytes() != canonical_json(_plan_data())
            or contract_path.read_bytes() != canonical_json(build_osv_service_contract())
            or os.path.lexists(snapshot_path)
            or os.path.lexists(report_path)
        ):
            raise OsvBenchmarkError
        snapshot, report = acquire_controlled_snapshot()
        _write_exclusive_atomic(snapshot_path, canonical_json(snapshot))
        _write_exclusive_atomic(report_path, canonical_json(report))
    elif mode in {"check", "report"}:
        plan_payload = plan_path.read_bytes()
        contract_payload = contract_path.read_bytes()
        snapshot_payload = snapshot_path.read_bytes()
        report_payload = report_path.read_bytes()
        snapshot = json.loads(snapshot_payload)
        report = build_controlled_report(snapshot)
        if (
            plan_payload != canonical_json(_plan_data())
            or contract_payload != canonical_json(build_osv_service_contract())
            or hashlib.sha256(plan_payload).hexdigest() != OSV_CONTROLLED_PLAN_SHA256
            or hashlib.sha256(contract_payload).hexdigest() != OSV_SERVICE_CONTRACT_SHA256
            or hashlib.sha256(snapshot_payload).hexdigest() != OSV_SERVICE_SNAPSHOT_SHA256
            or hashlib.sha256(report_payload).hexdigest() != OSV_CONTROLLED_REPORT_SHA256
        ):
            raise OsvBenchmarkError
        if report_payload != canonical_json(report):
            raise OsvBenchmarkError
        if mode == "report":
            print(canonical_json(report).decode(), end="")
    else:
        raise OsvBenchmarkError
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
