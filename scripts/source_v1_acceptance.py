#!/usr/bin/env python3
"""Prepare and verify the Source v1 release-acceptance evidence boundary."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import UUID

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = REPOSITORY_ROOT / "tests/fixtures/source_v1_acceptance/manifest-v1.json"
MANIFEST_SHA256 = "3006153694f349aa7f263f4a1396a777900950fa50ca9cc567a1c1cd785fa02d"
SUMMARY_SCHEMA_VERSION = "securescan-source-v1-release-acceptance-summary-v1"
_MAX_FILE_BYTES = 32 * 1024 * 1024
_SHA256_CHARS = frozenset("0123456789abcdef")
_STATE_IDS = (
    "A_VULNERABLE_INITIAL",
    "B_VULNERABLE_UNCHANGED",
    "C_REMEDIATED",
    "D_VULNERABLE_REINTRODUCED",
)
_LIFECYCLE_STATES = ("NEW", "EXISTING", "RESOLVED", "REOPENED")
_LIFECYCLE_REASONS = (
    "FIRST_OBSERVATION",
    "OBSERVED_AGAIN",
    "COMPARABLE_SCOPE_ABSENCE",
    "RETURNED_AFTER_RESOLUTION",
)
_PREVIOUS_LIFECYCLE_STATES = (None, "NEW", "EXISTING", "RESOLVED")
_AUTHORITIES = ("checkov", "gitleaks", "osv.dev", "semgrep-ce", "syft")
_SUCCESSFUL_COVERAGE_STATES = {
    "COMPLETE",
    "COMPLETE_WITH_FINDINGS",
    "COMPLETE_WITH_SUPPRESSIONS",
}
_ALLOWED_COVERAGE_STATES = _SUCCESSFUL_COVERAGE_STATES | {"NOT_APPLICABLE"}


class AcceptanceError(RuntimeError):
    """Fixed public failure for invalid acceptance input."""

    def __init__(self) -> None:
        super().__init__("Source v1 release acceptance input is invalid")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _read_regular_file(path: Path) -> bytes:
    try:
        metadata = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or not 0 <= metadata.st_size <= _MAX_FILE_BYTES
        ):
            raise AcceptanceError
        value = path.read_bytes()
    except (OSError, ValueError):
        raise AcceptanceError from None
    if len(value) != metadata.st_size or len(value) > _MAX_FILE_BYTES:
        raise AcceptanceError
    return value


def _mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise AcceptanceError
    return value


def _list(value: Any) -> list[Any]:
    if not isinstance(value, list):
        raise AcceptanceError
    return value


def _text(value: Any) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise AcceptanceError
    return value


def _integer(value: Any) -> int:
    if type(value) is not int or value < 0:
        raise AcceptanceError
    return value


def _sha(value: Any) -> str:
    text = _text(value)
    if len(text) != 64 or text != text.lower() or any(item not in _SHA256_CHARS for item in text):
        raise AcceptanceError
    return text


def _uuid(value: Any) -> str:
    text = _text(value)
    try:
        normalized = str(UUID(text))
    except ValueError:
        raise AcceptanceError from None
    if normalized != text:
        raise AcceptanceError
    return text


def _relative_path(value: Any) -> str:
    text = _text(value)
    candidate = PurePosixPath(text)
    if candidate.is_absolute() or text != candidate.as_posix() or ".." in candidate.parts:
        raise AcceptanceError
    return text


def _json(path: Path) -> dict[str, Any]:
    try:
        return _mapping(json.loads(_read_regular_file(path)))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise AcceptanceError from None


def _repository_file(relative: Any, expected_sha256: Any) -> tuple[str, bytes]:
    relative_path = _relative_path(relative)
    expected = _sha(expected_sha256)
    path = REPOSITORY_ROOT.joinpath(*PurePosixPath(relative_path).parts)
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(REPOSITORY_ROOT.resolve())
    except (OSError, ValueError):
        raise AcceptanceError from None
    value = _read_regular_file(path)
    if _sha256(value) != expected:
        raise AcceptanceError
    return relative_path, value


def load_and_verify_manifest() -> dict[str, Any]:
    raw = _read_regular_file(MANIFEST_PATH)
    if _sha256(raw) != MANIFEST_SHA256:
        raise AcceptanceError
    try:
        manifest = _mapping(json.loads(raw))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise AcceptanceError from None
    if (
        manifest.get("schema_version")
        != "securescan-source-v1-release-acceptance-fixtures-v1"
        or manifest.get("fixture_version") != "source-v1-ra1"
    ):
        raise AcceptanceError

    contract = _mapping(manifest.get("gitleaks_contract"))
    if (
        contract.get("benchmark_case_id") != "github-pat-positive-01"
        or contract.get("expected_rule_id") != "github-pat"
        or contract.get("detection_kind") != "CONTENT"
        or contract.get("target_path") != "config/release-sentinel.txt"
        or contract.get("expected_line") != 3
    ):
        raise AcceptanceError
    _repository_file(
        "src/securescan/scanners/gitleaks/config/securescan-gitleaks-v1.toml",
        contract.get("production_config_sha256"),
    )
    _, plan_raw = _repository_file(
        "benchmarks/gitleaks/corpus-plan-v1.json",
        contract.get("benchmark_plan_sha256"),
    )
    _, benchmark_manifest_raw = _repository_file(
        "benchmarks/gitleaks/manifest.json",
        contract.get("benchmark_manifest_sha256"),
    )
    _, baseline_raw = _repository_file(
        "benchmarks/gitleaks/initial-v0.4f-baseline.json",
        contract.get("benchmark_baseline_sha256"),
    )
    try:
        plan = _mapping(json.loads(plan_raw))
        benchmark_manifest = _mapping(json.loads(benchmark_manifest_raw))
        baseline = _mapping(json.loads(baseline_raw))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise AcceptanceError from None
    plan_cases = [
        _mapping(item)
        for item in _list(plan.get("cases"))
        if _mapping(item).get("case_id") == contract["benchmark_case_id"]
    ]
    manifest_cases = [
        _mapping(item)
        for item in _list(benchmark_manifest.get("cases"))
        if _mapping(item).get("case_id") == contract["benchmark_case_id"]
    ]
    baseline_cases = [
        _mapping(item)
        for item in _list(baseline.get("cases"))
        if _mapping(item).get("case_id") == contract["benchmark_case_id"]
    ]
    if len(plan_cases) != 1 or len(manifest_cases) != 1 or len(baseline_cases) != 1:
        raise AcceptanceError
    plan_case, manifest_case, baseline_case = (
        plan_cases[0],
        manifest_cases[0],
        baseline_cases[0],
    )
    if (
        plan_case.get("expectation") != "EXPECTED_MATCH"
        or plan_case.get("rule_id") != contract["expected_rule_id"]
        or plan_case.get("detection_kind") != contract["detection_kind"]
        or plan_case.get("source_type") != "PROJECT_OWNED_SYNTHETIC"
        or plan_case.get("relative_path") != manifest_case.get("relative_path")
        or manifest_case.get("expectation") != "EXPECTED_MATCH"
        or manifest_case.get("expected_rule_id") != contract["expected_rule_id"]
        or manifest_case.get("expected_detection_kind") != contract["detection_kind"]
        or manifest_case.get("source_type") != "PROJECT_OWNED_SYNTHETIC"
        or manifest_case.get("sha256")
        != "1c6feea09e2698569d24c88ce6996843fb7e85c5ed7e66809b437ace319ac39e"
        or baseline_case.get("classification") != "TP"
        or baseline_case.get("expectation") != "EXPECTED_MATCH"
        or baseline_case.get("expected_rule_id") != contract["expected_rule_id"]
        or baseline_case.get("expected_detection_kind") != contract["detection_kind"]
        or baseline_case.get("relative_path") != manifest_case.get("relative_path")
        or baseline_case.get("same_rule_observation_count") != 1
        or len(_list(baseline_case.get("same_rule_finding_instance_ids"))) != 1
    ):
        raise AcceptanceError

    destinations: set[str] = set()
    for item_value in _list(manifest.get("shared_files")):
        item = _mapping(item_value)
        destination = _relative_path(item.get("destination"))
        if destination in destinations:
            raise AcceptanceError
        destinations.add(destination)
        _repository_file(item.get("source"), item.get("sha256"))

    states = [_mapping(item) for item in _list(manifest.get("states"))]
    if tuple(item.get("state_id") for item in states) != _STATE_IDS:
        raise AcceptanceError
    if tuple(item.get("expected_lifecycle") for item in states) != _LIFECYCLE_STATES:
        raise AcceptanceError
    if tuple(item.get("selected_target_present") for item in states) != (
        True,
        True,
        False,
        True,
    ):
        raise AcceptanceError
    directories: set[str] = set()
    fixture_hashes = []
    for state in states:
        directory = _relative_path(state.get("directory"))
        if "/" in directory or directory in directories:
            raise AcceptanceError
        directories.add(directory)
        fixture_hashes.append(_sha(state.get("gitleaks_fixture_sha256")))
        _repository_file(
            state.get("gitleaks_fixture_source"),
            state.get("gitleaks_fixture_sha256"),
        )
    if not (fixture_hashes[0] == fixture_hashes[1] == fixture_hashes[3]):
        raise AcceptanceError
    if fixture_hashes[2] == fixture_hashes[0]:
        raise AcceptanceError

    expectations = _mapping(manifest.get("five_authority_expectations"))
    if tuple(sorted(expectations)) != _AUTHORITIES:
        raise AcceptanceError
    if _mapping(expectations["syft"]).get("evidence_role") != "package_component":
        raise AcceptanceError
    if any(
        _mapping(expectations[authority]).get("evidence_role") != "finding"
        for authority in _AUTHORITIES
        if authority != "syft"
    ):
        raise AcceptanceError
    return manifest


def prepare_fixtures(destination: Path) -> None:
    manifest = load_and_verify_manifest()
    candidate = destination.expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    candidate = candidate.resolve(strict=False)
    if candidate == Path(candidate.anchor) or os.path.lexists(candidate):
        raise AcceptanceError
    try:
        candidate.mkdir(parents=True, mode=0o700)
        shared = [
            (
                _relative_path(item["destination"]),
                _repository_file(item["source"], item["sha256"])[1],
            )
            for item in (_mapping(value) for value in manifest["shared_files"])
        ]
        target_path = _relative_path(manifest["gitleaks_contract"]["target_path"])
        for state_value in manifest["states"]:
            state = _mapping(state_value)
            state_root = candidate / _relative_path(state["directory"])
            for relative, value in shared:
                output = state_root.joinpath(*PurePosixPath(relative).parts)
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_bytes(value)
            _, sentinel = _repository_file(
                state["gitleaks_fixture_source"], state["gitleaks_fixture_sha256"]
            )
            output = state_root.joinpath(*PurePosixPath(target_path).parts)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(sentinel)
    except (OSError, ValueError):
        raise AcceptanceError from None


def _observation(root: Path, state_id: str, kind: str) -> dict[str, Any]:
    prefix = state_id[0].lower()
    return _json(root / f"{prefix}-{kind}.json")


def _finding_matches(
    item: dict[str, Any], rule_id: str, path: str, *, start_line: int | None = None
) -> bool:
    subject = item.get("subject")
    if not isinstance(subject, dict) or subject.get("rule_id") != rule_id:
        return False
    location = item.get("primary_location")
    if isinstance(location, dict):
        return location.get("path") == path and (
            start_line is None or location.get("start_line") == start_line
        )
    locations = item.get("locations")
    return isinstance(locations, list) and any(
        isinstance(value, dict)
        and value.get("path") == path
        and (start_line is None or value.get("start_line") == start_line)
        for value in locations
    )


def _authority_states(report: dict[str, Any]) -> dict[str, list[str]]:
    result: dict[str, set[str]] = {authority: set() for authority in _AUTHORITIES}
    for value in _list(report.get("coverage_outcomes")):
        outcome = _mapping(value)
        authority = _text(outcome.get("authority"))
        state = _text(outcome.get("state"))
        if authority not in result or state not in _ALLOWED_COVERAGE_STATES:
            raise AcceptanceError
        result[authority].add(state)
    if any(
        not values or values.isdisjoint(_SUCCESSFUL_COVERAGE_STATES)
        for values in result.values()
    ):
        raise AcceptanceError
    return {key: sorted(values) for key, values in sorted(result.items())}


def _coverage_scope_signature(report: dict[str, Any]) -> list[dict[str, Any]]:
    signature = []
    for value in _list(report.get("coverage_outcomes")):
        outcome = _mapping(value)
        signature.append(
            {
                "authority": _text(outcome.get("authority")),
                "capability": _text(outcome.get("capability")),
                "component_ref": outcome.get("component_ref"),
                "framework": outcome.get("framework"),
                "selected_scope": _list(outcome.get("selected_scope")),
            }
        )
    return sorted(
        signature,
        key=lambda item: json.dumps(item, separators=(",", ":"), sort_keys=True),
    )


def _assert_authority_evidence(
    report: dict[str, Any],
    manifest: dict[str, Any],
    *,
    selected_gitleaks_present: bool,
) -> None:
    expectations = _mapping(manifest["five_authority_expectations"])
    findings = [_mapping(item) for item in _list(report.get("findings"))]
    evidence = [_mapping(item) for item in _list(report.get("evidence"))]
    components = [_mapping(item) for item in _list(report.get("components"))]
    gitleaks = _mapping(expectations["gitleaks"])
    gitleaks_present = any(
        item.get("authority") == "gitleaks"
        and _finding_matches(
            item,
            _text(gitleaks["expected_rule_id"]),
            _text(manifest["gitleaks_contract"]["target_path"]),
            start_line=_integer(manifest["gitleaks_contract"]["expected_line"]),
        )
        for item in findings
    )
    if gitleaks_present is not selected_gitleaks_present:
        raise AcceptanceError
    semgrep = _mapping(expectations["semgrep-ce"])
    if not any(
        item.get("authority") == "semgrep-ce"
        and _finding_matches(
            item,
            _text(semgrep.get("expected_rule_id")),
            _text(semgrep.get("expected_path")),
        )
        for item in findings
    ):
        raise AcceptanceError
    checkov = _mapping(expectations["checkov"])
    expected_checkov_evidence = {
        item.get("evidence_id")
        for item in evidence
        if item.get("authority") == "checkov"
        and isinstance(item.get("payload"), dict)
        and item["payload"].get("check_id") == checkov.get("expected_check_id")
        and any(
            isinstance(location, dict)
            and location.get("path") == checkov.get("expected_path")
            for location in _list(item.get("locations"))
        )
    }
    if not expected_checkov_evidence or not any(
        item.get("authority") == "checkov"
        and isinstance(item.get("primary_evidence_refs"), list)
        and not expected_checkov_evidence.isdisjoint(item["primary_evidence_refs"])
        for item in findings
    ):
        raise AcceptanceError
    expected_purl = _text(_mapping(expectations["syft"])["expected_purl"])
    packages = {
        item.get("component_ref"): item
        for item in components
        if item.get("component_kind") == "PACKAGE"
        and isinstance(item.get("payload"), dict)
        and item["payload"].get("purl") == expected_purl
    }
    if not packages:
        raise AcceptanceError
    if not any(
        item.get("authority") == "osv.dev"
        and isinstance(item.get("subject"), dict)
        and item["subject"].get("component_ref") in packages
        for item in findings
    ):
        raise AcceptanceError


def build_summary(
    observations_root: Path,
    *,
    securescan_commit: str,
    project_id: str,
) -> dict[str, Any]:
    manifest = load_and_verify_manifest()
    if len(securescan_commit) != 40 or any(
        value not in _SHA256_CHARS for value in securescan_commit
    ):
        raise AcceptanceError
    project = _uuid(project_id)
    if not observations_root.is_dir() or observations_root.is_symlink():
        raise AcceptanceError

    selected_ids: list[str] = []
    lineage_id: str | None = None
    run_ids: set[str] = set()
    summaries = []
    expected_scope_signature: list[dict[str, Any]] | None = None
    for sequence, state_value in enumerate(manifest["states"], start=1):
        state = _mapping(state_value)
        state_id = _text(state["state_id"])
        status = _observation(observations_root, state_id, "status")
        lifecycle_event = _observation(observations_root, state_id, "lifecycle-event")
        report_wrapper = _observation(observations_root, state_id, "report")
        run_id = _uuid(lifecycle_event.get("run_id"))
        if run_id in run_ids:
            raise AcceptanceError
        run_ids.add(run_id)
        current_lineage = _uuid(lifecycle_event.get("lineage_id"))
        if lineage_id is None:
            lineage_id = current_lineage
        if (
            current_lineage != lineage_id
            or status.get("run_id") != run_id
            or status.get("lineage_id") != lineage_id
            or status.get("submission_sequence") != sequence
            or status.get("product_status") != "COMPLETED"
            or status.get("coverage_complete") is not True
            or status.get("published_at") is None
            or status.get("finalized_at") is None
        ):
            raise AcceptanceError
        report = _mapping(report_wrapper.get("report"))
        scope = _mapping(report.get("scope"))
        if report_wrapper.get("run_id") != run_id or scope.get("source_run_id") != run_id:
            raise AcceptanceError
        authority_states = _authority_states(report)
        scope_signature = _coverage_scope_signature(report)
        if expected_scope_signature is None:
            expected_scope_signature = scope_signature
        elif scope_signature != expected_scope_signature:
            raise AcceptanceError
        _assert_authority_evidence(
            report,
            manifest,
            selected_gitleaks_present=state["selected_target_present"],
        )

        findings = [_mapping(item) for item in _list(report.get("findings"))]
        category_counts = Counter(_text(item.get("category")) for item in findings)
        if _integer(status.get("finding_count")) != len(findings):
            raise AcceptanceError
        if set(lifecycle_event) != {
            "event_kind",
            "finding_id",
            "lineage_id",
            "previous_state",
            "project_id",
            "reason_codes",
            "resulting_state",
            "run_id",
            "schema_version",
            "submission_sequence",
            "transition_version",
        }:
            raise AcceptanceError
        if (
            lifecycle_event.get("schema_version")
            != "securescan-source-v1-ra1-lifecycle-event-v1"
            or lifecycle_event.get("event_kind") != "TRANSITION"
            or lifecycle_event.get("run_id") != run_id
            or lifecycle_event.get("lineage_id") != lineage_id
            or lifecycle_event.get("project_id") != project
            or lifecycle_event.get("submission_sequence") != sequence
            or lifecycle_event.get("transition_version") != sequence
            or lifecycle_event.get("previous_state")
            != _PREVIOUS_LIFECYCLE_STATES[sequence - 1]
            or lifecycle_event.get("resulting_state") != state.get("expected_lifecycle")
            or lifecycle_event.get("reason_codes")
            != [_LIFECYCLE_REASONS[sequence - 1]]
        ):
            raise AcceptanceError
        selected_id = _sha(lifecycle_event.get("finding_id"))
        selected_ids.append(selected_id)
        report_target_matches = [
            item
            for item in findings
            if item.get("authority") == "gitleaks"
            and _finding_matches(
                item,
                _text(manifest["gitleaks_contract"]["expected_rule_id"]),
                _text(manifest["gitleaks_contract"]["target_path"]),
                start_line=_integer(manifest["gitleaks_contract"]["expected_line"]),
            )
        ]
        target_in_report = len(report_target_matches) == 1 and (
            report_target_matches[0].get("finding_id") == selected_id
        )
        if target_in_report is not state.get("selected_target_present"):
            raise AcceptanceError
        if not state.get("selected_target_present") and report_target_matches:
            raise AcceptanceError
        coverage_counts = _mapping(status.get("coverage_counts"))
        priority_counts = _mapping(status.get("priority_counts"))
        if any(type(value) is not int or value < 0 for value in coverage_counts.values()):
            raise AcceptanceError
        if any(type(value) is not int or value < 0 for value in priority_counts.values()):
            raise AcceptanceError
        observed_coverage_counts = Counter(
            _text(_mapping(value).get("state"))
            for value in _list(report.get("coverage_outcomes"))
        )
        if dict(sorted(observed_coverage_counts.items())) != dict(
            sorted(coverage_counts.items())
        ):
            raise AcceptanceError
        if sum(priority_counts.values()) != len(findings):
            raise AcceptanceError
        if _integer(status.get("gap_count")) != len(_list(report.get("gaps"))):
            raise AcceptanceError
        if sequence == 3:
            gitleaks_outcomes = [
                _mapping(value)
                for value in _list(report.get("coverage_outcomes"))
                if _mapping(value).get("authority") == "gitleaks"
            ]
            if (
                len(gitleaks_outcomes) != 1
                or gitleaks_outcomes[0].get("state") != "COMPLETE"
                or gitleaks_outcomes[0].get("finding_count") != 0
                or gitleaks_outcomes[0].get("gap_count") != 0
                or _integer(status.get("gap_count")) != 0
            ):
                raise AcceptanceError
        summaries.append(
            {
                "authority_states": authority_states,
                "coverage_complete": True,
                "coverage_counts": dict(sorted(coverage_counts.items())),
                "finding_count": len(findings),
                "finding_counts_by_category": dict(sorted(category_counts.items())),
                "gap_count": _integer(status.get("gap_count")),
                "priority_counts": dict(sorted(priority_counts.items())),
                "product_status": "COMPLETED",
                "published": True,
                "finalized": True,
                "run_id": run_id,
                "selected_finding_id": selected_id,
                "selected_lifecycle_reason_code": _LIFECYCLE_REASONS[sequence - 1],
                "selected_lifecycle_state": state["expected_lifecycle"],
                "state_id": state_id,
                "submission_sequence": sequence,
            }
        )
    if lineage_id is None or len(set(selected_ids)) != 1:
        raise AcceptanceError
    return {
        "assertions": {
            "all_five_authorities_successful_for_all_runs": True,
            "comparable_complete_coverage_for_all_runs": True,
            "c_report_omits_selected_finding": True,
            "c_successful_gitleaks_coverage": True,
            "lifecycle_new_existing_resolved_reopened": True,
            "product_core_index_and_lifecycle_complete_for_all_runs": True,
            "syft_is_component_evidence_not_a_finding": True,
        },
        "decision": "PASS",
        "fixture_manifest_sha256": MANIFEST_SHA256,
        "fixture_version": manifest["fixture_version"],
        "lineage_id": lineage_id,
        "project_id": project,
        "runs": summaries,
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "securescan_commit": securescan_commit,
    }


def write_summary(path: Path, summary: dict[str, Any]) -> None:
    value = json.dumps(
        summary,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8") + b"\n"
    lowered = value.lower()
    if any(
        forbidden in lowered
        for forbidden in (
            b"postgresql://",
            b"database_url",
            b"hmac",
            b"stdout",
            b"stderr",
            b"raw_secret",
            b"ghp_",
        )
    ):
        raise AcceptanceError
    try:
        with path.open("xb") as output:
            output.write(value)
    except OSError:
        raise AcceptanceError from None


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("verify", help="verify the committed fixture contract")
    prepare = subparsers.add_parser("prepare", help="materialize four repository states")
    prepare.add_argument("destination", type=Path)
    summarize = subparsers.add_parser("summarize", help="validate and record safe observations")
    summarize.add_argument("observations", type=Path)
    summarize.add_argument("output", type=Path)
    summarize.add_argument("--securescan-commit", required=True)
    summarize.add_argument("--project-id", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "verify":
            manifest = load_and_verify_manifest()
            print(
                json.dumps(
                    {
                        "fixture_manifest_sha256": MANIFEST_SHA256,
                        "fixture_version": manifest["fixture_version"],
                        "status": "PASS",
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                )
            )
        elif arguments.command == "prepare":
            prepare_fixtures(arguments.destination)
            print("Source v1 acceptance fixtures prepared")
        else:
            summary = build_summary(
                arguments.observations,
                securescan_commit=arguments.securescan_commit,
                project_id=arguments.project_id,
            )
            write_summary(arguments.output, summary)
            print("Source v1 acceptance summary recorded")
    except AcceptanceError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
