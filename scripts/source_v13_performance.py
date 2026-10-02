#!/usr/bin/env python3
"""Reproducible, disposable Source v1.3 performance characterization.

This source-tree validation harness never executes scanners or calls external
services. Repository-shape measurements use the real intake, inventory,
profiling, coverage and planning code with a deterministic in-process Enry
stand-in. Product Core measurements use the real SQLite persistence, CAS,
published-S4 verification, indexing, lifecycle, Product View, Security Delta,
policy and CycloneDX paths over the fixed controlled S4 test report.
"""

from __future__ import annotations

import argparse
import json
import platform
import resource
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from uuid import UUID

import pytest

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from test_source_orchestration_s6b import _RUN_ID, _Environment  # noqa: E402
from test_source_product_core_pc1 import (  # noqa: E402
    _INDEXED_AT,
    _LINEAGE_IDS,
    _publish_environment,
)
from test_source_product_core_pc2 import _add_run  # noqa: E402
from test_trusted_baseline_delta_v12e import (  # noqa: E402
    _BASELINE_RUN,
    _CANDIDATE_RUNS,
    _mark_finalized,
    _report_loader,
)

from securescan.persistence.database import AnalysisRunRow, TargetRow  # noqa: E402
from securescan.product_core import (  # noqa: E402
    SourceFindingIndexService,
    SourceFindingLifecycleService,
    SourcePolicyService,
    SourceSecurityDeltaService,
    SourceTrustedBaselineService,
)
from securescan.product_core.interoperability import _cyclonedx_document  # noqa: E402
from securescan.product_core.product_view import (  # noqa: E402
    SourceFindingProductViewService,
)
from securescan.product_core.verified_read import VerifiedPublishedRun  # noqa: E402
from securescan.source import (  # noqa: E402
    AnalysisCapability,
    CapabilitySupportRule,
    EnryBatchResult,
    EnryClassification,
    EnryFileInput,
    LanguageSupportRule,
    SourcePlanningPolicy,
    SourceSupportPolicy,
    SourceSupportState,
    TrustedEnryHelper,
    TrustedSourceAnalyzer,
    TrustedSourceAnalyzerRegistry,
    assess_repository_language_support,
    build_repository_inventory,
    build_repository_profile,
    build_source_analysis_plan,
    detect_repository_components,
    enrich_repository_inventory,
    profile_repository_languages,
)
from securescan.workspaces import RepositoryWorkspaceManager  # noqa: E402

_HELPER_DIGEST = "e" * 64


@dataclass(frozen=True, slots=True)
class _Shape:
    name: str
    file_count: int
    pathological: bool = False


class _DeterministicEnry:
    configuration = TrustedEnryHelper(
        helper_path=Path("/validation/securescan-enry-helper"),
        expected_sha256=_HELPER_DIGEST,
        maximum_files_per_batch=4096,
    )

    def classify(self, files: tuple[EnryFileInput, ...]) -> EnryBatchResult:
        classifications = []
        for item in files:
            suffix = Path(item.relative_path).suffix
            language = {
                ".js": "JavaScript",
                ".jsx": "JavaScript",
                ".py": "Python",
                ".ts": "TypeScript",
                ".tsx": "TypeScript",
            }.get(suffix)
            classifications.append(
                EnryClassification(
                    relative_path=item.relative_path,
                    language=language,
                    candidate_languages=(language,) if language else (),
                    is_binary=False,
                    is_vendor=False,
                    is_generated=False,
                    is_test=False,
                    is_configuration=False,
                    is_documentation=False,
                    is_dot_file=False,
                    is_image=False,
                )
            )
        return EnryBatchResult(
            classifications=tuple(classifications),
            helper_sha256=_HELPER_DIGEST,
            helper_version="v1.3-performance-stand-in",
            enry_version="deterministic",
            duration_ms=0,
        )


def _measure[T](operation: Callable[[], T]) -> tuple[T, float]:
    started = time.perf_counter()
    value = operation()
    return value, time.perf_counter() - started


def _write_repository(root: Path, shape: _Shape) -> None:
    suffixes = (".js", ".py", ".ts", ".jsx", ".tsx")
    normal = b"export const controlled = true;\n"
    long_line = b"const controlled = '" + (b"x" * (64 * 1024)) + b"';\n"
    for index in range(shape.file_count):
        if shape.pathological:
            directories = [f"depth-{level:02d}" for level in range(16)]
            directories.append(f"bucket-{index // 250:05d}")
        else:
            directories = [f"bucket-{index // 250:05d}"]
        path = root.joinpath(*directories, f"file-{index:06d}{suffixes[index % 5]}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(long_line if shape.pathological and index % 100 == 0 else normal)


def _source_policy() -> SourceSupportPolicy:
    return SourceSupportPolicy(
        language_rules=(
            LanguageSupportRule("JavaScript", SourceSupportState.SCANNABLE),
            LanguageSupportRule("Python", SourceSupportState.SCANNABLE),
            LanguageSupportRule("TypeScript", SourceSupportState.SCANNABLE),
        ),
        capability_rules=(
            CapabilitySupportRule(
                AnalysisCapability.SOURCE_SAST,
                SourceSupportState.SCANNABLE,
            ),
        ),
    )


def _repository_measurement(base: Path, shape: _Shape) -> dict[str, object]:
    source = base / f"source-{shape.name}"
    managed = base / f"managed-{shape.name}"
    source.mkdir()
    _write_repository(source, shape)
    manager = RepositoryWorkspaceManager(managed)
    workspace, intake_seconds = _measure(lambda: manager.prepare_repository(source))
    try:
        inventory, inventory_seconds = _measure(lambda: build_repository_inventory(workspace))

        def build_profile():
            languages = profile_repository_languages(
                workspace,
                inventory,
                _DeterministicEnry(),
            )
            componentized = detect_repository_components(
                enrich_repository_inventory(inventory, languages)
            )
            policy = _source_policy()
            assessment = assess_repository_language_support(componentized, policy)
            return build_repository_profile(componentized, assessment, policy)

        profile, profiling_seconds = _measure(build_profile)
        registry = TrustedSourceAnalyzerRegistry(
            analyzers=(
                TrustedSourceAnalyzer(
                    "semgrep-source-v1",
                    (AnalysisCapability.SOURCE_SAST,),
                    True,
                ),
            )
        )
        plan, planning_seconds = _measure(
            lambda: build_source_analysis_plan(
                profile,
                registry,
                SourcePlanningPolicy(),
            )
        )
        return {
            "artifact_storage_bytes": workspace.manifest.total_bytes,
            "file_count": workspace.manifest.file_count,
            "intake_seconds": intake_seconds,
            "inventory_seconds": inventory_seconds,
            "planning_seconds": planning_seconds,
            "profiling_seconds": profiling_seconds,
            "runnable_plan_entries": plan.run_count,
            "shape": shape.name,
        }
    finally:
        manager.cleanup_workspace(workspace)


def _directory_bytes(root: Path) -> int:
    return sum(path.stat().st_size for path in root.rglob("*") if path.is_file())


def _product_core_measurement(base: Path) -> dict[str, object]:
    environment = _Environment(base / "product-core")
    monkeypatch = pytest.MonkeyPatch()
    try:
        _publish_environment(environment)
        index = SourceFindingIndexService(
            environment.factory,
            environment.store,
            clock=lambda: _INDEXED_AT,
            lineage_id_factory=lambda: _LINEAGE_IDS[0],
        )
        with environment.factory() as session:
            run = session.get(AnalysisRunRow, str(_RUN_ID))
            if run is None:
                raise RuntimeError("controlled run was not created")
            target = session.get(TargetRow, run.target_id)
            if target is None:
                raise RuntimeError("controlled target was not created")
            project_id = target.project_id
        lineage = index.create_lineage(project_id=project_id)
        index.attach_published_run(
            lineage_id=lineage.lineage_id,
            run_id=str(_RUN_ID),
        )
        _, indexing_seconds = _measure(
            lambda: index.index_attached_run(
                lineage_id=lineage.lineage_id,
                run_id=str(_RUN_ID),
            )
        )
        lifecycle = SourceFindingLifecycleService(
            environment.factory,
            environment.store,
            clock=lambda: _INDEXED_AT,
        )
        report = lifecycle._trusted_report(str(_RUN_ID))
        reports = {str(_RUN_ID): report}
        context = (environment, index, lifecycle, lineage, reports)
        lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=str(_RUN_ID))
        _mark_finalized(context, str(_RUN_ID))

        product_view = SourceFindingProductViewService(
            environment.factory,
            environment.store,
        )
        page, product_view_seconds = _measure(
            lambda: product_view.list_for_run(
                project_id=project_id,
                lineage_id=lineage.lineage_id,
                run_id=str(_RUN_ID),
            )
        )

        baseline_report = _add_run(
            context,
            monkeypatch,
            _BASELINE_RUN,
            present=False,
            ordinal=2,
        )
        lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=_BASELINE_RUN)
        _mark_finalized(context, _BASELINE_RUN)
        candidate_run = _CANDIDATE_RUNS[0]
        _add_run(
            context,
            monkeypatch,
            candidate_run,
            present=True,
            ordinal=3,
        )
        lifecycle.evaluate(lineage_id=lineage.lineage_id, run_id=candidate_run)
        _mark_finalized(context, candidate_run)
        baselines = SourceTrustedBaselineService(
            environment.factory,
            environment.store,
            clock=lambda: _INDEXED_AT + timedelta(days=10),
            baseline_id_factory=lambda: UUID("66666666-6666-4666-8666-666666666661"),
        )
        delta = SourceSecurityDeltaService(environment.factory, environment.store)
        loader = _report_loader(reports)
        monkeypatch.setattr(baselines._index, "_rebuild_trusted_report", loader)
        monkeypatch.setattr(delta._index, "_rebuild_trusted_report", loader)
        baselines.promote(
            project_id=project_id,
            lineage_id=lineage.lineage_id,
            run_id=_BASELINE_RUN,
            expected_revision=0,
        )
        delta_result, delta_seconds = _measure(
            lambda: delta.evaluate(
                project_id=project_id,
                lineage_id=lineage.lineage_id,
                candidate_run_id=candidate_run,
            )
        )
        policy = SourcePolicyService(
            environment.factory,
            environment.store,
            clock=lambda: _INDEXED_AT + timedelta(days=11),
        )
        monkeypatch.setattr(policy._delta._index, "_rebuild_trusted_report", loader)
        monkeypatch.setattr(policy._lifecycle, "_trusted_report", loader)
        policy_result, policy_seconds = _measure(
            lambda: policy.evaluate(
                project_id=project_id,
                lineage_id=lineage.lineage_id,
                candidate_run_id=candidate_run,
            )
        )

        verified = VerifiedPublishedRun(
            run_id=_BASELINE_RUN,
            target_id="00000000-0000-4000-8000-00000000b001",
            project_id=project_id,
            lineage_id=lineage.lineage_id,
            report_artifact_sha256="a" * 64,
            report_artifact_size_bytes=len(baseline_report.canonical_json()),
            report=baseline_report,
        )
        cyclonedx, cyclonedx_seconds = _measure(lambda: _cyclonedx_document(verified))
        return {
            "artifact_storage_bytes": _directory_bytes(base / "product-core" / "artifacts"),
            "cyclonedx_bytes": len(
                json.dumps(cyclonedx, sort_keys=True, separators=(",", ":")).encode()
            ),
            "cyclonedx_export_seconds": cyclonedx_seconds,
            "database_bytes": (base / "product-core" / "s6b.db").stat().st_size,
            "delta_finding_count": len(delta_result.findings),
            "policy_evaluation_seconds": policy_seconds,
            "policy_result": policy_result.result.value,
            "product_core_indexing_seconds": indexing_seconds,
            "product_view_finding_count": page.total,
            "product_view_seconds": product_view_seconds,
            "security_delta_seconds": delta_seconds,
            "security_delta_status": delta_result.comparison_status.value,
        }
    finally:
        monkeypatch.undo()
        environment.close()


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--include-large",
        action="store_true",
        help="include the 50,000-file case",
    )
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    shapes = [
        _Shape("small", 1_000),
        _Shape("medium", 10_000),
        _Shape("pathological", 1_000, pathological=True),
    ]
    if arguments.include_large:
        shapes.insert(2, _Shape("large", 50_000))
    with tempfile.TemporaryDirectory(prefix="securescan-v13-performance-") as value:
        base = Path(value)
        repositories = [_repository_measurement(base, shape) for shape in shapes]
        product_core = _product_core_measurement(base)
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    result = {
        "environment": {
            "machine": platform.machine(),
            "platform": platform.platform(),
            "python": platform.python_version(),
        },
        "limitations": [
            "scanner execution is excluded",
            "language classification uses a deterministic in-process stand-in",
            "Product Core uses the fixed controlled S4 report and SQLite",
            "ru_maxrss is a whole-process high-water mark",
        ],
        "peak_process_rss_kib": rss,
        "product_core": product_core,
        "repository_shapes": repositories,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
