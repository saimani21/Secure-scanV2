from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from unified_evidence_fixtures import (
    SEMGREP_ARTIFACT_BYTES,
    semgrep_native,
    semgrep_tool_execution,
)

from securescan.evidence import EvidenceAuthority, adapt_semgrep_assessment
from securescan.scanners.semgrep import load_source_ruleset

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/semgrep/rules/javascript-typescript"
RULES = ROOT / "src/securescan/scanners/semgrep/rules/securescan-javascript-typescript-v1.yml"
EXPECTED_RULES = {
    "child-process-exec": "securescan.javascript.child-process-exec",
    "child-process-shell": "securescan.javascript.child-process-shell",
    "dynamic-eval": "securescan.javascript.dynamic-eval",
    "request-derived-path": "securescan.javascript.request-derived-path",
    "request-derived-redirect": "securescan.javascript.request-derived-redirect",
    "sql-template-query": "securescan.javascript.sql-template-query",
}


def _semgrep_core() -> Path:
    launcher = shutil.which("semgrep")
    assert launcher is not None
    candidates = tuple(
        Path(launcher)
        .resolve()
        .parents[1]
        .glob("lib/python*/site-packages/semgrep/bin/semgrep-core")
    )
    assert len(candidates) == 1 and candidates[0].is_file()
    return candidates[0]


def _targets() -> tuple[Path, ...]:
    return tuple(sorted(path for path in FIXTURES.glob("*/*") if path.is_file()))


def _target_document(paths: tuple[Path, ...]) -> list[object]:
    targets = []
    for path in paths:
        analyzer = "typescript" if path.suffix in {".ts", ".tsx"} else "javascript"
        absolute = str(path.resolve())
        targets.append(
            [
                "CodeTarget",
                {
                    "analyzer": analyzer,
                    "path": {"fpath": absolute, "ppath": absolute},
                    "products": ["sast"],
                },
            ]
        )
    return ["Targets", targets]


def test_js_ts_rules_have_complete_positive_safe_and_near_miss_corpus() -> None:
    assert tuple(sorted(path.name for path in FIXTURES.iterdir())) == tuple(sorted(EXPECTED_RULES))
    assert len(_targets()) == 18
    for family in EXPECTED_RULES:
        directory = FIXTURES / family
        assert {path.stem for path in directory.iterdir()} == {
            "near_miss",
            "safe",
            "vulnerable",
        }


def test_js_ts_rule_pack_matches_only_bounded_vulnerable_examples(
    tmp_path: Path,
) -> None:
    paths = _targets()
    target_file = tmp_path / "targets.json"
    target_file.write_text(
        json.dumps(_target_document(paths), separators=(",", ":")),
        encoding="utf-8",
    )
    completed = subprocess.run(
        [
            str(_semgrep_core()),
            "-json",
            "-j",
            "1",
            "-rules",
            str(RULES),
            "-targets",
            str(target_file),
        ],
        cwd=ROOT,
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
    document = json.loads(completed.stdout.splitlines()[-1])
    assert document["errors"] == []
    assert len(document["paths"]["scanned"]) == 18
    assert len(document["results"]) == 6
    assert {
        (Path(result["path"]).parent.name, Path(result["path"]).stem, result["check_id"])
        for result in document["results"]
    } == {(family, "vulnerable", rule_id) for family, rule_id in EXPECTED_RULES.items()}


def test_v3_combined_ruleset_preserves_python_v2_and_adds_six_js_ts_rules() -> None:
    ruleset = load_source_ruleset()
    text = ruleset.content.decode("utf-8")

    assert ruleset.ruleset_id == "securescan-source-baseline-v3"
    assert ruleset.version == "3"
    assert text.count("\n  - id: securescan.python.") == 17
    assert text.count("\n  - id: securescan.javascript.") == 6
    assert "autofix:" not in text
    assert "\n    fix:" not in text


def test_js_ts_finding_reuses_canonical_semgrep_s4_identity() -> None:
    first = semgrep_native(
        rule_id="securescan.javascript.dynamic-eval",
        path="frontend/src/app.tsx",
        line=11,
    )
    second = semgrep_native(
        rule_id="securescan.javascript.dynamic-eval",
        path="frontend/src/app.tsx",
        line=11,
    )

    def fragment(values):
        assessment, context, projection, binding = values
        return adapt_semgrep_assessment(
            assessment,
            context=context,
            projection=projection,
            binding=binding,
            tool_execution=semgrep_tool_execution(assessment),
            sanitized_artifact_bytes=SEMGREP_ARTIFACT_BYTES,
        )

    first_fragment = fragment(first)
    second_fragment = fragment(second)
    finding = first_fragment.findings[0]
    evidence = first_fragment.evidence[0]

    assert finding.authority is EvidenceAuthority.SEMGREP
    assert finding.finding_id == second_fragment.findings[0].finding_id
    assert finding.native_finding_identity == evidence.native_identity
    assert evidence.payload.rule_id == "securescan.javascript.dynamic-eval"
    assert evidence.locations[0].path == "frontend/src/app.tsx"
    assert finding.locations == evidence.locations
