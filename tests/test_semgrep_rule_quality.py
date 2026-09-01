from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from collections import Counter
from pathlib import Path

import pytest

from securescan.scanners.semgrep import load_baseline_ruleset, parse_semgrep_output
from securescan.scanners.semgrep.sanitizer import build_sanitized_semgrep_evidence
from securescan.workspaces.models import (
    RepositoryManifest,
    RepositoryManifestEntry,
    repository_content_digest,
)

ROOT = Path(__file__).parent.parent
FIXTURE_ROOT = Path("tests/fixtures/semgrep/rules/python")
EXPECTED_RULES = {
    "dangerous-eval": ("securescan.python.dangerous-eval", "ERROR", "CWE-95"),
    "dangerous-exec": ("securescan.python.dangerous-exec", "ERROR", "CWE-95"),
    "os-system": ("securescan.python.os-system", "ERROR", "CWE-78"),
    "os-popen": ("securescan.python.os-popen", "ERROR", "CWE-78"),
    "subprocess-shell-true": (
        "securescan.python.subprocess-shell-true",
        "ERROR",
        "CWE-78",
    ),
    "unsafe-pickle-load": (
        "securescan.python.unsafe-pickle-load",
        "ERROR",
        "CWE-502",
    ),
    "unsafe-yaml-load": (
        "securescan.python.unsafe-yaml-load",
        "ERROR",
        "CWE-502",
    ),
    "requests-verify-false": (
        "securescan.python.requests-verify-false",
        "WARNING",
        "CWE-295",
    ),
    "requests-session-verify-false": (
        "securescan.python.requests-session-verify-false",
        "WARNING",
        "CWE-295",
    ),
    "ssl-unverified-context": (
        "securescan.python.ssl-unverified-context",
        "WARNING",
        "CWE-295",
    ),
    "paramiko-autoaddpolicy": (
        "securescan.python.paramiko-autoaddpolicy",
        "WARNING",
        "CWE-295",
    ),
    "insecure-tempfile-mktemp": (
        "securescan.python.insecure-tempfile-mktemp",
        "WARNING",
        "CWE-377",
    ),
    "flask-debug-enabled": (
        "securescan.python.flask-debug-enabled",
        "WARNING",
        "CWE-489",
    ),
    "jinja-autoescape-disabled": (
        "securescan.python.jinja-autoescape-disabled",
        "WARNING",
        "CWE-79",
    ),
    "sql-fstring-execute": (
        "securescan.python.sql-fstring-execute",
        "ERROR",
        "CWE-89",
    ),
    "jwt-signature-verification-disabled": (
        "securescan.python.jwt-signature-verification-disabled",
        "ERROR",
        "CWE-347",
    ),
    "lxml-resolve-entities": (
        "securescan.python.lxml-resolve-entities",
        "ERROR",
        "CWE-611",
    ),
}
EXPECTED_RESULT_COUNTS = {
    fixture_name: 13 if fixture_name == "unsafe-yaml-load" else 1
    for fixture_name in EXPECTED_RULES
}


def _fixture_paths() -> tuple[Path, ...]:
    return tuple(
        sorted(
            (ROOT / FIXTURE_ROOT).glob("*/*.py"),
            key=lambda path: path.relative_to(ROOT).as_posix(),
        )
    )


def _manifest(paths: tuple[Path, ...]) -> RepositoryManifest:
    entries = tuple(
        RepositoryManifestEntry(
            relative_path=path.relative_to(ROOT).as_posix(),
            size_bytes=len(content := path.read_bytes()),
            sha256=hashlib.sha256(content).hexdigest(),
        )
        for path in paths
    )
    return RepositoryManifest(
        entries=entries,
        file_count=len(entries),
        total_bytes=sum(entry.size_bytes for entry in entries),
        content_digest=repository_content_digest(entries),
    )


def _run_semgrep(tmp_path: Path, paths: tuple[Path, ...]) -> bytes:
    executable = shutil.which("semgrep")
    if executable is None:
        pytest.skip("local Semgrep CLI is unavailable")
    environment = os.environ.copy()
    environment["HOME"] = str(tmp_path)
    environment["SEMGREP_SETTINGS_FILE"] = str(tmp_path / "settings.yml")
    environment["SEMGREP_LOG_FILE"] = str(tmp_path / "semgrep.log")
    command = [
        executable,
        "scan",
        "--json",
        "--metrics=off",
        "--disable-version-check",
        "--quiet",
        "--no-git-ignore",
        "--jobs=1",
        "--no-rewrite-rule-ids",
        "--config=src/securescan/scanners/semgrep/rules/securescan-python-baseline-v2.yml",
        *(path.relative_to(ROOT).as_posix() for path in paths),
    ]
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        capture_output=True,
        check=False,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    return result.stdout


def test_every_rule_has_dedicated_positive_safe_and_near_miss_fixture() -> None:
    directories = tuple(
        sorted(
            path.name
            for path in (ROOT / FIXTURE_ROOT).iterdir()
            if path.is_dir()
        )
    )

    assert directories == tuple(sorted(EXPECTED_RULES))
    for directory in directories:
        assert {
            path.name
            for path in (ROOT / FIXTURE_ROOT / directory).iterdir()
            if path.is_file() and path.suffix == ".py"
        } == {"near_miss.py", "safe.py", "vulnerable.py"}


def test_curated_rules_match_only_expected_vulnerable_fixtures(
    tmp_path: Path,
) -> None:
    paths = _fixture_paths()
    raw_output = _run_semgrep(tmp_path, paths)
    document = json.loads(raw_output)

    assert document["errors"] == []
    assert len(document["paths"]["scanned"]) == 51
    assert len(document["results"]) == sum(EXPECTED_RESULT_COUNTS.values()) == 29
    seen: Counter[str] = Counter()
    for result in document["results"]:
        path = Path(result["path"])
        fixture_name = path.parent.name
        expected_id, expected_severity, expected_cwe = EXPECTED_RULES[fixture_name]
        assert path.name == "vulnerable.py"
        assert result["check_id"] == expected_id
        assert result["extra"]["severity"] == expected_severity
        assert result["extra"]["metadata"] == {"cwe": [expected_cwe]}
        seen[fixture_name] += 1
    assert seen == Counter(EXPECTED_RESULT_COUNTS)

    parsed = parse_semgrep_output(
        raw_output,
        _manifest(paths),
        scanner_id="semgrep-ce",
        scanner_version=document["version"],
    )
    assert len(parsed.findings) == 29
    assert parsed.analysis_gaps == ()
    assert {finding.rule_id for finding in parsed.findings} == {
        definition[0] for definition in EXPECTED_RULES.values()
    }
    evidence = json.loads(
        build_sanitized_semgrep_evidence(
            parsed,
            scanner_id="semgrep-ce",
            ruleset=load_baseline_ruleset(),
        )
    )
    assert len(evidence["results"]) == 29
    assert evidence["summary"]["analysis_gaps"] == 0


def test_ruleset_has_only_supported_metadata_and_no_autofix() -> None:
    text = load_baseline_ruleset().content.decode("utf-8")

    assert text.count("\n  - id: securescan.python.") == 17
    assert text.count("\n      cwe: [CWE-") == 17
    assert text.count("\n    severity: ERROR") == 10
    assert text.count("\n    severity: WARNING") == 7
    assert "autofix:" not in text
    assert "\n    fix:" not in text
    assert "p/" not in text
