from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_EXAMPLE = _ROOT / "examples" / "github-actions" / "securescan.yml"
_GUIDE = _ROOT / "docs" / "source-v1.1d-cli-sarif-ci.md"


def _text() -> str:
    return _EXAMPLE.read_text(encoding="utf-8")


def test_example_is_inert_and_all_actions_use_immutable_shas() -> None:
    assert _EXAMPLE.is_file()
    assert ".github/workflows" not in _EXAMPLE.as_posix()
    references = re.findall(r"^\s*uses:\s*([^\s#]+)", _text(), flags=re.MULTILINE)
    assert references
    assert all(re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", item) for item in references)
    assert references == [
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1",
        "actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f",
        "actions/download-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        "github/codeql-action/upload-sarif@2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2",
    ]
    assert not re.search(r"uses:\s*[^\n]+@(main|master|v\d+)\s*(?:#|$)", _text())


def test_jobs_have_exact_permission_and_untrusted_pr_boundaries() -> None:
    text = _text()
    scan, upload = text.split("\n  upload-sarif:\n", 1)
    assert "permissions:\n      contents: read\n" in scan
    assert "security-events:" not in scan
    assert "permissions:\n      contents: read\n      security-events: write\n" in upload
    assert "actions/checkout" not in upload
    assert "pull_request_target" not in text
    assert "github.event.pull_request.head.repo.full_name == github.repository" in upload


def test_example_waits_exports_to_runner_temp_and_always_cleans_up() -> None:
    text = _text()
    assert 'securescan scan "$GITHUB_WORKSPACE"' in text
    assert "--wait --json" in text
    assert '--output "$RUNNER_TEMP/securescan.sarif"' in text
    assert "path: ${{ runner.temp }}/securescan.sarif" in text
    assert "if: always()" in text
    assert "securescan system down" in text
    assert "docker compose down -v" not in text


def test_example_generates_private_credentials_without_committed_values() -> None:
    text = _text()
    assert text.count("openssl rand -hex 32") == 2
    assert "umask 077" in text
    assert "SECURESCAN_OPERATOR_PROFILE: ${{ runner.temp }}" in text
    assert "${{ secrets." not in text
    for forbidden in ("replace-me", "development-only-key", "password123"):
        assert forbidden not in text
    assert "cache: \"\"" in text


def test_preprovisioned_prerequisites_and_authority_are_documented() -> None:
    workflow = _text()
    guide = _GUIDE.read_text(encoding="utf-8")
    assert "pre-provisioned runner" in workflow
    assert "install '.[postgres]'" in workflow
    assert "securescan doctor" in workflow
    for prerequisite in (
        "Docker",
        "PostgreSQL",
        "Enry",
        "Gitleaks",
        "Syft",
        "Checkov",
        "Semgrep",
    ):
        assert prerequisite in guide
    normalized = " ".join(guide.split())
    assert "SecureScan canonical findings remain authoritative" in normalized
    assert "dismissal state never flows" in normalized
