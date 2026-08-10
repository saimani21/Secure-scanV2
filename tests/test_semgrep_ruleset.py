from __future__ import annotations

import hashlib
import stat
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from securescan.scanners.semgrep import (
    InvalidSemgrepRulesetError,
    TrustedSemgrepRuleset,
    load_baseline_ruleset,
)
from securescan.workspaces import RepositoryWorkspaceManager


def _ruleset(content: bytes = b"rules: []\n") -> TrustedSemgrepRuleset:
    return TrustedSemgrepRuleset(
        ruleset_id="test-rules",
        display_name="Test rules",
        version="1",
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
    )


def test_trusted_semgrep_ruleset_is_immutable_and_hash_validated() -> None:
    ruleset = _ruleset()

    assert ruleset.sha256 == hashlib.sha256(ruleset.content).hexdigest()
    with pytest.raises(FrozenInstanceError):
        ruleset.version = "2"  # type: ignore[misc]


def test_trusted_semgrep_ruleset_rejects_empty_oversized_nul_and_wrong_digest() -> None:
    invalid_values = (
        (b"", hashlib.sha256(b"").hexdigest()),
        (b"x" * (2 * 1024 * 1024 + 1), hashlib.sha256(b"x").hexdigest()),
        (b"rules:\0[]", hashlib.sha256(b"rules:\0[]").hexdigest()),
        (b"rules: []\n", "0" * 64),
    )

    for content, digest in invalid_values:
        with pytest.raises(InvalidSemgrepRulesetError):
            TrustedSemgrepRuleset("test-rules", "Test rules", "1", content, digest)


def test_baseline_ruleset_has_stable_identity_and_three_rules() -> None:
    ruleset = load_baseline_ruleset()
    text = ruleset.content.decode("utf-8")

    assert ruleset.ruleset_id == "securescan-python-baseline-v1"
    assert text.count("\n  - id: securescan.python.") == 3
    assert "securescan.python.dangerous-eval" in text
    assert "securescan.python.subprocess-shell-true" in text
    assert "securescan.python.unsafe-yaml-load" in text
    assert "autofix:" not in text


def test_ruleset_materialization_is_atomic_read_only_and_outside_source(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "app.py").write_text("print('safe')\n", encoding="utf-8")
    manager = RepositoryWorkspaceManager(tmp_path / "workspaces")
    workspace = manager.prepare_repository(repository)
    original_digest = workspace.manifest.content_digest
    try:
        rules_path = _ruleset().materialize(workspace.output_directory)

        assert rules_path.parent == workspace.output_directory
        assert not (workspace.source_directory / rules_path.name).exists()
        assert stat.S_IMODE(rules_path.stat().st_mode) == 0o444
        assert workspace.manifest.content_digest == original_digest
        with pytest.raises(InvalidSemgrepRulesetError):
            _ruleset().materialize(workspace.output_directory)
    finally:
        manager.cleanup_workspace(workspace)
