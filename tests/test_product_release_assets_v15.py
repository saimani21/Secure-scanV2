from __future__ import annotations

from pathlib import Path

from securescan.runtime_assets import runtime_asset_path

_ROOT = Path(__file__).resolve().parents[1]


def test_v15_github_workflow_preserves_failures_and_uses_current_sarif_actions() -> None:
    path = _ROOT / "examples" / "github-actions" / "securescan-v15.yml"
    text = path.read_text(encoding="utf-8")
    assert "permissions:\n  contents: read\n  security-events: write\n" in text
    assert "actions/checkout@v6" in text
    assert "github/codeql-action/upload-sarif@v4" in text
    assert "actions/upload-artifact@v6" in text
    assert "set +e" in text
    assert "gate_exit=$?" in text
    assert "Preserve SecureScan decision" in text
    assert "secrets." not in text
    assert ".github/workflows" not in path.as_posix()


def test_runtime_assets_resolve_from_source_tree() -> None:
    assert runtime_asset_path("alembic.ini") == _ROOT / "alembic.ini"
    assert runtime_asset_path("compose.yaml") == _ROOT / "compose.yaml"
