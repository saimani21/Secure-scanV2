from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/verify-gitleaks-functionality-sentinel.py"
GITLEAKS_BINARY = os.environ.get("SECURESCAN_GITLEAKS_BINARY")


@pytest.mark.skipif(
    GITLEAKS_BINARY is None,
    reason="SECURESCAN_GITLEAKS_BINARY is not set to the trusted pinned binary",
)
def test_exact_pinned_binary_functionality_sentinel() -> None:
    assert GITLEAKS_BINARY is not None
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--gitleaks",
            GITLEAKS_BINARY,
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        stdin=subprocess.DEVNULL,
        text=True,
        timeout=320,
    )

    assert result.returncode == 0
    assert result.stdout == "PINNED_BINARY_FUNCTIONALITY_SENTINEL_PASS\n"
    assert result.stderr == ""


def test_sentinel_is_opt_in_and_does_not_store_a_pat_shaped_value() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert "ghp_" in source
    assert not any(
        part.startswith("ghp_") and len(part) >= 40
        for part in source.replace('"', " ").replace("'", " ").split()
    )
    assert "TemporaryDirectory" in source
    assert 'Path("/tmp")' in source
