"""Hostile process-boundary acceptance cases for V1.2I-B."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from securescan.source.enry_client import (
    EnryClient,
    EnryHelperExecutionError,
    EnryHelperIntegrityError,
    EnryHelperOutputLimitError,
    EnryHelperTimeoutError,
    TrustedEnryHelper,
)
from securescan.source.enry_protocol import EnryFileInput, EnryProtocolError

_SECRET = "v12i-helper-stderr-secret-sentinel"


@pytest.mark.parametrize(
    ("body", "error_type", "timeout_seconds", "stdout_limit"),
    [
        ("import os; os.kill(os.getpid(), 9)", EnryHelperExecutionError, 2, 1024),
        (
            "import os; os.write(1, b'{\\\"ok\\\":'); os.kill(os.getpid(), 9)",
            EnryHelperExecutionError,
            2,
            1024,
        ),
        ("import os; os.close(0); os._exit(3)", EnryHelperExecutionError, 2, 1024),
        ("import time; time.sleep(2)", EnryHelperTimeoutError, 0.1, 1024),
        ("import os; os.write(1, b'x' * 4096)", EnryHelperOutputLimitError, 2, 32),
        ("import os; os.write(1, b'{\\\"ok\\\":')", EnryProtocolError, 2, 1024),
    ],
    ids=(
        "killed-before-response",
        "killed-mid-response",
        "stdin-closed-early",
        "timeout",
        "oversized-response",
        "truncated-response",
    ),
)
def test_real_helper_failure_never_produces_classifications_or_leaks_stderr(
    tmp_path: Path,
    body: str,
    error_type: type[Exception],
    timeout_seconds: float,
    stdout_limit: int,
) -> None:
    helper = tmp_path / "hostile-enry-helper"
    script = (
        "#!/usr/bin/python3\n"
        "import os\n"
        + (f"os.write(2, {_SECRET!r}.encode())\n" if error_type is not EnryProtocolError else "")
        + f"{body}\n"
    ).encode("utf-8")
    helper.write_bytes(script)
    helper.chmod(0o700)
    configuration = TrustedEnryHelper(
        helper_path=helper,
        expected_sha256=hashlib.sha256(script).hexdigest(),
        timeout_seconds=timeout_seconds,
        stdout_limit_bytes=stdout_limit,
    )

    with pytest.raises(error_type) as raised:
        EnryClient(configuration).classify(
            (EnryFileInput("src/app.py", b"print('private source')\n"),)
        )

    assert _SECRET not in str(raised.value)
    assert str(helper) not in str(raised.value)
    assert "private source" not in str(raised.value)


@pytest.mark.parametrize("replacement", ["symlink", "directory"])
def test_real_helper_substitution_during_execution_rejects_result(
    tmp_path: Path,
    replacement: str,
) -> None:
    helper = tmp_path / "hostile-enry-helper"
    target = tmp_path / "replacement-target"
    target.write_bytes(b"untrusted replacement")
    action = f"path.symlink_to({str(target)!r})" if replacement == "symlink" else "path.mkdir()"
    script = (
        "#!/usr/bin/python3\n"
        "from pathlib import Path\n"
        "path = Path(__file__)\n"
        "path.unlink()\n"
        f"{action}\n"
        "print('{}')\n"
    ).encode()
    helper.write_bytes(script)
    helper.chmod(0o700)
    configuration = TrustedEnryHelper(
        helper_path=helper,
        expected_sha256=hashlib.sha256(script).hexdigest(),
    )

    with pytest.raises(EnryHelperIntegrityError) as raised:
        EnryClient(configuration).classify((EnryFileInput("src/app.py", b"safe"),))

    assert str(helper) not in str(raised.value)
    assert str(target) not in str(raised.value)
