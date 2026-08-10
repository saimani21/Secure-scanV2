from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

import pytest

from securescan.execution import (
    CancellableProcessExecutor,
    CancellableProcessRequest,
    InvalidCancellableProcessRequestError,
)


def _request(
    script: Path,
    *arguments: str,
    timeout_seconds: float = 2,
    stdout_limit_bytes: int = 4096,
    stderr_limit_bytes: int = 4096,
    stdin_data: bytes | None = None,
) -> CancellableProcessRequest:
    return CancellableProcessRequest(
        argv=(sys.executable, str(script), *arguments),
        cwd=script.parent,
        environment=None,
        timeout_seconds=timeout_seconds,
        stdout_limit_bytes=stdout_limit_bytes,
        stderr_limit_bytes=stderr_limit_bytes,
        stdin_data=stdin_data,
    )


def _pid_is_running(pid: int) -> bool:
    proc_stat = Path(f"/proc/{pid}/stat")
    if proc_stat.exists():
        fields = proc_stat.read_text().split()
        return len(fields) > 2 and fields[2] != "Z"
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def test_process_executor_captures_stdout_stderr_and_exit_code(
    tmp_path: Path,
) -> None:
    script = tmp_path / "capture.py"
    script.write_text(
        "import sys\n"
        "sys.stdout.buffer.write(b'captured-out')\n"
        "sys.stderr.buffer.write(b'captured-err')\n"
        "raise SystemExit(7)\n"
    )

    with CancellableProcessExecutor().start(_request(script)) as handle:
        result = handle.wait(timeout_seconds=2)

    assert result is not None
    assert result.return_code == 7
    assert result.stdout == b"captured-out"
    assert result.stderr == b"captured-err"
    assert result.timed_out is False
    assert result.output_limit_exceeded is False
    assert result.termination_requested is False
    assert result.force_killed is False


def test_process_executor_does_not_invoke_a_shell(tmp_path: Path) -> None:
    script = tmp_path / "literal.py"
    side_effect = tmp_path / "shell-side-effect"
    argument = f"literal; touch {side_effect}"
    script.write_text("import sys\nsys.stdout.buffer.write(sys.argv[1].encode())\n")

    with CancellableProcessExecutor().start(_request(script, argument)) as handle:
        result = handle.wait(timeout_seconds=2)

    assert result is not None
    assert result.stdout.decode() == argument
    assert not side_effect.exists()


def test_process_timeout_requests_termination(tmp_path: Path) -> None:
    script = tmp_path / "timeout.py"
    script.write_text("import time\ntime.sleep(30)\n")

    with CancellableProcessExecutor().start(_request(script, timeout_seconds=0.05)) as handle:
        result = handle.wait(timeout_seconds=2)
        assert result is not None
        assert handle.poll() is result

    assert result.timed_out is True
    assert result.termination_requested is True
    assert result.force_killed is False
    assert 0 <= result.duration_ms < 2000


def test_output_limit_is_bounded_and_stops_process(tmp_path: Path) -> None:
    script = tmp_path / "output_flood.py"
    script.write_text(
        "import sys\n"
        "while True:\n"
        "    sys.stdout.buffer.write(b'x' * 4096)\n"
        "    sys.stdout.buffer.flush()\n"
    )

    with CancellableProcessExecutor().start(_request(script, stdout_limit_bytes=128)) as handle:
        result = handle.wait(timeout_seconds=2)

    assert result is not None
    assert result.output_limit_exceeded is True
    assert result.termination_requested is True
    assert len(result.stdout) == 128
    assert len(result.stderr) <= 4096


def test_terminate_stops_process_group(tmp_path: Path) -> None:
    script = tmp_path / "process_group.py"
    child_pid_file = tmp_path / "child.pid"
    script.write_text(
        "import subprocess\n"
        "import sys\n"
        "import time\n"
        "from pathlib import Path\n"
        "child = subprocess.Popen([sys.executable, '-c', "
        "'import time; time.sleep(30)'])\n"
        "Path(sys.argv[1]).write_text(str(child.pid))\n"
        "time.sleep(30)\n"
    )

    handle = CancellableProcessExecutor().start(_request(script, str(child_pid_file)))
    try:
        for _ in range(200):
            if child_pid_file.exists():
                break
            assert handle.wait(timeout_seconds=0.01) is None
        assert child_pid_file.exists()
        child_pid = int(child_pid_file.read_text())
        handle.terminate()
        result = handle.wait(timeout_seconds=2)
        assert result is not None
        if os.name == "posix":
            assert not _pid_is_running(child_pid)
    finally:
        handle.close()


@pytest.mark.skipif(os.name != "posix", reason="SIGTERM ignore behavior is POSIX-specific")
def test_kill_escalation_marks_force_killed(tmp_path: Path) -> None:
    script = tmp_path / "ignore_term.py"
    ready_file = tmp_path / "ready"
    script.write_text(
        "import signal\n"
        "import sys\n"
        "import time\n"
        "from pathlib import Path\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "Path(sys.argv[1]).write_text('ready')\n"
        "time.sleep(30)\n"
    )

    handle = CancellableProcessExecutor().start(_request(script, str(ready_file)))
    try:
        for _ in range(200):
            if ready_file.exists():
                break
            assert handle.wait(timeout_seconds=0.01) is None
        assert ready_file.exists()
        handle.terminate()
        assert handle.wait(timeout_seconds=0.05) is None
        handle.kill()
        result = handle.wait(timeout_seconds=2)
        assert result is not None
        assert result.termination_requested is True
        assert result.force_killed is True
    finally:
        handle.close()


def test_close_is_idempotent_and_reaps_running_process(tmp_path: Path) -> None:
    script = tmp_path / "close.py"
    script.write_text("import time\ntime.sleep(30)\n")
    handle = CancellableProcessExecutor().start(_request(script))

    handle.close()
    handle.close()

    result = handle.poll()
    assert result is not None
    assert result.termination_requested is True

def test_process_executor_supplies_bounded_stdin(
    tmp_path: Path,
) -> None:
    script = tmp_path / "stdin_capture.py"
    script.write_text(
        "import hashlib\n"
        "import sys\n"
        "data = sys.stdin.buffer.read()\n"
        "digest = hashlib.sha256(data).hexdigest()\n"
        "sys.stdout.write(f'{len(data)}:{digest}')\n",
        encoding="utf-8",
    )
    payload = b"securescan-enry-input\n"

    with CancellableProcessExecutor().start(
        _request(
            script,
            stdin_data=payload,
        )
    ) as handle:
        result = handle.wait(timeout_seconds=2)

    assert result is not None
    assert result.return_code == 0
    assert result.stderr == b""
    assert result.stdout.decode() == (
        f"{len(payload)}:"
        f"{hashlib.sha256(payload).hexdigest()}"
    )
    assert payload not in b" ".join(
        argument.encode()
        for argument in _request(
            script,
            stdin_data=payload,
        ).argv
    )


def test_process_executor_uses_eof_when_stdin_is_absent(
    tmp_path: Path,
) -> None:
    script = tmp_path / "stdin_empty.py"
    script.write_text(
        "import sys\n"
        "sys.stdout.write(str(len(sys.stdin.buffer.read())))\n",
        encoding="utf-8",
    )

    with CancellableProcessExecutor().start(
        _request(script)
    ) as handle:
        result = handle.wait(timeout_seconds=2)

    assert result is not None
    assert result.return_code == 0
    assert result.stdout == b"0"


def test_process_request_rejects_mutable_stdin(
    tmp_path: Path,
) -> None:
    script = tmp_path / "unused.py"
    script.write_text("", encoding="utf-8")

    with pytest.raises(
        InvalidCancellableProcessRequestError,
        match="Process input must be immutable bytes",
    ):
        CancellableProcessRequest(
            argv=(sys.executable, str(script)),
            cwd=tmp_path,
            environment={},
            timeout_seconds=2,
            stdout_limit_bytes=4096,
            stderr_limit_bytes=4096,
            stdin_data=bytearray(b"mutable"),  # type: ignore[arg-type]
        )


def test_process_request_rejects_oversized_stdin(
    tmp_path: Path,
) -> None:
    script = tmp_path / "unused.py"
    script.write_text("", encoding="utf-8")

    with pytest.raises(
        InvalidCancellableProcessRequestError,
        match="Process input must be immutable bytes",
    ):
        CancellableProcessRequest(
            argv=(sys.executable, str(script)),
            cwd=tmp_path,
            environment={},
            timeout_seconds=2,
            stdout_limit_bytes=4096,
            stderr_limit_bytes=4096,
            stdin_data=b"x" * (16 * 1024 * 1024 + 1),
        )
