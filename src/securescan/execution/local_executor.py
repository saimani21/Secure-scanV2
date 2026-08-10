from __future__ import annotations

import os
import subprocess
import tempfile
import time
from pathlib import Path

from securescan.domain.models import CapturedProcess, ExecutionPlan


class LocalProcessExecutor:
    """Execute a command without a shell and enforce timeout/output limits.

    Output is written to temporary files rather than accumulated in process pipes.
    This avoids deadlocks and lets the executor terminate output-flooding tools.
    """

    def execute(self, plan: ExecutionPlan) -> CapturedProcess:
        started = time.monotonic()
        environment = os.environ.copy()
        environment.update(plan.environment)

        with tempfile.TemporaryDirectory(prefix="securescan-exec-") as temp_dir:
            stdout_path = Path(temp_dir) / "stdout.bin"
            stderr_path = Path(temp_dir) / "stderr.bin"

            with stdout_path.open("wb") as stdout_file, stderr_path.open("wb") as stderr_file:
                process = subprocess.Popen(  # noqa: S603 - command is an argument array
                    plan.command,
                    cwd=str(plan.cwd) if plan.cwd else None,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    shell=False,
                    start_new_session=True,
                )

                timed_out = False
                output_limit_exceeded = False
                deadline = started + plan.timeout_seconds

                while process.poll() is None:
                    if time.monotonic() >= deadline:
                        timed_out = True
                        self._terminate(process)
                        break

                    output_size = self._size(stdout_path) + self._size(stderr_path)
                    if output_size > plan.max_output_bytes:
                        output_limit_exceeded = True
                        self._terminate(process)
                        break

                    time.sleep(0.025)

                process.wait(timeout=2)
                final_output_size = self._size(stdout_path) + self._size(stderr_path)
                if final_output_size > plan.max_output_bytes:
                    output_limit_exceeded = True

            stdout = self._read_bounded(stdout_path, plan.max_output_bytes)
            remaining = max(0, plan.max_output_bytes - len(stdout))
            stderr = self._read_bounded(stderr_path, remaining)

        duration_ms = int((time.monotonic() - started) * 1000)
        return CapturedProcess(
            command=plan.command,
            exit_code=process.returncode,
            stdout=stdout,
            stderr=stderr,
            duration_ms=duration_ms,
            timed_out=timed_out,
            output_limit_exceeded=output_limit_exceeded,
        )

    @staticmethod
    def _size(path: Path) -> int:
        try:
            return path.stat().st_size
        except FileNotFoundError:
            return 0

    @staticmethod
    def _read_bounded(path: Path, limit: int) -> bytes:
        if limit <= 0 or not path.exists():
            return b""
        with path.open("rb") as file:
            return file.read(limit)

    @staticmethod
    def _terminate(process: subprocess.Popen[bytes]) -> None:
        try:
            if os.name == "posix":
                os.killpg(process.pid, 15)
            else:
                process.terminate()
            process.wait(timeout=1)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            try:
                if os.name == "posix":
                    os.killpg(process.pid, 9)
                else:
                    process.kill()
            except ProcessLookupError:
                pass
