import subprocess


def capture(command: str) -> bytes:
    return subprocess.check_output(command, shell=True)

