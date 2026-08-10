# Curated clean fixture: an argument array avoids invoking a command shell.

import subprocess


def run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, shell=False, check=True, text=True)
