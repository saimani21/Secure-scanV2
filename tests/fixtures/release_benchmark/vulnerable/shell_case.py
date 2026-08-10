# Curated benchmark fixture: one intentional shell=True rule match.

import subprocess


def run_command(command: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, shell=True, check=False, text=True)
