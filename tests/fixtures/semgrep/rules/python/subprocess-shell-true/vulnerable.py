import subprocess


def run_command(command: str):
    return subprocess.run(command, shell=True, check=True)
