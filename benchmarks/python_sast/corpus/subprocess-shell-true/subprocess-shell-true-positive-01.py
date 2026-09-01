import subprocess


def run(command: str):
    return subprocess.run(command, shell=True, check=True)

