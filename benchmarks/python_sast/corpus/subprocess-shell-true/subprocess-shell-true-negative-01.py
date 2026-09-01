import subprocess


def run(command: str):
    return subprocess.run(command, shell=False, check=True)

