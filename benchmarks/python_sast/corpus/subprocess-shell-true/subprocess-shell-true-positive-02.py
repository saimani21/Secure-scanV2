import subprocess


def start(command: str):
    return subprocess.Popen(command, shell=True)

