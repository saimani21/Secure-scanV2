import subprocess


def run_command(command: str):
    return subprocess.Popen([command], shell=False)
