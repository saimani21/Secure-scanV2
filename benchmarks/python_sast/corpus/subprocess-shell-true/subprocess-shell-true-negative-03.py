import subprocess


def run(command: str, use_shell: bool):
    return subprocess.run(command, shell=use_shell, check=True)

