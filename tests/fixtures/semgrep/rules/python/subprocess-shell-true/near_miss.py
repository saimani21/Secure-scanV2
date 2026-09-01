import subprocess


def run_command(command: str, use_shell: bool):
    return subprocess.run([command], shell=use_shell, check=True)
