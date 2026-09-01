import subprocess


def run(program: str, argument: str):
    return subprocess.run([program, argument], check=True)

