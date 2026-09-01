import subprocess


def invoke(program: str, argument: str):
    return subprocess.run([program, argument], shell=False, check=True)

