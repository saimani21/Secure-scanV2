import subprocess


def start(program: str):
    return subprocess.Popen([program], shell=False)

