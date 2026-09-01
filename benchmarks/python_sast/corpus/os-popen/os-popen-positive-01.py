import os


def read_command(command: str) -> str:
    return os.popen(command).read()

