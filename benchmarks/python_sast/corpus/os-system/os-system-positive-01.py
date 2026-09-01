import os


def invoke(command: str) -> int:
    return os.system(command)

