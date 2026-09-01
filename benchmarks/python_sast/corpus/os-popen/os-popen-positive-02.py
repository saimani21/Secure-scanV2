import os


def list_path(path: str) -> str:
    return os.popen(f"ls {path}").read()

