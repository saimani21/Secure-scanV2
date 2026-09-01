from pathlib import Path


def read_file(path: Path) -> str:
    return path.open(encoding="utf-8").read()

