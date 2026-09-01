import tempfile


def temporary_name() -> str:
    return tempfile.mktemp()

