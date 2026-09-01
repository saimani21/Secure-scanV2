import tempfile


def socket_name(directory: str) -> str:
    return tempfile.mktemp(dir=directory, suffix=".sock")

