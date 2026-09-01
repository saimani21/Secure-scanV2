import os


def invoke_parts(program: str, argument: str) -> int:
    command = f"{program} {argument}"
    return os.system(command)

