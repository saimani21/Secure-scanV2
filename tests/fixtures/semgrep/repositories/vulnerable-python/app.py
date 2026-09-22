import subprocess

import yaml


def unsafe(expression: str, command: str, document: str) -> tuple[object, object]:
    evaluated = eval(expression)
    subprocess.run(command, shell=True, check=False)
    return evaluated, yaml.load(document, Loader=yaml.Loader)


def safe(command: list[str], document: str) -> tuple[object, object]:
    subprocess.run(command, shell=False, check=True)
    return command, yaml.safe_load(document)
