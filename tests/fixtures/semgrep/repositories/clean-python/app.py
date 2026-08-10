import ast
import subprocess

import yaml


def safe(expression: str, command: list[str], document: str) -> tuple[object, object]:
    evaluated = ast.literal_eval(expression)
    subprocess.run(command, shell=False, check=True)
    return evaluated, yaml.safe_load(document)
