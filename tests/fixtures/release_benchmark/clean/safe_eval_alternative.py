# Curated clean fixture: literal parsing avoids arbitrary code execution.

import ast


def parse_literal(expression: str) -> object:
    return ast.literal_eval(expression)
