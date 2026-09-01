import ast


def parse_literal(value: str):
    return ast.literal_eval(value)

