import ast


def parse_literal(expression: str):
    return ast.literal_eval(expression)
