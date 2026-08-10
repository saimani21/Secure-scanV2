# Curated benchmark fixture: one intentional dangerous-eval rule match.


def evaluate_expression(expression: str) -> object:
    return eval(expression)
