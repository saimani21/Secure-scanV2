class FormulaEngine:
    def eval(self, expression: str) -> str:
        return expression


def calculate(engine: FormulaEngine, expression: str) -> str:
    return engine.eval(expression)

