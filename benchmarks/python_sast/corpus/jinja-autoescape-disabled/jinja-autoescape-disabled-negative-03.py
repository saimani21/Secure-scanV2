class Environment:
    def __init__(self, *, autoescape: bool) -> None:
        self.autoescape = autoescape


def environment() -> Environment:
    return Environment(autoescape=False)

