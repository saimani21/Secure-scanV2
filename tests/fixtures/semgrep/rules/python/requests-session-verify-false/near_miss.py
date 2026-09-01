class LocalSession:
    def __init__(self) -> None:
        self.verify = False


def local_session() -> LocalSession:
    return LocalSession()
