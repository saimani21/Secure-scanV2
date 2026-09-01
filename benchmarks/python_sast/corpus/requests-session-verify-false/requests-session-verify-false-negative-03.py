class Session:
    def __init__(self) -> None:
        self.verify = True


def local_session() -> Session:
    client = Session()
    client.verify = False
    return client

