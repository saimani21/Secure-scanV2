class TemporaryNames:
    def mktemp(self) -> str:
        return "controlled-name"


def controlled_name(names: TemporaryNames) -> str:
    return names.mktemp()
