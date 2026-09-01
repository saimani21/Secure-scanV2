class NameFactory:
    def mktemp(self, prefix: str) -> str:
        return prefix


def temporary_name(factory: NameFactory) -> str:
    return factory.mktemp("safe-")

