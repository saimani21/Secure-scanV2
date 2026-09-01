class ProcessFactory:
    def popen(self, name: str) -> str:
        return name


def create(factory: ProcessFactory, name: str) -> str:
    return factory.popen(name)

