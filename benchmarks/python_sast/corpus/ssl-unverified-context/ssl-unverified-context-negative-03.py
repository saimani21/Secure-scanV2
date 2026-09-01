class ContextFactory:
    def _create_unverified_context(self) -> object:
        return object()


def create(factory: ContextFactory) -> object:
    return factory._create_unverified_context()

