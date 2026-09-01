class Simulator:
    def system(self, value: str) -> str:
        return value


def simulate(instance: Simulator, value: str) -> str:
    return instance.system(value)

