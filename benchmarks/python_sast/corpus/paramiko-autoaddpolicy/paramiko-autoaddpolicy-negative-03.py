class AutoAddPolicy:
    pass


class Client:
    def set_missing_host_key_policy(self, policy: object) -> None:
        self.policy = policy


def configure(client: Client) -> None:
    client.set_missing_host_key_policy(AutoAddPolicy())

