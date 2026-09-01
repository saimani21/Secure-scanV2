class AutoAddPolicy:
    pass


class LocalClient:
    def set_policy(self, policy: AutoAddPolicy) -> None:
        self.policy = policy
