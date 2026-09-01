class TaskRunner:
    def exec(self, task: str) -> str:
        return task


def run_task(runner: TaskRunner, task: str) -> str:
    return runner.exec(task)

