import os


def command_stream(program: str, argument: str):
    command = program + " " + argument
    return os.popen(command)

