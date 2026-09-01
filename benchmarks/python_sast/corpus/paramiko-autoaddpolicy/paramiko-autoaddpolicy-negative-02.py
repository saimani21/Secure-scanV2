import paramiko


def configure(client: paramiko.SSHClient) -> None:
    client.load_system_host_keys()

