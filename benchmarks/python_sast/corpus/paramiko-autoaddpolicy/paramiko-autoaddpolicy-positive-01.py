import paramiko


def configure(client: paramiko.SSHClient) -> None:
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

