import paramiko


def trust_unknown_hosts(client: paramiko.SSHClient) -> None:
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
