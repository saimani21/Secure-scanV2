import paramiko


def connect(host: str) -> paramiko.SSHClient:
    transport = paramiko.SSHClient()
    transport.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    transport.connect(host)
    return transport

