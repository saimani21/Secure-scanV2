import requests


def secure_session() -> requests.Session:
    client = requests.Session()
    client.verify = True
    return client

