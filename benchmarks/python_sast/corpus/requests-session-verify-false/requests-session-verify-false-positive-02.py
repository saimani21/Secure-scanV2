import requests


def insecure_session() -> requests.Session:
    client = requests.Session()
    client.verify = False
    return client

