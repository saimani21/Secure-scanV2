import requests


def configured_session(verify: bool) -> requests.Session:
    client = requests.Session()
    client.verify = verify
    return client

