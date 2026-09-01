import requests


def configure() -> requests.Session:
    transport = requests.Session()
    transport.headers.update({"Accept": "application/json"})
    transport.verify = False
    return transport

