import requests


def send(method: str, url: str):
    return requests.request(method, url, verify=False)

