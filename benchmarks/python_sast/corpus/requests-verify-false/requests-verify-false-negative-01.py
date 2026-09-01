import requests


def fetch(url: str):
    return requests.get(url, verify=True)

