import requests


def fetch(url: str, verify: bool):
    return requests.get(url, verify=verify, timeout=5)
