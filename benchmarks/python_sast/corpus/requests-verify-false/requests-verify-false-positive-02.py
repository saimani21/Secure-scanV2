import requests


def submit(url: str, payload: dict[str, object]):
    return requests.post(url, json=payload, verify=False)

