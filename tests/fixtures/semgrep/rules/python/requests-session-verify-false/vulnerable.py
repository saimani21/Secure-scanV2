import requests


def session_without_verification():
    session = requests.Session()
    session.verify = False
    return session
