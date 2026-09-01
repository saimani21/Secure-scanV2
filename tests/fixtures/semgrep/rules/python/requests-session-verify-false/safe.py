import requests


def verified_session():
    session = requests.Session()
    session.verify = True
    return session
