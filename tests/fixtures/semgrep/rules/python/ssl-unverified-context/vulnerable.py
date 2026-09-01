import ssl


def insecure_context():
    return ssl._create_unverified_context()
