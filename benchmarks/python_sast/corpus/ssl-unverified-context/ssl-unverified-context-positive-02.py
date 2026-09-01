import ssl


def insecure_context() -> ssl.SSLContext:
    return ssl._create_unverified_context()

