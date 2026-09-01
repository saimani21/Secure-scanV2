import ssl


def secure_context() -> ssl.SSLContext:
    return ssl.create_default_context()

