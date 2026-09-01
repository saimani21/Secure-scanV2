import ssl


def verified_context():
    return ssl.create_default_context()
