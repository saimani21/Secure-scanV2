import ssl


def configure() -> ssl.SSLContext:
    context = ssl._create_unverified_context(protocol=ssl.PROTOCOL_TLS_CLIENT)
    return context

