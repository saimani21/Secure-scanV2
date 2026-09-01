import jwt


def decode_without_signature(token: str, key: str):
    return jwt.decode(token, key, options={"verify_signature": False})

