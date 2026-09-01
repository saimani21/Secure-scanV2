import jwt


def decode_unverified(token: str):
    return jwt.decode(token, options={"verify_signature": False})
