import jwt


def decode_verified(token: str, key: str):
    return jwt.decode(token, key, algorithms=["HS256"])
