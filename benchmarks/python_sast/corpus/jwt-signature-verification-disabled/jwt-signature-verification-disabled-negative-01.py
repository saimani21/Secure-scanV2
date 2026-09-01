import jwt


def decode(token: str, key: str):
    return jwt.decode(token, key, algorithms=["HS256"])

