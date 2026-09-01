import jwt


def claims(token: str):
    return jwt.decode(token, algorithms=["HS256"], options={"verify_signature": False})

