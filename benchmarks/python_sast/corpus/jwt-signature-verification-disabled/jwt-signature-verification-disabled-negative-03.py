import jwt


def decode(token: str):
    return jwt.decode(token, options={"verify_exp": False})

