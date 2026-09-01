import jwt


def decode_without_audience(token: str, key: str):
    return jwt.decode(
        token,
        key,
        algorithms=["HS256"],
        options={"verify_aud": False},
    )
