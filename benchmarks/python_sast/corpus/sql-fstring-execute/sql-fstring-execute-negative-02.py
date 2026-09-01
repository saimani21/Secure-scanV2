def build_query(username: str) -> str:
    return f"SELECT * FROM users WHERE name = '{username}'"

