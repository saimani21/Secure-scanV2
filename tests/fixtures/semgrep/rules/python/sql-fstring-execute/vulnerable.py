def find_user(cursor, username: str):
    return cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
