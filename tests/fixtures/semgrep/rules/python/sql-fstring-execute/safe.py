def find_user(cursor, username: str):
    return cursor.execute("SELECT * FROM users WHERE name = ?", (username,))
