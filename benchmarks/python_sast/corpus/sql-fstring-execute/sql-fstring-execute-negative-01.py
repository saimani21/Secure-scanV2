def lookup(cursor, username: str):
    return cursor.execute("SELECT * FROM users WHERE name = %s", (username,))

