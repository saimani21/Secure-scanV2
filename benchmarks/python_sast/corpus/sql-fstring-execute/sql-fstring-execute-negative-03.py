def count(cursor):
    return cursor.execute("SELECT count(*) FROM users")

