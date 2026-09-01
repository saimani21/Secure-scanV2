def update(connection, value: str):
    return connection.cursor().execute(f"UPDATE settings SET value = '{value}'")

