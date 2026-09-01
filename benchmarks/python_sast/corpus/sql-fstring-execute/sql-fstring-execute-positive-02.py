def remove(cursor, record_id: int):
    cursor.execute(f"DELETE FROM records WHERE id = {record_id}")

