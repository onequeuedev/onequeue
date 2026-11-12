import sqlite3


def find_user(conn: sqlite3.Connection, name: str):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)
    return cursor.fetchall()
