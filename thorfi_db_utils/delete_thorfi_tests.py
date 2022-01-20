import sqlite3
conn = sqlite3.connect('thorfi_users.db')
cur = conn.cursor()
result = cur.execute("DELETE FROM tests;").fetchall()
conn.commit()
conn.close()

