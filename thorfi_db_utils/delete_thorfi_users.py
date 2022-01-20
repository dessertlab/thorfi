import sqlite3
conn = sqlite3.connect('/tmp/thorfi_users.db')
cur = conn.cursor()
result = cur.execute("DELETE FROM users;").fetchall()
conn.commit()
conn.close()

