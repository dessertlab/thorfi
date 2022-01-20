import sqlite3
conn = sqlite3.connect('thorfi_users.db')
cur = conn.cursor()
result = cur.execute("DELETE FROM campaigns;").fetchall()
conn.commit()
conn.close()

