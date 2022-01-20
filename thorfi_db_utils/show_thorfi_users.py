import sqlite3
conn = sqlite3.connect('thorfi_users.db')
cur = conn.cursor()
result = cur.execute("SELECT * from users;").fetchall()
print result
conn.close()

