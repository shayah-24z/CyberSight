import sqlite3

DB_PATH = "secure-web-sys/secure_app.db" 

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

try:
    cursor.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")
    print(" is_admin column added.")
except sqlite3.OperationalError as e:
    print(" Column may already exist or failed to add:", e)

conn.commit()
conn.close()
