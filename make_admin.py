import sqlite3

DB_PATH = "secure-web-sys/secure_app.db" 
username = "spoon" 

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

cursor.execute("UPDATE users SET is_admin = 1 WHERE username = ?", (username,))
conn.commit()
conn.close()

print(f"✅ User '{username}' is now an admin.")