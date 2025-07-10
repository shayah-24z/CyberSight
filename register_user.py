import bcrypt
import sqlite3

# Get user input
username = input("Enter a username: ")
email = input("Enter your email: ")
password = input("Enter a password: ")
hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# Connect to the database
conn = sqlite3.connect("secure_app.db")
cursor = conn.cursor()

try:
    # Insert new user
    cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", 
               (username, email, hashed_password))
    conn.commit()
    print("✅ User registered successfully!")
except sqlite3.IntegrityError:
    print("❌ That username or email already exists.")
finally:
    conn.close()
