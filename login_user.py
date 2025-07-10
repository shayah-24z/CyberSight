import sqlite3
import bcrypt
from datetime import datetime

#Count how many recent failures a user has had and shows a warning after 3
def count_recent_failures(username, log_path="login_activity.log", limit=3):
    try:
        with open(log_path, "r") as log_file:
            lines = log_file.readlines()
    except FileNotFoundError:
        return 0  # no log = no failures yet

    # Check recent failures for this username
    failures = 0
    for line in reversed(lines):
        if f"User: {username}" in line:
            if "SUCCESS" in line:
                break  # they logged in successfully — reset
            elif "FAILURE" in line:
                failures += 1
                if failures >= limit:
                    return failures
    return failures

# Get user input
username = input("Enter your username: ")
password = input("Enter your password: ")

# Connect to the database
conn = sqlite3.connect("secure_app.db")
cursor = conn.cursor()

# Look for the user
cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
result = cursor.fetchone()
conn.close()

# Create log entry
timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

fail_count = count_recent_failures(username)
if fail_count >= 3:
    print("🚨 WARNING: This account has had 3 or more failed logins in a row.")

if result:
    stored_hash = result[0]
    if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
        outcome = "SUCCESS"
        print("✅ Login successful!")
    else:
        outcome = "FAILURE - Wrong password"
        print("❌ Incorrect password.")
else:
    outcome = "FAILURE - No such user"
    print("❌ No user found with that username.")

# Save to log file
with open("login_activity.log", "a") as log_file:
    log_file.write(f"[{timestamp}] User: {username} — {outcome}\n")