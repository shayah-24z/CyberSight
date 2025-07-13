from flask import Flask, render_template, request, redirect
import sqlite3
import bcrypt
import os
import json
import time
from datetime import datetime

app = Flask(__name__)

#path to my database
DB_PATH = os.path.join(os.path.dirname(__file__), "secure_app.db")

#home page route
@app.route("/")
def home():
    log_entries = []
    try:
        with open("login_activity.log", "r") as f:
            log_entries = f.readlines()
    except FileNotFoundError:
        log_entries = ["No login activity yet."]
    
    # Show most recent entries first
    log_entries = log_entries[::-1][:10]  # Last 10 entries
    return render_template("dashboard.html", log_entries=log_entries)

#home page roure
@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

#register page route
@app.route("/register", methods=["GET", "POST"])
def register():
    #gets form data
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    #connets to database referenced earlier
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        try:
            #insers user into database
            cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                           (username, email, hashed_pw))
            conn.commit()
            return redirect("/register?success=1")
        except sqlite3.IntegrityError:
            return redirect("/register?error=1") #redirects if user/email exists
        finally:
            conn.close()
    #shows registration form
    return render_template("register.html")

def count_recent_failures(username, log_path="login_activity.log", limit=3):
    try:
        with open(log_path, "r") as log_file:
            lines = log_file.readlines()
    except FileNotFoundError:
        return 0

    failures = 0
    for line in reversed(lines):
        if f"User: {username}" in line:
            if "SUCCESS" in line:
                break
            elif "FAILURE" in line:
                failures += 1
                if failures >= limit:
                    return failures
    return failures

def is_user_locked(username, lock_file="login_locks.json"):
    try:
        with open(lock_file, "r") as f:
            locks = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return False

    unlock_time = locks.get(username)
    if unlock_time and time.time() < unlock_time:
        return True
    return False

def lock_user(username, duration=30, lock_file="login_locks.json"):
    try:
        with open(lock_file, "r") as f:
            locks = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        locks = {}

    locks[username] = time.time() + duration

    with open(lock_file, "w") as f:
        json.dump(locks, f)

#login page route
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if is_user_locked(username):
            return redirect("/login?locked=1")

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()

        from datetime import datetime
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        if result:
            stored_hash = result[0]
            if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
                outcome = "SUCCESS"
                with open("login_activity.log", "a") as f:
                    f.write(f"[{timestamp}] User: {username} — {outcome}\n")
                return redirect("/login?success=1")
            else:
                outcome = "FAILURE - Wrong password"
        else:
            outcome = "FAILURE - No such user"

        with open("login_activity.log", "a") as f:
            f.write(f"[{timestamp}] User: {username} — {outcome}\n")

        fail_count = count_recent_failures(username)
        if fail_count >= 3:
            lock_user(username)
            return redirect("/login?locked=1")

        return redirect("/login?error=1")

    return render_template("login.html")

#runs server
if __name__ == "__main__":
    app.run(debug=True)