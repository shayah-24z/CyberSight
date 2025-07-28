from flask import Flask, render_template, request, redirect, session, jsonify
import sqlite3
import bcrypt
import os
import json
import time
from datetime import datetime

app = Flask(__name__)

app.secret_key = "spoon"


DB_PATH = os.path.join(os.path.dirname(__file__), "secure_app.db")


@app.route("/")
def home():
    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    username = session.get("username", "spoon") 

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT is_admin FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()

    is_admin = result and result[0] == 1

   
    try:
        with open("login_activity.log", "r") as f:
            log_entries = f.readlines()
    except FileNotFoundError:
        log_entries = ["No login activity yet."]
    log_entries = log_entries[::-1][:10]


    user_list = []
    if is_admin:
        cursor.execute("SELECT id, username, email, is_admin FROM users")
        user_list = cursor.fetchall()

   
    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]

    # Active today (users with a SUCCESS login today)
    today = datetime.now().strftime('%Y-%m-%d')
    active_today_set = set()
    try:
        with open("login_activity.log", "r") as f:
            for line in f:
                if today in line and "SUCCESS" in line:
                    user = line.split("User: ")[1].split(" ")[0]
                    active_today_set.add(user)
    except FileNotFoundError:
        pass
    active_today = len(active_today_set)

    # Locked accounts (from login_locks.json)
    locked_accounts = 0
    locked_users = []
    try:
        with open("login_locks.json", "r") as f:
            locks = json.load(f)
        now = time.time()
        locked_users = [u for u, t in locks.items() if now < t]
        locked_accounts = len(locked_users)
    except (FileNotFoundError, json.JSONDecodeError):
        locked_accounts = 0
        locked_users = []

  
    login_stats = []
    date_counts = {}
    success_count = 0
    failure_count = 0
    try:
        with open("login_activity.log", "r") as f:
            for line in f:
                if "User: " in line:
              
                    date_str = line[1:11]
                    outcome = line.split("—")[-1].strip()
                    if date_str not in date_counts:
                        date_counts[date_str] = {"success_count": 0, "failure_count": 0}
                    if "SUCCESS" in outcome:
                        date_counts[date_str]["success_count"] += 1
                        success_count += 1
                    elif "FAILURE" in outcome:
                        date_counts[date_str]["failure_count"] += 1
                        failure_count += 1
    except FileNotFoundError:
        pass
 
    from datetime import timedelta
    days = [(datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d') for i in range(6, -1, -1)]
    for d in days:
        login_stats.append({
            "date": d,
            "success_count": date_counts.get(d, {}).get("success_count", 0),
            "failure_count": date_counts.get(d, {}).get("failure_count", 0)
        })

    conn.close()

    return render_template(
        "dashboard.html",
        log_entries=log_entries,
        is_admin=is_admin,
        user_list=user_list,
        total_users=total_users,
        active_today=active_today,
        locked_accounts=locked_accounts,
        login_stats=login_stats,
        success_count=success_count,
        failure_count=failure_count,
        locked_users=locked_users,
        session=session 
    )

#register page route
@app.route("/register", methods=["GET", "POST"])
def register():
    #gets form data
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        try:
            
            cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                           (username, email, hashed_pw))
            conn.commit()
            return redirect("/register?success=1")
        except sqlite3.IntegrityError:
            return redirect("/register?error=1") 
        finally:
            conn.close()
    
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


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if is_user_locked(username):
            return redirect("/login?locked=1")

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT password, is_admin FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()

    
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        if result:
            stored_hash, is_admin = result
            if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
               
                outcome = "SUCCESS"
                with open("login_activity.log", "a") as f:
                    f.write(f"[{timestamp}] User: {username} — {outcome}\n")

            
                session["username"] = username
                session["is_admin"] = is_admin == 1

              
                if session["is_admin"]:
                    return redirect("/dashboard")
                else:
                    return redirect("/sandbox")

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

@app.route("/api/dashboard-data")
def api_dashboard_data():
    username = session.get("username", "spoon")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT is_admin FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    is_admin = result and result[0] == 1

    
    user_list = []
    if is_admin:
        cursor.execute("SELECT id, username, email, is_admin FROM users")
        user_list = cursor.fetchall()

    
    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]

   
    today = datetime.now().strftime('%Y-%m-%d')
    active_today_set = set()
    try:
        with open("login_activity.log", "r") as f:
            for line in f:
                if today in line and "SUCCESS" in line:
                    user = line.split("User: ")[1].split(" ")[0]
                    active_today_set.add(user)
    except FileNotFoundError:
        pass
    active_today = len(active_today_set)

    # Locked accounts
    locked_accounts = 0
    locked_users = []
    try:
        with open("login_locks.json", "r") as f:
            locks = json.load(f)
        now = time.time()
        locked_users = [u for u, t in locks.items() if now < t]
        locked_accounts = len(locked_users)
    except (FileNotFoundError, json.JSONDecodeError):
        locked_accounts = 0
        locked_users = []

    
    login_stats = []
    date_counts = {}
    success_count = 0
    failure_count = 0
    try:
        with open("login_activity.log", "r") as f:
            for line in f:
                if "User: " in line:
                    date_str = line[1:11]
                    outcome = line.split("—")[-1].strip()
                    if date_str not in date_counts:
                        date_counts[date_str] = {"success_count": 0, "failure_count": 0}
                    if "SUCCESS" in outcome:
                        date_counts[date_str]["success_count"] += 1
                        success_count += 1
                    elif "FAILURE" in outcome:
                        date_counts[date_str]["failure_count"] += 1
                        failure_count += 1
    except FileNotFoundError:
        pass
    from datetime import timedelta
    days = [(datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d') for i in range(6, -1, -1)]
    for d in days:
        login_stats.append({
            "date": d,
            "success_count": date_counts.get(d, {}).get("success_count", 0),
            "failure_count": date_counts.get(d, {}).get("failure_count", 0)
        })

    # Recent log entries (last 10, newest first)
    try:
        with open("login_activity.log", "r") as f:
            log_entries = f.readlines()
    except FileNotFoundError:
        log_entries = ["No login activity yet."]
    log_entries = [entry.strip() for entry in log_entries[::-1][:10]]

    conn.close()

    return jsonify({
        "total_users": total_users,
        "active_today": active_today,
        "locked_accounts": locked_accounts,
        "login_stats": login_stats,
        "success_count": success_count,
        "failure_count": failure_count,
        "user_list": user_list,
        "is_admin": is_admin,
        "log_entries": log_entries,
        "locked_users": locked_users
    })

@app.route("/api/logins-for-day")
def api_logins_for_day():
    date = request.args.get('date')
    if not date:
        return jsonify([])
    entries = []
    try:
        with open("login_activity.log", "r") as f:
            for line in f:
                if line.startswith(f"[{date}"):
                    entries.append(line.strip())
    except FileNotFoundError:
        pass
    return jsonify(entries)


if __name__ == "__main__":
    app.run(debug=True)