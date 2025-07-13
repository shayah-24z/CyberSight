import sqlite3
import bcrypt
from datetime import datetime
import json
import time

def show_menu():
    print("\n=== Secure User System ===")
    print("1. Register")
    print("2. Login")
    print("3. Exit")

while True:
    show_menu()
    choice = input("Select an option (1-3): ")

    if choice == "1": #register user function
        
        username = input("Enter a username: ")
        email = input("Enter your email: ")
        password = input("Enter a password: ")
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        #connects to database
        conn = sqlite3.connect("secure_app.db")
        cursor = conn.cursor()

        try:
            cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", 
                    (username, email, hashed_password))
            conn.commit()
            print(" User registered successfully!")
        except sqlite3.IntegrityError:
            print(" That username or email already exists.")
        finally:
            conn.close()
       
    elif choice == "2":
        #Count how many recent failures a user has had and shows a warning after 3
        def count_recent_failures(username, log_path="login_activity.log", limit=3):
            try:
                with open(log_path, "r") as log_file:
                    lines = log_file.readlines()
            except FileNotFoundError:
                return 0  # no log = no failures yet

            #Check recent failures for this username
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

         #gets user input
        username = input("Enter your username: ")
        password = input("Enter your password: ")

    #Connects to the database
        conn = sqlite3.connect("secure_app.db")
        cursor = conn.cursor()

        #looks for the user
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()

        #Creates log entry
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        fail_count = count_recent_failures(username)
        if fail_count >= 3:
            print(" WARNING: This account has had 3 or more failed logins in a row.")

        if result:
            stored_hash = result[0]
            if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
                outcome = "SUCCESS"
                print(" Login successful!")
            else:
                outcome = "FAILURE - Wrong password"
                print(" Incorrect password.")
        else:
            outcome = "FAILURE - No such user"
            print(" No user found with that username.")

        # Save to log file
        with open("login_activity.log", "a") as log_file:
            log_file.write(f"[{timestamp}] User: {username} — {outcome}\n")
     
    elif choice == "3":
        print(" Exiting. Bye!")
        break
    else:
        print(" Invalid choice. Please enter 1, 2 or 3.")