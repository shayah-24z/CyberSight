import sqlite3
import bcrypt

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
        print(" Logging in...")
     
    elif choice == "3":
        print(" Exiting. Bye!")
        break
    else:
        print(" Invalid choice. Please enter 1, 2 or 3.")