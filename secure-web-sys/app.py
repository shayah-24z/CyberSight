from flask import Flask, render_template, request, redirect
import sqlite3
import bcrypt
import os

app = Flask(__name__)

#path to my database
DB_PATH = os.path.join(os.path.dirname(__file__), "secure_app.db")

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
#runs server
if __name__ == "__main__":
    app.run(debug=True)