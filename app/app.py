from flask import Flask
from flask import flash, redirect, render_template, request, url_for, session, abort
import os

app=Flask(__name__)
app.secret_key=os.urandom(24)
@app.route("/")
def home():
    if not session.get("logged_in"):
        return render_template("login.html")
    else:
        return "Hello There <a href='/logout'>Logout</a>"

@app.route("/login", methods=["POST"])
def admin_login():
    username = request.form.get("username")
    password = request.form.get("password")

    if username == "admin" and password == "password":
        session["logged_in"] = True
    else:
        flash("Invalid username or password!")
    return redirect(url_for("home"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=4000)