import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required, calculate_age

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///birthday.db")


@app.route("/")
@login_required
def index():
    # show 10 friends birthdays nearest from today

    # select 10 friends data from table
    friends = db.execute("SELECT * FROM friends WHERE user_id = ? ORDER BY birthday DESC LIMIT 5", session['user_id'])

    # if there were no friend record, let user access to Add page
    if not friends:
        return apology("add friends from Add")

    # for every friend, calculate age from their birthday
    for friend in friends:
        birthday = friend['birthday']
        age = calculate_age(birthday)
        friend['age'] = age

    return render_template("index.html", friends = friends)


@app.route("/mypage", methods=["GET", "POST"])
@login_required
def mypage():
    # show user's information

    # select user's data from table
    users = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])

    # if user's data hasn't registered, let user access to settings page
    if not users[0]['birthday'] or not users[0]['item'] or not users[0]['price']:
        return apology("register your information from settings")

    # calculate user's age
    birthday = users[0]['birthday']
    age = calculate_age(birthday)
    users[0]['age'] = age

    return render_template("mypage.html", users = users)


@app.route("/history")
@login_required
def history():
    # show record of present given to friends

    # select all user's record from table
    records = db.execute("SELECT * FROM records WHERE user_id = ? ORDER BY friendname, age DESC", session["user_id"])

    # if there were no friend's record, let user access to add page
    if not records:
        return apology("add your friend's birthday record from add page")

    return render_template("history.html", records = records)


@app.route("/login", methods=["GET", "POST"])
def login():
    # log user in

    # forget any user_id
    session.clear()

    # if user reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username")

        # ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password")

        # query database for username
        user = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # ensure username exists and password is correct
        if len(user) != 1 or not check_password_hash(user[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password")

        # remember which user has logged in
        session["user_id"] = user[0]["id"]

        # redirect user to home page
        return redirect("/")

    # else if user reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    # log user out

    # forget any user_id
    session.clear()

    # redirect user to login form
    return render_template("login.html")


@app.route("/search", methods=["GET", "POST"])
@login_required
def search():
    # search friends' info

    if request.method == "GET":
        # display form to request birthday
        return render_template("search.html")

    if request.method == "POST":
        # display friend's information that matches user's selected birthday

        # if user didn't provide neccesary info
        if not request.form.get("birthday"):
            return apology("no birthday found")

        birthday = request.form.get("birthday")

        # select friend's data that matches user's request
        friends = db.execute("SELECT * FROM friends WHERE birthday = ?", birthday)

        # display error message if no one matches selected birthday
        if len(friends) == 0:
            return apology("no one matches selected birthday")

        # for every friend, calculate age from their birthday
        for friend in friends:
            birthday = friend['birthday']
            age = calculate_age(birthday)
            friend['age'] = age

        return render_template("searched.html", friends = friends)


@app.route("/changepassword", methods=["GET", "POST"])
@login_required
def changepassword():

    if request.method == "GET":
        return render_template("changepassword.html")

    if request.method == "POST":

        if not request.form.get("password"):
            return apology("no password found")

        elif not request.form.get("confirmation"):
            return apology("no password confirmation")

        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("must provide same password")

        password = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8)

        db.execute("UPDATE users SET hash = ? WHERE id = ?", password, session["user_id"])

        return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":

        if not request.form.get("username"):
            return apology("no username found")

        elif len(db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))) != 0:
            return apology("username already used")

        elif not request.form.get("email"):
            return apology("no email found")

        elif len(db.execute("SELECT * FROM users WHERE email = ?", request.form.get("email"))) != 0:
            return apology("email already exists")

        elif not request.form.get("password"):
            return apology("no password found")

        elif not request.form.get("confirmation"):
            return apology("no password confirmation")

        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("must provide same password")

        password = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8)
        # insert user to the database
        username = request.form.get("username")
        email = request.form.get("email")

        db.execute("INSERT INTO users (username, hash, email) VALUES(?, ?, ?)", username, password, email)

        return redirect("/login")

    else:
        return render_template("register.html")


@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    # add friend's info

    if request.method == "POST":

        if not request.form.get("friendname"):
            return apology("no friendname found")

        elif len(db.execute("SELECT * FROM friends WHERE friendname = ?", request.form.get("friendname"))) != 0:
            return apology("friendname already exists")

        elif not request.form.get("birthday"):
            return apology("no birthday found")

        friendname = request.form.get('friendname')
        birthday = request.form.get('birthday')

        db.execute("INSERT INTO friends (user_id, friendname, birthday) VALUES(?, ?, ?)", session['user_id'], friendname, birthday)

        return redirect("/")

    else:
        return render_template("add.html")


@app.route("/record", methods=["GET", "POST"])
@login_required
def record():
    # add friend's birthday record

    if request.method == "GET":

        friends = db.execute("SELECT friendname FROM friends WHERE user_id = ?", session["user_id"])

        if len(friends) == 0:
            return apology("add friend info from Add first")

        return render_template("record.html", friends = friends)

    if request.method == "POST":

        if not request.form.get("friendname"):
            return apology("no friendname found")

        elif not request.form.get("age"):
            return apology("no birthday found")

        elif not request.form.get("item"):
            return apology("no item found")

        elif not request.form.get("price"):
            return apology("no price confirmation")

        friend = db.execute("SELECT * FROM friends WHERE user_id = ? AND friendname = ?", session['user_id'], request.form.get("friendname"))

        birthday = friend[0]['birthday']
        age = calculate_age(birthday)

        if int(age) < int(request.form.get("age")):
            return apology("that birthday is future")

        friend = request.form.get('friendname')
        age = request.form.get('age')
        item = request.form.get('item')
        price = request.form.get('price')

        db.execute("INSERT INTO records (user_id, friendname, age, item, price) VALUES(?, ?, ?, ?, ?)", session['user_id'], friend, age, item, price)

        return redirect("/record")


@app.route("/list")
@login_required
def list():
    # show all of friends birthdays

    friends = db.execute("SELECT * FROM friends WHERE user_id = ? ORDER BY birthday DESC", session['user_id'])

    if not friends:
        return apology("no friends added")

    for friend in friends:
        birthday = friend['birthday']
        age = calculate_age(birthday)
        friend['age'] = age

    return render_template("index.html", friends = friends)


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    # something

    if request.method == "POST":

        if not request.form.get("birthday"):
            return apology("no birthday found")

        elif not request.form.get("item"):
            return apology("no item found")

        elif not request.form.get("price"):
            return apology("no price found")

        birthday = request.form.get('birthday')
        item = request.form.get('item')
        price = request.form.get('price')

        db.execute("UPDATE users SET birthday = ?, item = ?, price = ? WHERE id = ?", birthday, item, price, session['user_id'])

        return redirect("/settings")

    else:
        return render_template("settings.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
