import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # Query database for username
    user_portfolio = db.execute(
        "SELECT id, symbol, name, SUM(shares)  FROM trades WHERE id = ? GROUP BY symbol HAVING SUM(shares) > 0 ORDER BY price DESC", session["user_id"])

    user_cash = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])

    # update user_portfolio with stock current price and total actual price of shares
    current_worth = 0
    for stock in user_portfolio:
        stock_data = lookup(stock["symbol"])
        stock["currentprice"] = stock_data["price"]
        stock["totalprice"] = stock_data["price"] * stock["SUM(shares)"]
        current_worth += stock["totalprice"]

    return render_template("index.html", user_portfolio=user_portfolio, user_cash=user_cash, current_worth=current_worth)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares_nbr = request.form.get("shares")

        # Ensure symbol is not blank
        if not symbol:
            return apology("MISSING SYMBOL", 400)

        # Validate shares
        try:
            shares_nbr = int(shares_nbr)
            if shares_nbr <= 0:
                return apology("SHARES MUST BE POSITIVE INTEGER", 400)
        except ValueError:
            return apology("INVALID SHARES", 400)

        # Lookup stock
        stock_quote = lookup(symbol)
        if not stock_quote:
            return apology("INVALID SYMBOL", 400)

        # Calculate total cost
        total_cost = shares_nbr * stock_quote["price"]

        # Check user's cash
        user_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        if user_cash < total_cost:
            return apology("CAN'T AFFORD", 400)

        # Perform the purchase
        db.execute(
            "INSERT INTO trades (id, symbol, name, shares, price) VALUES(?, ?, ?, ?, ?)",
            session["user_id"], stock_quote['symbol'], stock_quote['name'], shares_nbr, stock_quote['price']
        )
        db.execute(
            "UPDATE users SET cash = cash - ? WHERE id = ?",
            total_cost, session["user_id"]
        )

        flash('Bought!')
        return redirect("/")
    else:
        return render_template("buy.html")



@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # Retrieve all transactions for the user
    transactions = db.execute(
        "SELECT symbol, shares, price, transacted FROM trades WHERE id = ? ORDER BY transacted DESC",
        session["user_id"]
    )
    return render_template("history.html", transactions=transactions)



@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        symbol = request.form.get("symbol")
        # Ensure symbol is not blank
        if symbol == "":
            return apology("input is blank", 400)

        stock_quote = lookup(symbol)

        if not stock_quote:
            return apology("INVALID SYMBOL", 400)
        else:
            return render_template("quoted.html", symbol=stock_quote)

    # User reached route via GET
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Validate submission
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        # Ensure password == confirmation
        if not (password == confirmation):
            return apology("the passwords do not match", 400)

        # Ensure password not blank
        if password == "" or confirmation == "" or username == "":
            return apology("input is blank", 400)

        # Ensure username does not exists already
        if len(rows) == 1:
            return apology("username already exist", 400)
        else:
            hashcode = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
            db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, hashcode)

        # Redirect user to home page
        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        # Get form inputs
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        # Ensure symbol and shares are provided
        if not symbol:
            return apology("MISSING SYMBOL", 400)
        if not shares or not shares.isdigit() or int(shares) <= 0:
            return apology("INVALID SHARES", 400)

        shares = int(shares)

        # Query the user's portfolio for the stock
        stock = db.execute(
            "SELECT SUM(shares) AS total_shares FROM trades WHERE id = ? AND symbol = ? GROUP BY symbol",
            session["user_id"], symbol.upper()
        )

        # Check if the user owns the stock and has enough shares
        if not stock or stock[0]["total_shares"] < shares:
            return apology("TOO MANY SHARES", 400)

        # Get the current stock price
        stock_quote = lookup(symbol)
        if not stock_quote:
            return apology("INVALID SYMBOL", 400)

        # Calculate total sale value
        sale_value = shares * stock_quote["price"]

        # Record the sale in the trades table (negative shares indicate a sale)
        db.execute(
            "INSERT INTO trades (id, symbol, name, shares, price) VALUES (?, ?, ?, ?, ?)",
            session["user_id"], symbol.upper(), stock_quote["name"], -shares, stock_quote["price"]
        )

        # Update user's cash balance
        db.execute(
            "UPDATE users SET cash = cash + ? WHERE id = ?",
            sale_value, session["user_id"]
        )

        flash("Sold!")
        return redirect("/")

    else:
        # Fetch user's owned stocks for the dropdown
        stocks = db.execute(
            "SELECT symbol, SUM(shares) AS total_shares FROM trades WHERE id = ? GROUP BY symbol HAVING total_shares > 0",
            session["user_id"]
        )
        return render_template("sell.html", stocks=stocks)



@app.route("/settings")
@login_required
def settings():
    """Show settings"""
    # Query database
    username = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])
    return render_template("settings.html", username=username[0]['username'])


@app.route("/passwordupdate", methods=["GET", "POST"])
@login_required
def passwordupdate():
    """Show settings"""

    if request.method == "POST":

        # Validate submission
        currentpassword = request.form.get("currentpassword")
        newpassword = request.form.get("newpassword")
        confirmation = request.form.get("confirmation")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])

        # Ensure password == confirmation
        if not (newpassword == confirmation):
            return apology("the passwords do not match", 400)

        # Ensure password not blank
        if currentpassword == "" or newpassword == "" or confirmation == "":
            return apology("input is blank", 400)

       # Ensure password is correct
        if not check_password_hash(rows[0]["hash"], currentpassword):
            return apology("invalid password", 403)
        else:
            hashcode = generate_password_hash(newpassword, method='pbkdf2:sha256', salt_length=8)
            db.execute("UPDATE users SET hash = ? WHERE id = ?", hashcode, session["user_id"])

        # Redirect user to settings
        return redirect("/settings")

    else:
        return render_template("passwordupdate.html")
