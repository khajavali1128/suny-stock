import os

from datetime import datetime
from pytz import timezone, utc

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
    user_id = session["user_id"]
    portfolio = db.execute("SELECT * FROM portfolio WHERE user_id = ?", user_id)
    username = db.execute("SELECT username FROM users WHERE id = ?", user_id)[0]['username']
    user_cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
    message = ""
    if len(portfolio) == 0:
        message = "You Hold Zero Stocks"
    cur_stock_price = {}  # current prices of each stock of each company stored as symbol = "price"
    for row in portfolio:  # iterate through every row got from database of portfolio and then find the current price of the company and then assign them to cur_stock_price dictionary
        if not row['symbol']:  # Skip rows with invalid symbols
            continue
        stock = lookup(row['symbol'])
        if stock:
            cur_stock_price[row['symbol']] = stock['price']

    return render_template(
        "index.html",
        portfolio=portfolio,
        cur_stock_price=cur_stock_price,
        usd=usd,
        username=username,
        cash=user_cash,
        message=message
    )


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    user_id = session["user_id"]
    user_cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
    # via POST
    if request.method == "POST":
        # Retrieve form inputs
        symbol = request.form.get("symbol")

        shares_input = request.form.get("shares")

        # Validate symbol
        if not symbol or not lookup(symbol):
            return apology("Invalid stock symbol")

        # Validate shares
        if not shares_input or not shares_input.isdigit():
            return apology("Number of shares is required and positive")
        else:
            shares = int(shares_input)
            if shares < 1:
                return apology("Shares must be a positive integer.")

        stockinfo = lookup(symbol)

        # check the each stock price
        stock_price = stockinfo["price"]

        # total price for the current purchase
        total_price = shares * stock_price

        # check if user has enough money for that price
        if user_cash >= total_price:
            # Update user cash balance
            db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", total_price, user_id)
            # Track transaction
            db.execute("INSERT INTO transactions (user_id, symbol, shares, price, total_price, type) VALUES (?, ?, ?, ?, ?, ?)",
                       user_id, symbol.upper(), shares, stock_price, total_price, "BUY")

            # Insert into portfolio
            existing_portfolio = db.execute(
                "SELECT shares FROM portfolio WHERE user_id = ? AND symbol = ?", user_id, symbol.upper())
            if existing_portfolio:
                # Update existing portfolio
                cur_shares = existing_portfolio[0]["shares"]
                db.execute("UPDATE portfolio SET shares = ? WHERE user_id = ? AND symbol = ?",
                           cur_shares + shares, user_id, symbol.upper())
            else:
                # Insert new stock into the portfolio
                db.execute("INSERT INTO portfolio (user_id, symbol, company_name, shares) VALUES(?, ?, ?, ?)",
                           user_id, symbol.upper(), stockinfo["name"], shares)
            return redirect("/")

        else:
            # Render the form again with an error message
            return apology("Not enough cash!")
    return render_template("buy.html", cash=user_cash, usd=usd)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session['user_id']
    transactions = db.execute(
        "SELECT * FROM transactions WHERE user_id = ? ORDER BY timestamp DESC", user_id)

    # Convert UTC to the user's local timezone
    local_tz = timezone("America/New_York")  # Replace with desired timezone
    for transaction in transactions:
        utc_time = datetime.strptime(transaction["timestamp"], "%Y-%m-%d %H:%M:%S")
        transaction["local_timestamp"] = utc.localize(
            utc_time).astimezone(local_tz).strftime("%Y-%m-%d %I:%M:%S %p")

    return render_template("history.html", transactions=transactions, usd=usd)


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
    # Render the form if it's a POST request
    if request.method == "POST":
        try:
            symbol = request.form.get("symbol")
            if not symbol:
                return apology("invalid symbol")

            quoteinfo = lookup(symbol)

            if not quoteinfo:
                return apology("No data found for the symbol")

            return render_template("quoted.html", quoteinfo=quoteinfo, usd=usd)

        except ValueError as e:
            return render_template("quote.html", error=str(e))

        except Exception as e:
            return render_template("quote.html", error="An unexpected error occurred")

    # Render the form if it's a GET request
    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirm_password = request.form.get("confirmation")

        # Validate username
        if not username or not password:
            return apology("user name or password cannot be empty")
        elif password != confirm_password:
            return apology("Password not matched!")
        elif username[0].isdigit():
            return apology("Username cannot start with number")
        elif len(username) < 3 or len(username) > 15:
            message = "Username must be between 3 and 15 characters."
        elif " " in password or "_" in password:
            message = "Password cannot contain spaces or underscores."
        else:
            # Hash the password
            hashed_password = generate_password_hash(password)

            # Check if username already exists
            try:
                db.execute("INSERT INTO users (username, hash) VALUES(?, ?)",
                           username, hashed_password)
                user_id = db.execute("SELECT id FROM users WHERE username = ?", username)[0]["id"]
                # db.execute("INSERT INTO portfolio (user_id) VALUES(?)", user_id)
                session["user_id"] = user_id
                return redirect("/")
            except ValueError:
                return apology("Username already exists. Choose a different username.")

        return render_template("register.html", message=message)
    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user_id = session['user_id']
    portfolio = db.execute("SELECT * FROM portfolio WHERE user_id = ?", user_id)
    username = db.execute("SELECT username FROM users WHERE id = ?", user_id)[0]['username']
    if request.method == "POST":

        # Get the profit
        shares_input = request.form.get("shares")
        symbol = request.form.get("symbol")

        # Validate symbol
        if not symbol:
            return apology("Must select a stock")

        # Validate shares
        try:
            shares = int(shares_input)
            if shares < 1:
                raise ValueError
        except (ValueError, TypeError):
            return apology("Invalid number of shares")

        cur_shares = db.execute(
            "SELECT shares FROM portfolio WHERE user_id = ? AND symbol = ?", user_id, symbol.upper())
        if not cur_shares or cur_shares[0]["shares"] < shares:
            return apology("Not enough shares to sell", 400)

        # Perform sale
        stock = lookup(symbol)
        if not stock:
            return apology("Invalid stock symbol")

        profit = stock['price'] * shares
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", profit, user_id)

        # Track the transaction
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, total_price, type) VALUES(?, ?, ? ,? ,? ,?)",
                   user_id, symbol.upper(), -shares, stock['price'], profit, 'SELL')

        # Update the portfolio
        if cur_shares[0]["shares"] == shares:
            db.execute("DELETE FROM portfolio WHERE user_id = ? AND symbol = ?", user_id, symbol)
        else:
            db.execute("UPDATE portfolio SET shares = shares - ? WHERE user_id = ? AND symbol = ?",
                       shares, user_id, symbol.upper())

        return redirect("/")

    return render_template("sell.html", portfolio=portfolio, username=username)
