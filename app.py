import os
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from pytz import timezone, utc
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import apology, login_required, lookup, usd
from sqlalchemy.exc import SQLAlchemyError
import logging

# Initialize SQLAlchemy with null app
db = SQLAlchemy()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_app():
    app = Flask(__name__)
    
    try:
        # Load environment variables
        load_dotenv()
        
        # Configure application
        app.config["SESSION_PERMANENT"] = False
        app.config["SESSION_TYPE"] = "filesystem"
        
        # Configure PostgreSQL database
        app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        
        # Initialize extensions
        Session(app)
        db.init_app(app)
        
        # Custom filter
        app.jinja_env.filters["usd"] = usd
        
        with app.app_context():
            try:
                db.create_all()
                logger.info("Database tables created successfully")
            except Exception as e:
                logger.error(f"Database initialization error: {e}")
                
    except Exception as e:
        logger.error(f"Application initialization error: {e}")
    
    return app

app = create_app()

# Create models
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    hash = db.Column(db.String(255), nullable=False)
    cash = db.Column(db.Float, default=10000.00)

class Portfolio(db.Model):
    __tablename__ = 'portfolio'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    symbol = db.Column(db.String(10), nullable=False)
    company_name = db.Column(db.String(100))
    shares = db.Column(db.Integer, nullable=False)

class Transaction(db.Model):
    __tablename__ = 'transactions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    symbol = db.Column(db.String(10), nullable=False)
    shares = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    total_price = db.Column(db.Float, nullable=False)
    type = db.Column(db.String(4), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

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
    portfolio = Portfolio.query.filter_by(user_id=user_id).all()
    user = User.query.get(user_id)
    message = "You Hold Zero Stocks" if not portfolio else ""
    
    cur_stock_price = {}
    for item in portfolio:
        if not item.symbol:
            continue
        stock = lookup(item.symbol)
        if stock:
            cur_stock_price[item.symbol] = stock['price']

    return render_template(
        "index.html",
        portfolio=portfolio,
        cur_stock_price=cur_stock_price,
        username=user.username,
        cash=user.cash,
        message=message
    )


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    user_id = session["user_id"]
    user = User.query.get(user_id)

    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares_input = request.form.get("shares")

        if not symbol or not lookup(symbol):
            return apology("Invalid stock symbol")

        if not shares_input or not shares_input.isdigit():
            return apology("Number of shares is required and positive")
        
        shares = int(shares_input)
        if shares < 1:
            return apology("Shares must be a positive integer.")

        stockinfo = lookup(symbol)
        stock_price = stockinfo["price"]
        total_price = shares * stock_price

        if user.cash >= total_price:
            user.cash -= total_price
            
            # Add transaction
            transaction = Transaction(
                user_id=user_id,
                symbol=symbol.upper(),
                shares=shares,
                price=stock_price,
                total_price=total_price,
                type="BUY"
            )
            db.session.add(transaction)

            # Update portfolio
            portfolio_item = Portfolio.query.filter_by(
                user_id=user_id, symbol=symbol.upper()
            ).first()

            if portfolio_item:
                portfolio_item.shares += shares
            else:
                new_portfolio = Portfolio(
                    user_id=user_id,
                    symbol=symbol.upper(),
                    company_name=stockinfo["name"],
                    shares=shares
                )
                db.session.add(new_portfolio)

            try:
                db.session.commit()
                return redirect("/")
            except Exception as e:
                db.session.rollback()
                return apology("Transaction failed")

        return apology("Not enough cash!")

    return render_template("buy.html", cash=user.cash, usd=usd)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session['user_id']
    transactions = Transaction.query.filter_by(user_id=user_id).order_by(Transaction.timestamp.desc()).all()

    # Convert UTC to local timezone
    local_tz = timezone("America/New_York")
    for transaction in transactions:
        utc_time = transaction.timestamp
        transaction.local_timestamp = utc.localize(utc_time).astimezone(local_tz).strftime("%Y-%m-%d %I:%M:%S %p")

    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    session.clear()

    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide username", 403)
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        user = User.query.filter_by(username=request.form.get("username")).first()

        # Ensure username exists and password is correct
        if not user or not check_password_hash(user.hash, request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = user.id
        return redirect("/")

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
    if request.method == "POST":
        try:
            symbol = request.form.get("symbol")
            if not symbol:
                return apology("invalid symbol")

            quoteinfo = lookup(symbol)
            if not quoteinfo:
                return apology("No data found for the symbol")

            return render_template("quoted.html", quoteinfo=quoteinfo)

        except ValueError as e:
            return render_template("quote.html", error=str(e))
        except Exception as e:
            return render_template("quote.html", error="An unexpected error occurred")

    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirm_password = request.form.get("confirmation")

        if not username or not password:
            return apology("user name or password cannot be empty")
        elif password != confirm_password:
            return apology("Password not matched!")
        elif username[0].isdigit():
            return apology("Username cannot start with number")
        elif len(username) < 3 or len(username) > 15:
            message = "Username must be between 3 and 15 characters."
            return render_template("register.html", message=message)
        elif " " in password or "_" in password:
            message = "Password cannot contain spaces or underscores."
            return render_template("register.html", message=message)

        # Check if username exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return apology("Username already exists")

        # Create new user
        new_user = User(
            username=username,
            hash=generate_password_hash(password),
            cash=10000.00
        )
        
        try:
            db.session.add(new_user)
            db.session.commit()
            session["user_id"] = new_user.id
            return redirect("/")
        except Exception as e:
            db.session.rollback()
            return apology("Registration failed")

    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user_id = session['user_id']
    user = User.query.get(user_id)
    portfolio = Portfolio.query.filter_by(user_id=user_id).all()

    if request.method == "POST":
        shares_input = request.form.get("shares")
        symbol = request.form.get("symbol")

        if not symbol:
            return apology("Must select a stock")

        try:
            shares = int(shares_input)
            if shares < 1:
                raise ValueError
        except (ValueError, TypeError):
            return apology("Invalid number of shares")

        portfolio_item = Portfolio.query.filter_by(user_id=user_id, symbol=symbol.upper()).first()
        if not portfolio_item or portfolio_item.shares < shares:
            return apology("Not enough shares to sell", 400)

        stock = lookup(symbol)
        if not stock:
            return apology("Invalid stock symbol")

        profit = stock['price'] * shares
        user.cash += profit

        # Record transaction
        transaction = Transaction(
            user_id=user_id,
            symbol=symbol.upper(),
            shares=-shares,
            price=stock['price'],
            total_price=profit,
            type='SELL'
        )
        db.session.add(transaction)

        # Update portfolio
        if portfolio_item.shares == shares:
            db.session.delete(portfolio_item)
        else:
            portfolio_item.shares -= shares

        try:
            db.session.commit()
            return redirect("/")
        except Exception:
            db.session.rollback()
            return apology("Transaction failed")

    return render_template("sell.html", portfolio=portfolio, username=user.username)

# Error handler for database errors
@app.errorhandler(SQLAlchemyError)
def handle_db_error(error):
    logger.error(f"Database error: {str(error)}")
    return apology("A database error occurred", 500)

# General error handler
@app.errorhandler(Exception)
def handle_error(error):
    logger.error(f"Unhandled error: {str(error)}")
    return apology("An unexpected error occurred", 500)
