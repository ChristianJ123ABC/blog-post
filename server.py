#Sources:
#Passwords
    #OWASP's scrypt standard: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

#Security Logging + error handling
    #https://flask.palletsprojects.com/en/stable/errorhandling/
    #https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
    #https://docs.python.org/3/howto/logging.html
    #https://www.geeksforgeeks.org/python/logging-in-python/
    #Writing to a log: https://last9.io/blog/flask-logging/

#Security Headers + Session management
    #https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
    #https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
    # CSP Headers: https://community.owasp.org/controls/Content_Security_Policy
    #https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers#security

#Required decorator pattern for login + admin
    #https://flask.palletsprojects.com/en/stable/patterns/viewdecorators/

#Input validation
    #OWASP REGEX: https://community.owasp.org/OWASP_Validation_Regex_Repository
    #https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html
    #Regex Tester: https://regex101.com/
    #Exception handling: https://werkzeug.palletsprojects.com/en/stable/exceptions/

    #Passwords
        #NIST SP800-63B-4: https://pages.nist.gov/800-63-4/sp800-63b.html
        #100,000 commonly breached passwords: https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt



import re, os, logging, werkzeug
from functools import wraps
from flask import Flask, render_template, redirect, url_for, request, session, flash, abort
from flask_wtf.csrf import CSRFProtect, CSRFError
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mysqldb import MySQL
from datetime import timedelta
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
load_dotenv(override=True)

app = Flask(__name__, template_folder='templates')
csrf = CSRFProtect(app) 

#Database setup
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')
app.config['MYSQL_PORT'] = int(os.getenv('MYSQL_PORT'))
app.config["MYSQL_CHARSET"] = os.getenv("MYSQL_CHARSET") 
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static/uploads')

#Encrypts connection to railway with TLS (prevents emails and password from being sent to railway in plaintext) (Refuses to connect without it)
app.config["MYSQL_CUSTOM_OPTIONS"] = {"ssl_mode": "REQUIRED"}

#Session management
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=15)
app.config["SESSION_COOKIE_HTTPONLY"] = True #JavaScript cannot read the session cookie
app.config["SESSION_COOKIE_SAMESITE"] = "Lax" #Blocks cookies from being sent with POSTs from other websites
app.config["SESSION_COOKIE_SECURE"] = False #False since the app runs on 127.0.0.1 instead of HTTPs
app.secret_key = os.getenv("SECRET_KEY")
mysql = MySQL(app)

#Turn this to False in .env when testing with Zap and playwright
app.config["RATELIMIT_ENABLED"] = os.getenv("RATELIMIT_ENABLED", "true" == "true")
rateLimiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://",
)

#OWASP recommendation: scrypt memory cost has to be a minimum of 131072, Werkzeug's is 32768. This makes it more secure, but hashes are created slower.
hashMethod = "scrypt:131072:8:1"



#Security Logs: dockerfile makes it so that the app can write changes into a .log file whenever it occurs
os.makedirs("logs", exist_ok=True)
logFormat = logging.Formatter("%(asctime)s %(levelname)s %(message)s") #DATE, WARNING/INFO/DANGER, Message
fileHandler = logging.FileHandler("logs/app.log")
fileHandler.setFormatter(logFormat)
consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(logFormat)
securityLogger = logging.getLogger("security")
securityLogger.setLevel(logging.INFO) #default log if not specified
securityLogger.addHandler(fileHandler)
securityLogger.addHandler(consoleHandler)

#Security headers after every response
@app.after_request
def add_headers(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'" #Only loads file from this site and blocks inline scripts (e.g. onclick=alert()) (XSS FIX)
    response.headers["X-Content-Type-Options"] = "nosniff" #stops browser from guessing file format (XSS fix)
    response.headers["X-Frame-Options"] = "DENY" #Prevents clickjacking (loading a web page inside <frame>, <embed>, etc)
    response.headers["Referrer-Policy"] = "no-referrer" #URLs are not sent to other sites
    response.headers["Cache-Control"] = "no-store" #Pages are not kept by browser after log out
    return response

@app.route("/")
def home():
    return render_template("landing_page.html")




# - - - - - - -
# FUNCTIONS FOR FEATURES (ORDER: Logging, Access Control, Validation, Exception Handling)
# - - - - - - -

#Types of actions logged as WARNING
warningActions = ["failed_login", "forbidden", "failed_account_delete"]

def writeLog(action, userId=None):
    cursor = mysql.connection.cursor()
    cursor.execute("INSERT INTO logs (user_id, action, ip_address) VALUES (%s, %s, %s)", (userId, action, get_remote_address()))
    mysql.connection.commit()
    cursor.close()
    level = logging.WARNING if action in warningActions else logging.INFO
    securityLogger.log(level, "action=%s user_id=%s ip=%s", action, userId, get_remote_address())


#Decorator Patterns:  checks if the user is logged in or if an admin is required. these are re-used with every route that needs it.
def loginRequired(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("You need to be logged in.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

def isAdmin():
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT role FROM users WHERE id = %s", (session["user_id"],))
    user = cursor.fetchone()
    cursor.close()
    return user is not None and user["role"] == "admin"


def adminRequired(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        if not isAdmin():
            writeLog("forbidden", session["user_id"])
            abort(403)
        return view(*args, **kwargs)
    return wrapped


#3-50 characters. allows letters numbers and underscores
def validUsername(username):
    return re.match(r'^[A-Za-z0-9_]{3,50}$', username)

#Format: mail@domain.com / name.last@domain.com
def validEmail(email):
    return re.match(r'^[a-zA-Z0-9_+&*-]+(?:\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,7}$', email)

#Follows NIST SP800-63B-4 Policy: (minimum 15 characters, maximum 128 characters, no commonly breached passwords)
def isPasswordValid(password):
    if len(password) < 15 or len(password) > 128:
        return False

    with open("data/passwords.txt", encoding="utf-8", errors="ignore") as textFile: #errors ignore skips malformed lines
        for line in textFile:
            if line.strip().lower() == password.lower():
                return "breached"
            
    return True

def validPost(title, body):
    return 0 < len(title) <= 150 and 0 < len(body) <= 5000


def validComment(body):
    return 0 < len(body) <= 1000



#Exception Handling for error codes
@app.errorhandler(werkzeug.exceptions.Forbidden)
def handle_forbidden(e):
    return "403 Forbidden", 403

@app.errorhandle(werkzeug.exceptions.NotFound)
def handle_notfound_request(e):
    return "404 Page Not Found", 404

@app.errorhandler(werkzeug.exceptions.TooManyRequests)
def handle_rate_limit(e):
    return "429 Too Many Requests, try again later", 429

#Sends the log to .log file
@app.errorhandler(werkzeug.exceptions.InternalServerError)
def handle_server_error(e):
    securityLogger.error("server_error_type=%s", type(e.original_exception).__name__)
    return "500 Internal Server error", 500

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash(e.description, "warning")
    return redirect(url_for("home"))





# - - - - - - -
#   USER ACCOUNTS (ORDER: Register, Login, Logout, Account, Delete Account)
# - - - - - - -
@app.route("/register", methods=["GET", "POST"])
@rateLimiter.limit("5 per minute", methods=["POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form["username"].strip()
    email = request.form["email"].strip().lower()
    password = request.form["password"]

    if isPasswordValid(password) == "breached":
        flash("That password is on a list of commonly breached passwords, choose another one.", "danger")
        return render_template("register.html", username=username, email=email)

    if not validUsername(username) or not validEmail(email) or isPasswordValid(password) == False:
        flash("Registration invalid: Check the username (3 to 50 letters, numbers or _), the email and the password (15 to 128 characters).", "danger")
        return render_template("register.html", username=username, email=email)

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT id FROM users WHERE username = %s OR email = %s", (username, email))
    #Same error message to avoid specifying what usernames / emails are registered
    if cursor.fetchone():
        cursor.close()
        flash("Registration invalid: Check the username (3 to 50 letters, numbers or _), the email and the password (15 to 128 characters).", "danger")
        return render_template("register.html", username=username, email=email)

    #Password hash using scrypt 131072:8:1
    cursor.execute("INSERT INTO users (username, email, hashed_password) VALUES (%s, %s, %s)", (username, email, generate_password_hash(password, method=hashMethod)))
    mysql.connection.commit()
    newUserId = cursor.lastrowid
    cursor.close()

    writeLog("register", newUserId)
    flash("Account Created, please log in", "success")
    return redirect(url_for("login"))

@app.route("/login", methods=["GET","POST"])
@rateLimiter.limit("5 per minute", methods=["GET","POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    email = request.form["email"].strip().lower()
    password = request.form["password"]

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT id, username, role, hashed_password FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    cursor.close()

    #Same message for wrong email and password to prevent enumeration attack
    if not user or not check_password_hash(user["hashed_password"], password):
        writeLog("failed_login", user["id"] if user else None)
        flash("Invalid email or password.", "danger")
        return render_template("login.html")

    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]
    session.permanent = True
    writeLog("login", user["id"])
    return redirect(url_for("dashboard"))


#POST so CSRF can stop other websites from logging the user out with a link
@app.route("/logout", methods=["POST"])
def logout():
    if "user_id" in session:
        writeLog("logout", session["user_id"])
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))