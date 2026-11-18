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