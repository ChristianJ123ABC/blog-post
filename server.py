#Sources:
#Passwords
    #OWASP's scrypt standard: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

#Security Logging + error handling
    #https://flask.palletsprojects.com/en/stable/errorhandling/
    #https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
    #https://docs.python.org/3/howto/logging.html
    #https://www.geeksforgeeks.org/python/logging-in-python/
    #Writing to a log: https://last9.io/blog/flask-logging/
    #Displaying logs in the last 24 hours: https://stackoverflow.com/questions/1888544/how-to-select-records-from-last-24-hours-using-sql

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

#Search bar
    #https://www.geeksforgeeks.org/python/using-request-args-for-a-variable-url-in-flask/
    #https://stackoverflow.com/questions/56387161/flask-search-bar-using-postgres


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
#Multi statements prevents several SQL statements from being executed in a single call
app.config["MYSQL_CUSTOM_OPTIONS"] = {"ssl_mode": "REQUIRED", "multi_statements": False}

#Session management
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=15)
app.config["SESSION_COOKIE_HTTPONLY"] = True #JavaScript cannot read the session cookie
app.config["SESSION_COOKIE_SAMESITE"] = "Lax" #Blocks cookies from being sent with POSTs from other websites
app.config["SESSION_COOKIE_SECURE"] = False #False since the app runs on 127.0.0.1 instead of HTTPs
app.secret_key = os.getenv("SECRET_KEY")
mysql = MySQL(app)

#Turn this to False in .env when testing with Zap and playwright
app.config["RATELIMIT_ENABLED"] = os.getenv("RATELIMIT_ENABLED","true").lower() == "true"

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
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("landing_page.html")




# - - - - - - -
# FUNCTIONS FOR FEATURES (ORDER: Logging, Access Control, Validation, Exception Handling)
# - - - - - - -

#Types of actions logged as WARNING
warningActions = ["failed_login", "forbidden", "failed_account_delete", "rejected_input", "csrf_failed", "rate_limited"]

def writeLog(action, userId=None):
    cursor = mysql.connection.cursor()
    cursor.execute("INSERT INTO logs (user_id, action, ip_address) VALUES (%s, %s, %s)", (userId, action, get_remote_address()))
    mysql.connection.commit()
    cursor.close()
    level = logging.WARNING if action in warningActions else logging.INFO
    #%r prints the path in quotes to prevent fake lines from being added to the URL
    securityLogger.log(level, "action=%s user_id=%s ip=%s path=%r", action, userId, get_remote_address(), request.path)


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

@app.errorhandler(werkzeug.exceptions.NotFound)
def handle_notfound_request(e):
    return "404 Page Not Found", 404

@app.errorhandler(werkzeug.exceptions.TooManyRequests)
def handle_rate_limit(e):
    writeLog("rate_limited", session.get("user_id"))
    return "429 Too Many Requests, try again later", 429

#Sends the log to .log file
@app.errorhandler(werkzeug.exceptions.InternalServerError)
def handle_server_error(e):
    securityLogger.error("server_error_type=%s", type(e.original_exception).__name__)
    return "500 Internal Server error", 500

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    writeLog("csrf_failed", session.get("user_id"))
    flash("Session expired, please try again", "warning")
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
        writeLog("rejected_input")
        flash("That password is on a list of commonly breached passwords, choose another one.", "danger")
        return render_template("register.html", username=username, email=email)

    if not validUsername(username) or not validEmail(email) or isPasswordValid(password) == False:
        writeLog("rejected_input")
        flash("Registration invalid: Check the username (3 to 50 letters, numbers or _), the email and the password (15 to 128 characters).", "danger")
        return render_template("register.html", username=username, email=email)

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT id FROM users WHERE username = %s OR email = %s", (username, email))
    #Same error message to avoid specifying what usernames / emails are registered
    if cursor.fetchone():
        cursor.close()
        writeLog("rejected_input")
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
@rateLimiter.limit("5 per minute", methods=["POST"])
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
    userId = session.get("user_id")
    session.clear()
    try:
        writeLog("logout", userId)
    except Exception:
        app.logger.exception("logout log failed")
    return redirect(url_for("login"))

#Displays users data held about them (GDPR Right of access)
@app.route("/account")
@loginRequired
def account():
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT username, email, created_at FROM users WHERE id = %s", (session["user_id"],))
    user = cursor.fetchone()
    cursor.close()
    return render_template("account.html", user=user)


#Deletes users account (GDPR right to erasure)
@app.route("/account/delete", methods=["POST"])
@rateLimiter.limit("5 per minute")
@loginRequired
def delete_account():
    password = request.form["password"]
    userId = session["user_id"]

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT hashed_password FROM users WHERE id = %s", (userId,))
    user = cursor.fetchone()

    if not check_password_hash(user["hashed_password"], password):
        cursor.close()
        writeLog("failed_account_delete", userId)
        flash("Password incorrect")
        return redirect(url_for("account"))

    writeLog("delete_account", userId)
    cursor.execute("DELETE FROM users WHERE id = %s", (userId,))
    mysql.connection.commit()
    cursor.close()

    session.clear()
    flash("Your account has been deleted, alongside your posts and comments", "success")
    return redirect(url_for("home"))

# - - - - - - - - - -
# POSTS AND COMMENTS (ORDER: Dashboard + Search, New Post, View Post, Edit Post, Delete Post, Comments, Admin Logs)
# - - - - - - - - - -
@app.route("/dashboard")
@loginRequired
def dashboard():
    search  = request.args.get("q", "").strip()[:100]
    cursor = mysql.connection.cursor()

    #Searchs and filters the posts by their title. If nothing is typed, it displays all posts
    if search:
        cursor.execute("SELECT p.id, p.title, p.created_at, u.username FROM posts p JOIN users u on p.user_id = u.id WHERE p.title LIKE %s ORDER BY p.created_at DESC", ("%" + search + "%",))
    else:
        cursor.execute("SELECT p.id, p.title, p.created_at, u.username FROM posts p JOIN users u ON p.user_id = u.id ORDER BY p.created_at DESC")
    posts = cursor.fetchall()
    cursor.close()

    return render_template("dashboard.html", posts=posts, search=search)


@app.route("/post/new", methods=["GET","POST"])
@loginRequired
def new_post():
    if request.method == "GET":
        return render_template("edit_post.html", title="", body="", ePostId=None) #ePostId is named that to not be confused with view_post's post_id.

    title = request.form["title"].strip()
    body = request.form["body"].strip()

    if not validPost(title,body):
        writeLog("rejected_input", session["user_id"])
        flash("Title must be between 1 and 150 characters and the body to be between 1 and 5000 characters.", "danger")
        return render_template("edit_post.html", title=title, body=body, ePostId=None)

    cursor = mysql.connection.cursor()
    cursor.execute("INSERT INTO posts (user_id, title, body) VALUES (%s, %s, %s)", (session["user_id"],title,body))
    mysql.connection.commit()
    newPostId = cursor.lastrowid
    cursor.close()

    writeLog("create_post", session["user_id"])
    return redirect(url_for("view_post", post_id=newPostId))


@app.route("/post/<int:post_id>")
@loginRequired
def view_post(post_id):
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT p.id, p.title, p.body, p.user_id, p.created_at, u.username FROM posts p JOIN users u ON p.user_id = u.id WHERE p.id = %s", (post_id,))
    post = cursor.fetchone()

    if not post:
        cursor.close()
        abort(404)

    cursor.execute("SELECT c.id, c.user_id, c.body, c.created_at, u.username FROM comments c JOIN users u ON c.user_id = u.id WHERE c.post_id = %s ORDER BY c.created_at", (post_id,))
    comments = cursor.fetchall()
    cursor.close()

    return render_template("view_post.html", post=post, comments=comments, userIsAdmin=isAdmin())

@app.route("/post/<int:post_id>/edit", methods=["GET","POST"])
@loginRequired
@rateLimiter.limit("5 per minute", methods=["POST"])
def edit_post(post_id):
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT id, title, body, user_id FROM posts WHERE id = %s", (post_id,))
    post = cursor.fetchone()
    cursor.close()

    if not post:
        abort(404)

    #Only the owner of the post can edit it
    if post["user_id"] != session["user_id"]:
        writeLog("forbidden", session["user_id"])
        abort(403)

    if request.method == "GET":
        return render_template("edit_post.html", title=post["title"], body=post["body"], ePostId=post_id)

    title = request.form["title"].strip()
    body = request.form["body"].strip()

    if not validPost(title,body):
        writeLog("rejected_input", session["user_id"])
        flash("Title must be between 1 and 150 characters and the body to be between 1 and 5000 characters.", "danger")
        return render_template("edit_post.html", title=title, body=body, ePostId=post_id)

    cursor = mysql.connection.cursor()
    cursor.execute("UPDATE posts SET title = %s, body = %s WHERE id = %s", (title, body, post_id))
    mysql.connection.commit()
    cursor.close()

    writeLog("edit_post", session["user_id"])
    flash("Post updated", "success")
    return redirect(url_for("view_post", post_id=post_id))



@app.route("/post/<int:post_id>/delete", methods=["POST"])
@loginRequired
@rateLimiter.limit("5 per minute", methods=["POST"])
def delete_post(post_id):
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT user_id FROM posts WHERE id = %s", (post_id,))
    post = cursor.fetchone()

    if not post:
        cursor.close()
        abort(404)

    #Only the owner of the post and an admin can delete the post
    if post["user_id"] != session["user_id"] and not isAdmin():
        cursor.close()
        writeLog("forbidden", session["user_id"])
        abort(403)


    cursor.execute("DELETE FROM posts WHERE id = %s", (post_id,))
    mysql.connection.commit()
    cursor.close()

    writeLog("delete_post", session["user_id"])
    flash("Post deleted", "success")
    return redirect(url_for("dashboard"))


@app.route("/post/<int:post_id>/comment", methods=["POST"])
@loginRequired
@rateLimiter.limit("5 per minute", methods=["POST"])
def add_comment(post_id):
    body = request.form["body"].strip()

    if not validComment(body):
        writeLog("rejected_input", session["user_id"])
        flash("Comments must be between 1 to 1000 characters", "danger")
        return redirect(url_for("view_post", post_id=post_id))

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT id FROM posts WHERE id = %s", (post_id,))
    if not cursor.fetchone():
        cursor.close()
        abort(404)

    cursor.execute("INSERT INTO comments (post_id, user_id, body) VALUES (%s,%s,%s)", (post_id, session["user_id"], body))
    mysql.connection.commit()

    cursor.close()
    writeLog("add_comment", session["user_id"])
    return redirect(url_for("view_post", post_id=post_id))

@app.route("/comment/<int:comment_id>/edit", methods=["GET","POST"])
@loginRequired
@rateLimiter.limit("5 per minute", methods=["POST"])
def edit_comment(comment_id):
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT id, post_id, user_id, body FROM comments WHERE id = %s", (comment_id,))
    comment = cursor.fetchone()
    cursor.close()

    if not comment:
        abort (404)

    if comment["user_id"] != session["user_id"]:
        writeLog("forbidden", session["user_id"])
        abort(403)

    if request.method == "GET":
        return render_template("edit_comment.html", comment=comment)

    body = request.form["body"].strip()

    if not validComment(body):
        writeLog("rejected_input", session["user_id"])
        flash("Comments must be between 1 and 1000 characters", "danger")
        return render_template("edit_comment.html", comment=comment)

    cursor = mysql.connection.cursor()
    cursor.execute("UPDATE comments SET body = %s WHERE id = %s", (body, comment_id))
    mysql.connection.commit()
    cursor.close()

    writeLog("edit_comment", session["user_id"])
    flash("Comment updated", "success")
    return redirect(url_for("view_post", post_id=comment["post_id"]))

@app.route("/comment/<int:comment_id>/delete", methods=["POST"])
@loginRequired
@rateLimiter.limit("5 per minute", methods=["POST"])
def delete_comment(comment_id):
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT post_id, user_id FROM comments WHERE id = %s", (comment_id,))
    comment = cursor.fetchone()

    if not comment:
        cursor.close()
        abort(404)

    #Only owner of comment can delete their comment besides an admin
    if comment["user_id"] != session["user_id"] and not isAdmin():
        cursor.close()
        writeLog("forbidden", session["user_id"])
        abort(403)

    cursor.execute("DELETE FROM comments WHERE id = %s", (comment_id,))
    mysql.connection.commit()
    cursor.close()

    writeLog("delete_comment", session["user_id"])
    flash("Comment deleted", "success")
    return redirect(url_for("view_post", post_id=comment["post_id"]))

#Displays 50 latest events that have occurred in the app and how many warnings happened in the last 24 hours
@app.route("/admin/logs")
@adminRequired
def admin_logs():
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT action, COUNT(*) AS total FROM logs WHERE created_at >= NOW() - INTERVAL 1 dAY GROUP BY action ORDER BY total DESC")
    summary = [row for row in cursor.fetchall() if row["action"] in warningActions] #Display on the warning actions
    cursor.execute("SELECT l.created_at, l.action, l.ip_address, u.username FROM logs l LEFT JOIN users u ON l.user_id = u.id ORDER BY l.id DESC LIMIT 50")
    logs = cursor.fetchall()
    cursor.close()
    return render_template("admin_logs.html", summary=summary, logs=logs, warningActions=warningActions)



#debug is OFF so error pages never show code
if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)