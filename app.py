from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import os

app = Flask(__name__)
app.secret_key = "secret123"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

FAILED_THRESHOLD = 3
BLOCK_MINUTES = 1

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)

class LoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50))
    success = db.Column(db.Integer)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip = db.Column(db.String(50))

with app.app_context():
    db.create_all()

def save_log(username, success):
    log = LoginLog(
        username=username,
        success=success,
        ip=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()

def is_blocked(username):
    window = datetime.utcnow() - timedelta(minutes=BLOCK_MINUTES)
    recent = LoginLog.query.filter(
        LoginLog.username == username,
        LoginLog.timestamp >= window,
        LoginLog.success == 0
    ).count()

    if recent >= FAILED_THRESHOLD:
        last_fail = LoginLog.query.filter_by(username=username, success=0)\
            .order_by(LoginLog.timestamp.desc()).first()
        remaining = 60 - int((datetime.utcnow() - last_fail.timestamp).total_seconds())
        return True, max(remaining, 0)

    return False, 0

@app.route("/")
def login_page():
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form["username"]
    password = request.form["password"]

    if User.query.filter_by(username=username).first():
        return "EXISTS", 409

    user = User(username=username, password=password)
    db.session.add(user)
    db.session.commit()

    return "CREATED", 201

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]

    blocked, seconds = is_blocked(username)
    if blocked:
        return f"BLOCKED:{seconds}", 403

    user = User.query.filter_by(username=username).first()

    if not user:
        save_log(username, 0)
        return "NO_USER"

    if user.password == password:
        save_log(username, 1)
        return "SUCCESS"
    else:
        save_log(username, 0)
        return "WRONG_PASSWORD"

@app.route("/dashboard/<username>")
def dashboard(username):
    logs = LoginLog.query.filter_by(username=username).order_by(LoginLog.timestamp.desc()).all()

    total_attempts = len(logs)
    failed_attempts = len([l for l in logs if l.success == 0])
    success_attempts = len([l for l in logs if l.success == 1])

    last_ip = logs[0].ip if logs else "N/A"

    return render_template(
        "dashboard.html",
        username=username,
        total=total_attempts,
        failed=failed_attempts,
        success=success_attempts,
        last_ip=last_ip,
        logs=logs[:10]    
    )

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)

