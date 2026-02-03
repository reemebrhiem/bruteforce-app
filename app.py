from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import os
import joblib

app = Flask(__name__)
app.secret_key = "secret123"

model, features = joblib.load("model.joblib")

app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

FAILED_THRESHOLD = 3
BLOCK_MINUTES = 1
MAX_LOGS = 80

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)

class LoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50))
    success = db.Column(db.Integer)  # 1 = نجاح | 0 = فشل
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip = db.Column(db.String(50))

with app.app_context():
    db.create_all()

def cleanup_logs():
    count = LoginLog.query.count()
    if count > MAX_LOGS:
        to_delete = count - MAX_LOGS
        old_logs = LoginLog.query.order_by(LoginLog.timestamp.asc()).limit(to_delete).all()
        for log in old_logs:
            db.session.delete(log)
        db.session.commit()

def get_client_ip():
    ip = request.headers.get("X-Forwarded-For", "")
    if ip:
        return ip.split(",")[0]
    return request.remote_addr

def save_log(username, success):
    try:
        cleanup_logs()
        log = LoginLog(
            username=username,
            success=success,
            ip=get_client_ip()
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print("LOG ERROR:", e)

def is_blocked(username):
    window = datetime.utcnow() - timedelta(minutes=BLOCK_MINUTES)

    fails = LoginLog.query.filter(
        LoginLog.username == username,
        LoginLog.success == 0,
        LoginLog.timestamp >= window
    ).order_by(LoginLog.timestamp.asc()).all()

    if len(fails) < FAILED_THRESHOLD:
        return False, 0

    first_fail = fails[0].timestamp
    unblock_time = first_fail + timedelta(minutes=BLOCK_MINUTES)
    remaining = int((unblock_time - datetime.utcnow()).total_seconds())

    return True, max(remaining, 0)

@app.route("/")
def login_page():
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username")
    password = request.form.get("password")

    if not username or not password:
        return "ERROR", 400

    if User.query.filter_by(username=username).first():
        return "EXISTS", 409

    user = User(username=username, password=password)
    db.session.add(user)
    db.session.commit()

    return "CREATED", 201

@app.route("/login", methods=["POST"])
def login():
    try:
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            return "ERROR"

        blocked, seconds = is_blocked(username)
        if blocked:
            return f"BLOCKED:{seconds}"

        user = User.query.filter_by(username=username).first()

        if not user:
            save_log(username, 0)
            return "NO_USER"

        if user.password != password:
            save_log(username, 0)
            return "WRONG_PASSWORD"

        save_log(username, 1)
        return "SUCCESS"

    except Exception as e:
        print("LOGIN ERROR:", e)
        return "ERROR"

@app.route("/dashboard/<username>")
def dashboard(username):
    return render_template("dashboard.html", username=username)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
