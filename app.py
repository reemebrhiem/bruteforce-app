from flask import Flask, render_template, request, redirect
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import joblib
import os

app = Flask(__name__)
app.secret_key = "secret123"

DATABASE_URL = os.environ.get("DATABASE_URL")

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

model, features = joblib.load("model.joblib")

FAILED_THRESHOLD = 3
BLOCK_SECONDS = 60

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)

class LoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50))
    success = db.Column(db.Integer)  # 1 نجاح – 0 فشل
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
    now = datetime.utcnow()

    logs = LoginLog.query.filter_by(
        username=username,
        success=0
    ).order_by(LoginLog.timestamp.desc()).all()

    if len(logs) < FAILED_THRESHOLD:
        return False, 0

    first_block_time = logs[FAILED_THRESHOLD - 1].timestamp
    diff = (now - first_block_time).seconds

    if diff < BLOCK_SECONDS:
        return True, BLOCK_SECONDS - diff

    return False, 0

def extract_features(username):
    logs = LoginLog.query.filter_by(username=username, success=0).all()

    if len(logs) < FAILED_THRESHOLD:
        return [len(logs), 0]

    times = [log.timestamp for log in logs[-FAILED_THRESHOLD:]]
    time_span = (max(times) - min(times)).seconds

    return [len(logs), time_span]


def predict_attack(username):
    try:
        X = extract_features(username)
        return model.predict([X])[0] == 1
    except:
        return False


@app.route("/")
def login_page():
    username = request.args.get("user")
    blocked = False
    remaining = 0

    if username:
        blocked, remaining = is_blocked(username)

    return render_template(
        "login.html",
        blocked=blocked,
        remaining=remaining
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username")
    password = request.form.get("password")

    blocked, remaining = is_blocked(username)
    if blocked:
        return f"BLOCKED:{remaining}", 403

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

    recent_fails = LoginLog.query.filter_by(
        username=username,
        success=0
    ).order_by(LoginLog.timestamp.desc()).limit(FAILED_THRESHOLD).all()

    if len(recent_fails) == FAILED_THRESHOLD:
        delta = datetime.utcnow() - recent_fails[0].timestamp
        if delta.seconds < BLOCK_MINUTES * 60:
            return f"BLOCKED:{BLOCK_MINUTES*60 - delta.seconds}", 403200


@app.route("/dashboard/<username>")
def dashboard(username):
    logs = LoginLog.query.filter_by(username=username).all()
    return render_template("dashboard.html", username=username, logs=logs)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)


