from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy
import numpy as np
from datetime import datetime, timedelta
import os
import joblib

app = Flask(__name__)

model = None
try:
    if os.path.exists("model.joblib"):
        model, features_list = joblib.load("model.joblib")

except:
    model = None

DATABASE_URL = os.environ.get("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL or "sqlite:///site.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

FAILED_THRESHOLD = 3   
BLOCK_MINUTES = 1       
MAX_LOGS = 80           
ML_THRESHOLD = 0.7      

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
    try:
        count = LoginLog.query.count()
        if count > MAX_LOGS:
            to_delete = count - MAX_LOGS
            old_logs = LoginLog.query.order_by(LoginLog.timestamp.asc()).limit(to_delete).all()
            for log in old_logs:
                db.session.delete(log)
            db.session.commit()
    except:
        db.session.rollback()

def get_client_ip():
    ip = request.headers.get("X-Forwarded-For", "")
    if ip:
        return ip.split(",")[0]
    return request.remote_addr or "127.0.0.1"

def is_automated_tool():
    ua = request.headers.get("User-Agent", "").lower()
    automated_keywords = ["hydra", "curl", "burp", "sqlmap", "wget", "python", "requests"]
    return ua == "" or any(keyword in ua for keyword in automated_keywords)

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
        return True
    except:
        db.session.rollback()
        return False

def is_blocked(username):
    try:
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
    except:
        return False, 0

def predict_with_ml(username, ip_address):
    if model is None:
        return False, 0.0
    
    try:
        now = datetime.utcnow()
        five_min_ago = now - timedelta(minutes=5)
        
        failed_user_5min = LoginLog.query.filter(
            LoginLog.username == username,
            LoginLog.success == 0,
            LoginLog.timestamp >= five_min_ago,
            LoginLog.timestamp < now
        ).count()
        
        is_attack = failed_user_5min >= 5

        confidence = min(failed_user_5min / 10, 1.0)
        
        return is_attack, confidence
    except:
        return False, 0.0

@app.route("/")
def login_page():
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    if len(username) < 3 or len(password) < 3:
        return "INVALID"

    if User.query.filter_by(username=username).first():
        return "EXISTS"

    try:
        user = User(username=username, password=password)
        db.session.add(user)
        db.session.commit()
        save_log(username, 1)
        return "CREATED"
    except:
        db.session.rollback()
        return "ERROR"

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    client_ip = get_client_ip()

    if not username or not password:
        save_log("unknown", 0)
        return "ERROR"

    blocked, seconds = is_blocked(username)
    if blocked:
        save_log(username, 0)
        return f"BLOCKED:{seconds}"

    is_attack_ml, ml_confidence = predict_with_ml(username, client_ip)
    if is_attack_ml and ml_confidence >= ML_THRESHOLD:
        save_log(username, 0)
        return f"BLOCKED:60"

    if is_automated_tool():
        save_log(username, 0)
        return "WRONG_PASSWORD"

    user = User.query.filter_by(username=username).first()
    if not user:
        save_log(username, 0)
        return "NO_USER"

    if user.password != password:
        save_log(username, 0)
        return "WRONG_PASSWORD"

    save_log(username, 1)
    return "SUCCESS"

@app.route("/dashboard/<username>")
def dashboard(username):
    return render_template("dashboard.html", username=username)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False)

