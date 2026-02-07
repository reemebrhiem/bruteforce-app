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
        print(f"DEBUG: Log saved - User: {username}, Success: {success}, IP: {get_client_ip()}")
    except Exception as e:
        db.session.rollback()
        print(f"LOG ERROR: {e}")

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

def extract_behavioral_features(username):
    window = datetime.utcnow() - timedelta(minutes=5)
    
    logs = LoginLog.query.filter(
        LoginLog.username == username,
        LoginLog.timestamp >= window
    ).order_by(LoginLog.timestamp.asc()).all()
    
    if len(logs) < 2:
        return None
    
    features = []
    failed_attempts = sum(1 for log in logs if log.success == 0)
    features.append(failed_attempts)
    
    if len(logs) > 1:
        time_diffs = []
        for i in range(1, len(logs)):

diff = (logs[i].timestamp - logs[i-1].timestamp).total_seconds()
            time_diffs.append(diff)
        avg_time_diff = sum(time_diffs) / len(time_diffs) if time_diffs else 0
        features.append(avg_time_diff)
    
    ip_counts = {}
    for log in logs:
        ip_counts[log.ip] = ip_counts.get(log.ip, 0) + 1
    
    unique_ips = len(ip_counts)
    features.append(unique_ips)
    
    return features

@app.route("/")
def login_page():
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    if not username or not password:
        return "ERROR", 400
    
    if len(username) < 3 or len(password) < 3:
        return "INVALID", 400

    if User.query.filter_by(username=username).first():
        return "EXISTS", 409

    user = User(username=username, password=password)
    db.session.add(user)
    db.session.commit()
    
    save_log(username, 1)

    return "CREATED", 201

@app.route("/login", methods=["POST"])
def login():
    try:
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:
            save_log("invalid_input", 0)
            return "WRONG_PASSWORD"     

        blocked, seconds = is_blocked(username)
        if blocked:
            save_log(username, 0)     
            return f"BLOCKED:{seconds}"

        user = User.query.filter_by(username=username).first()

        behavioral_features = extract_behavioral_features(username)
        
        ml_prediction = "normal"
        if behavioral_features and model:
            try:
                pass
            except Exception as e:
                print(f"ML Model Error: {e}")

        if is_automated_tool():
            save_log(username, 0)
            return "WRONG_PASSWORD"    

        if not user or user.password != password:
            save_log(username, 0)
            return "WRONG_PASSWORD"  

        save_log(username, 1)
        return "SUCCESS"

    except Exception as e:
        print(f"LOGIN ERROR: {e}")
        save_log("system_error", 0)
        return "ERROR"

@app.route("/dashboard/<username>")
def dashboard(username):
    return render_template("dashboard.html", username=username)

@app.route("/logs")
def view_logs():
    logs = LoginLog.query.order_by(LoginLog.timestamp.desc()).limit(20).all()
    
    log_list = []
    for log in logs:
        log_list.append({
            'username': log.username,
            'success': 'ناجح' if log.success == 1 else 'فاشل',
            'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'ip': log.ip
        })
    
    return render_template("logs.html", logs=log_list)

@app.route("/stats")
def statistics():
    total_logs = LoginLog.query.count()
    successful_logs = LoginLog.

query.filter_by(success=1).count()
    failed_logs = LoginLog.query.filter_by(success=0).count()
    
    user_attempts = db.session.query(
        LoginLog.username,
        db.func.count(LoginLog.id).label('attempts')
    ).group_by(LoginLog.username).order_by(db.desc('attempts')).limit(10).all()
    
    stats = {
        'total': total_logs,
        'successful': successful_logs,
        'failed': failed_logs,
        'success_rate': (successful_logs / total_logs * 100) if total_logs > 0 else 0,
        'top_users': user_attempts
    }
    
    return render_template("stats.html", stats=stats)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=True)
