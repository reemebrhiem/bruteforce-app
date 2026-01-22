Reem Ebrahem., [03/08/47 04:52 م]
from flask import Flask, render_template, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import pandas as pd
from datetime import datetime, timedelta
import os
import joblib

model, features = joblib.load("model.joblib")

app = Flask(__name__)
app.secret_key = "secret123"

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[]
)

USERS_FILE = "users.csv"
LOGS_FILE = "login_logs.csv"

FAILED_THRESHOLD = 3
BLOCK_MINUTES = 1

if not os.path.exists(USERS_FILE):
    pd.DataFrame(columns=["username", "password"]).to_csv(USERS_FILE, index=False)

if not os.path.exists(LOGS_FILE):
    pd.DataFrame(columns=["username", "success", "timestamp"]).to_csv(LOGS_FILE, index=False)

def load_logs():
    if os.path.getsize(LOGS_FILE) == 0:
        return pd.DataFrame(columns=["username", "success", "timestamp"])
    df = pd.read_csv(LOGS_FILE)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df

def save_log(username, success):
    df = load_logs()
    new = {
        "username": username,
        "success": success,
        "timestamp": datetime.now()
    }
    df = pd.concat([df, pd.DataFrame([new])], ignore_index=True)
    df.to_csv(LOGS_FILE, index=False)

def extract_features(username):
    df = load_logs()
    user_logs = df[df["username"] == username]

    if user_logs.empty:
        return [0, 0]

    attempts = len(user_logs)
    time_span = (user_logs["timestamp"].max() - user_logs["timestamp"].min()).seconds

    return [attempts, time_span]

def predict_attack(username):
    X = extract_features(username)
    prediction = model.predict([X])[0]
    return prediction == 1

@app.route("/")
def login_page():
    return render_template("login.html")

@app.route("/register", methods=["GET"])
def register_page():
    return render_template("register.html")

@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    password = request.form.get("password")

    users = pd.read_csv(USERS_FILE)

    if username in users["username"].values:
        return jsonify({"status": "error", "message": "اسم المستخدم موجود مسبقًا"})

    users = pd.concat([users, pd.DataFrame([{
        "username": username,
        "password": password
    }])], ignore_index=True)

    users.to_csv(USERS_FILE, index=False)

    return jsonify({"status": "success", "message": "تم إنشاء الحساب بنجاح"})

@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    if predict_attack(username):
        return "ATTACK DETECTED", 403

    users = pd.read_csv(USERS_FILE)

    if username not in users["username"].values:
        save_log(username, 0)
        return "FAILED", 401

    valid = users[
        (users["username"] == username) &
        (users["password"] == password)
    ]

    if not valid.empty:
        save_log(username, 1)
        return "SUCCESS", 200
    else:
        save_log(username, 0)
        return "FAILED", 401


@app.route("/dashboard/<username>")
def dashboard(username):
    return f"Welcome {username}"
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
