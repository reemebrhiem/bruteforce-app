from flask import Flask, render_template, request
import pandas as pd
from datetime import datetime, timedelta
import os
import joblib

model, features = joblib.load("model.joblib")

app = Flask(__name__)
app.secret_key = "secret123"

USERS_FILE = "users.csv"
LOGS_FILE = "login_logs.csv"

FAILED_THRESHOLD = 3
BLOCK_MINUTES = 1

if not os.path.exists(USERS_FILE):
    pd.DataFrame(columns=["username", "password"]).to_csv(USERS_FILE, index=False)

if not os.path.exists(LOGS_FILE):
    pd.DataFrame(columns=["username", "success", "timestamp", "ip"]).to_csv(LOGS_FILE, index=False)
    
def load_logs():
    if not os.path.exists(LOGS_FILE) or os.path.getsize(LOGS_FILE) == 0:
        return pd.DataFrame(columns=["username", "success", "timestamp", "ip"])
    df = pd.read_csv(LOGS_FILE)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df

def save_log(username, success):
    df = load_logs()

    ip = request.remote_addr
    new = {
        "username": username,
        "success": success,
        "timestamp": datetime.now(),
        "ip": ip
    }

    df = pd.concat([df, pd.DataFrame([new])], ignore_index=True)
    df.to_csv(LOGS_FILE, index=False)

def extract_features(username):
    df = load_logs()
    user = df[df["username"] == username]

    if user.empty:
        return [0, 0]

    attempts = len(user)
    time_span = (user["timestamp"].max() - user["timestamp"].min()).seconds
    return [attempts, time_span]

def threshold_attack(username):
    df = load_logs()
    window = datetime.now() - timedelta(minutes=BLOCK_MINUTES)
    recent = df[(df["username"] == username) & (df["timestamp"] >= window)]
    failed = recent[recent["success"] == 0]
    return len(failed) >= FAILED_THRESHOLD

def predict_attack(username):
    X = extract_features(username)
    try:
        return model.predict([X])[0] == 1
    except:
        return False

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
        return "EXISTS", 409

    users = pd.concat([
        users,
        pd.DataFrame([{"username": username, "password": password}])
    ], ignore_index=True)

    users.to_csv(USERS_FILE, index=False)
    return "CREATED", 201

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    if predict_attack(username):
        return "ATTACK"

    users = pd.read_csv(USERS_FILE)

    if username not in users["username"].values:
        save_log(username, 0)
        return "FAILED"

    valid = users[
        (users["username"] == username) &
        (users["password"] == password)
    ]

    if not valid.empty:
        save_log(username, 1)
        return "SUCCESS"
    else:
        save_log(username, 0)
        return "FAILED"
        
@app.route("/dashboard/<username>")
def dashboard(username):
    return render_template("dashboard.html", username=username)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)





