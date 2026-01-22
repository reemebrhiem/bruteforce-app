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
    pd.DataFrame(columns=["username", "success", "timestamp"]).to_csv(LOGS_FILE, index=False)


def load_logs():
    df = pd.read_csv(LOGS_FILE)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df

def save_log(username, success):
    df = load_logs()
    df = pd.concat([
        df,
        pd.DataFrame([{
            "username": username,
            "success": success,
            "timestamp": datetime.now()
        }])
    ], ignore_index=True)
    df.to_csv(LOGS_FILE, index=False)

def is_blocked(username):
    df = load_logs()
    window = datetime.now() - timedelta(minutes=BLOCK_MINUTES)

    recent = df[
        (df["username"] == username) &
        (df["timestamp"] >= window)
    ]

    failed = recent[recent["success"] == 0]
    return len(failed) >= FAILED_THRESHOLD

@app.route("/")
def login_page():
    return render_template("login.html")

@app.route("/register")
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

    if is_blocked(username):
        return "ATTACK DETECTED", 403

    users = pd.read_csv(USERS_FILE)

    if username not in users["username"].values:
        save_log(username, 0)
        return "FAILED", 401

    user = users[users["username"] == username]

    if user.iloc[0]["password"] == password:
        save_log(username, 1)
        return "SUCCESS", 200
    else:
        save_log(username, 0)
        return "FAILED", 401

@app.route("/dashboard/<username>")
def dashboard(username):
    return render_template("dashboard.html", username=username)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
