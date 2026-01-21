from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import Flask, render_template, request, jsonify
import pandas as pd
from datetime import datetime, timedelta
import os
import joblib

model, features = joblib.load("model.joblib")


app = Flask(__name__)
app.secret_key = "secret123"

limiter = Limiter(
    get_remote_address,
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
    new_row = {
        "username": username,
        "success": success,
        "timestamp": datetime.now()
    }
    df = pd.concat([df, pd.DataFrame([new_row])], ignore_index=True)
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
    username = request.form["username"]
    password = request.form["password"]

    users = pd.read_csv(USERS_FILE)

    if username in users["username"].values:
        return jsonify({
            "status": "error",
            "message": "اسم المستخدم موجود مسبقًا"
        })

    users = pd.concat([
        users,
        pd.DataFrame([{
            "username": username,
            "password": password
        }])
    ], ignore_index=True)

    users.to_csv(USERS_FILE, index=False)

    return jsonify({
        "status": "success",
        "message": "تم إنشاء الحساب بنجاح"
    }),200

@app.route("/login", methods=["POST"])
@limiter.limit("3 per minute") 
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    if is_blocked(username):
        return jsonify({
            "status": "blocked",
            "message": "تم حظر الدخول لمدة دقيقة بسبب محاولات متكررة"
        }), 429

    users = pd.read_csv(USERS_FILE)

    if username not in users["username"].values:
        save_log(username, 0)
        return jsonify({
            "status": "error",
            "message": "اسم المستخدم غير موجود"
        }),404

    real_password = users.loc[
        users["username"] == username, "password"
    ].values[0]

    if password == real_password:
        save_log(username, 1)
        return jsonify({
            "status": "success",
            "redirect": f"/dashboard/{username}"
        })
    else:
        save_log(username, 0)
        return jsonify({
            "status": "error",
            "message": "كلمة المرور غير صحيحة"
        })

@app.route("/dashboard/<username>")
def dashboard(username):
    return render_template("dashboard.html", username=username)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)




