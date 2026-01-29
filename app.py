from flask import Flask, render_template, request, redirect
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import joblib
import os

print("DB URL FOUND:", bool(os.environ.get("DATABASE_URL")))

app = Flask(__name__)
app.secret_key = "secret123"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

model, features = joblib.load("model.joblib")

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

def extract_features(username):
    logs = LoginLog.query.filter_by(username=username).all()

    if not logs:
        return [0, 0]

    attempts = len(logs)
    times = [log.timestamp for log in logs]
    time_span = (max(times) - min(times)).seconds

    return [attempts, time_span]

def predict_attack(username):
    try:
        X = extract_features(username)
        return model.predict([X])[0] == 1
    except:
        return False

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
        return "USER EXISTS"

    user = User(username=username, password=password)
    db.session.add(user)
    db.session.commit()

    return redirect("/")

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]

    if predict_attack(username):
        return "ATTACK DETECTED"

    user = User.query.filter_by(username=username).first()

    if not user:
        save_log(username, 0)
        return "FAILED"

    if user.password == password:
        save_log(username, 1)
        return "SUCCESS"
    else:
        save_log(username, 0)
        return "FAILED"

@app.route("/dashboard/<username>")
def dashboard(username):
    logs = LoginLog.query.filter_by(username=username).all()
    return render_template("dashboard.html", username=username, logs=logs)
    
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)

