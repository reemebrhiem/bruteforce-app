from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import joblib
import os

app = Flask(__name__)
app.secret_key = "secret123"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

model, features = joblib.load("model.joblib")

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
    times = [log.timestamp for log in logs]
    return [len(logs), (max(times) - min(times)).seconds]

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

    username = request.form.get("username")
    password = request.form.get("password")

    if User.query.filter_by(username=username).first():
        return "EXISTS", 409

    user = User(username=username, password=password)
    db.session.add(user)
    db.session.commit()

    return "CREATED", 201

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    if predict_attack(username):
        return "ATTACK", 403

    user = User.query.filter_by(username=username).first()

    if not user:
        save_log(username, 0)
        return "NO_USER", 404

    if user.password != password:
        save_log(username, 0)
        return "WRONG_PASSWORD", 401

    save_log(username, 1)
    return "SUCCESS", 200

@app.route("/dashboard/<username>")
def dashboard(username):
    return render_template("dashboard.html", username=username)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
