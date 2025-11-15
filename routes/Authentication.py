# routes/Authentication.py

from flask import Blueprint, request, render_template, redirect, url_for, flash, session, current_app, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from firebase_admin import credentials, firestore, initialize_app
import firebase_admin
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import os
import re
import requests
import traceback

auth_bp = Blueprint("Authentication", __name__)

# ----------------------------
# Firebase Setup
# ----------------------------
try:
    if not firebase_admin._apps:
        cred_path = os.environ.get("FIREBASE_CRED_PATH", "serviceAccountKey.json")
        cred = credentials.Certificate(cred_path)
        initialize_app(cred)
    db = firestore.client()
except Exception as e:
    print("❌ Firebase initialization failed:", e)
    db = None

# ----------------------------
# Token Serializer
# ----------------------------
def get_serializer():
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"])


# ----------------------------
# BREVO EMAIL API (No SMTP!)
# ----------------------------
def send_confirmation_email(to_email, username, confirm_link):
    api_key = os.environ.get("BREVO_API_KEY")
    sender_email = os.environ.get("BREVO_SENDER_EMAIL")

    if not api_key:
        print("❌ Missing BREVO_API_KEY environment variable")
        return

    url = "https://api.brevo.com/v3/smtp/email"
    headers = {
        "accept": "application/json",
        "api-key": api_key,
        "content-type": "application/json"
    }

    html_content = f"""
    <h2>Email Confirmation</h2>
    <p>Hello <b>{username}</b>,</p>
    <p>Please click the link below to confirm your email:</p>
    <a href="{confirm_link}">{confirm_link}</a>
    """

    payload = {
        "sender": {"email": sender_email, "name": "OuwN System"},
        "to": [{"email": to_email}],
        "subject": "Confirm Your Email",
        "htmlContent": html_content
    }

    try:
        resp = requests.post(url, headers=headers, json=payload)
        print("📨 Brevo Response:", resp.status_code, resp.text)
    except Exception as e:
        print("❌ Brevo Email Error:", e)


# ----------------------------
# LOGIN
# ----------------------------
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    entered_username = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        entered_username = username

        if not username or not password:
            flash("Please enter both username and password.", "error")
            return render_template("login.html", entered_username=entered_username)

        try:
            users = db.collection("HealthCareP").where("UserID", "==", username).limit(1).get()
            if not users:
                flash("Invalid username or password.", "error")
                return render_template("login.html", entered_username=entered_username)

            user_doc = users[0]
            user = user_doc.to_dict()

            if not user.get("email_confirmed", 0):
                flash("⚠️ Please confirm your email first.", "error")
                return render_template("login.html", entered_username=entered_username)

            if not check_password_hash(user.get("Password", ""), password):
                flash("Invalid username or password.", "error")
                return render_template("login.html", entered_username=entered_username)

            session["user_id"] = user_doc.id
            session["user_name"] = user.get("Name")
            session["user_email"] = user.get("Email")

            return redirect(url_for("dashboard"))

        except Exception as e:
            print("❌ Login error:", e)
            flash("Login failed. Try again.", "error")

    return render_template("login.html", entered_username=entered_username)


# ----------------------------
# SIGNUP
# ----------------------------
@auth_bp.route("/signup", methods=["GET", "POST"])
def signup():
    entered = {"first_name": "", "last_name": "", "username": "", "email": ""}

    if request.method == "POST":
        first = request.form.get("first_name", "").strip()
        last = request.form.get("last_name", "").strip()
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        entered.update({"first_name": first, "last_name": last, "username": username, "email": email})

        if not all([first, last, username, email, password]):
            flash("All fields are required.", "error")
            return render_template("signup.html", entered=entered)

        try:
            if db.collection("HealthCareP").document(username).get().exists:
                flash("Username already exists.", "error")
                return render_template("signup.html", entered=entered)

            hashed_pw = generate_password_hash(password)
            db.collection("HealthCareP").document(username).set({
                "UserID": username,
                "Email": email,
                "Password": hashed_pw,
                "Name": f"{first} {last}",
                "email_confirmed": 0
            })

            s = get_serializer()
            token = s.dumps({"username": username, "email": email}, salt="email-confirm")
            confirm_link = url_for("Authentication.confirm_email", token=token, _external=True)

            send_confirmation_email(email, username, confirm_link)

            flash("Account created! Please check your email to confirm.", "success")
            return redirect(url_for("Authentication.login"))

        except Exception as e:
            print("❌ Signup error:", e)
            traceback.print_exc()
            flash("Signup failed.", "error")

    return render_template("signup.html", entered=entered)


# ----------------------------
# EMAIL CONFIRMATION
# ----------------------------
@auth_bp.route("/confirm/<token>")
def confirm_email(token):
    try:
        s = get_serializer()
        data = s.loads(token, salt="email-confirm", max_age=3600)

        username = data.get("username")
        doc_ref = db.collection("HealthCareP").document(username)
        doc_ref.update({"email_confirmed": 1})

        return render_template("confirm.html", msg="✅ Email confirmed! You may now log in.")

    except SignatureExpired:
        return render_template("confirm.html", msg="⚠️ Link expired.")
    except BadSignature:
        return render_template("confirm.html", msg="⚠️ Invalid confirmation link.")
