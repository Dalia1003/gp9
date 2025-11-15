# routes/Authentication.py
from flask import Blueprint, request, render_template, redirect, url_for, flash, session, current_app, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from firebase_admin import credentials, firestore, initialize_app
import firebase_admin
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import os
import re
import traceback
import threading
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ----------------------------
# Blueprint
# ----------------------------
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
    print("❌ Firebase failed:", e)
    db = None


# ----------------------------
# Token Serializer
# ----------------------------
def get_serializer():
    secret = current_app.config.get("SECRET_KEY")
    if not secret:
        raise RuntimeError("SECRET_KEY must be set in Render environment")
    return URLSafeTimedSerializer(secret)


# ----------------------------
# Brevo API Email Sender
# ----------------------------
BREVO_API_KEY = os.environ.get("BREVO_API_KEY", "")
SENDER_EMAIL = os.environ.get("SENDER_EMAIL", "")

def send_brevo_email_async(message_data):
    """Run the API email send in a background thread."""
    try:
        response = requests.post(
            "https://api.brevo.com/v3/smtp/email",
            headers={
                "accept": "application/json",
                "api-key": BREVO_API_KEY,
                "content-type": "application/json"
            },
            json=message_data,
            timeout=30
        )

        print("📨 Brevo API Response:", response.status_code, response.text)

    except Exception as e:
        print("❌ Brevo API error:", e)
        traceback.print_exc()


def send_confirmation_email(recipient, html_body, subject="Confirm Your Email"):
    """Formats and triggers async Brevo API email."""
    if not BREVO_API_KEY:
        print("❌ Missing BREVO_API_KEY environment variable")
        return

    email_payload = {
        "sender": {"email": SENDER_EMAIL, "name": "OuwN System"},
        "to": [{"email": recipient}],
        "subject": subject,
        "htmlContent": html_body
    }

    # Send asynchronously
    thread = threading.Thread(target=send_brevo_email_async, args=(email_payload,), daemon=True)
    thread.start()


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

        if db is None:
            flash("Database connection error.", "error")
            return render_template("login.html", entered_username=entered_username)

        try:
            users = db.collection("HealthCareP").where("UserID", "==", username).limit(1).get()
            if not users:
                flash("Invalid username or password.", "error")
                return render_template("login.html", entered_username=entered_username)

            user_doc = users[0]
            user = user_doc.to_dict()

            if not user.get("email_confirmed", 0):
                flash("⚠️ Please confirm your email before logging in.", "error")
                return render_template("login.html", entered_username=entered_username)

            if not check_password_hash(user["Password"], password):
                flash("Invalid username or password.", "error")
                return render_template("login.html", entered_username=entered_username)

            # Login successful
            session["user_id"] = user_doc.id
            session["user_name"] = user.get("Name")
            session["user_email"] = user.get("Email")

            flash("Logged in successfully!", "success")
            return redirect(url_for("dashboard"))

        except Exception as e:
            print("❌ Login error:", e)
            traceback.print_exc()
            flash("Login failed.", "error")

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
        entered = {"first_name": first, "last_name": last, "username": username, "email": email}

        if not all([first, last, username, email, password]):
            flash("All fields are required.", "error")
            return render_template("signup.html", entered=entered)

        if len(password) < 8 or not any(c.isupper() for c in password) \
                or not any(c.islower() for c in password) or not any(c.isdigit() for c in password):
            flash("Weak password. Include upper, lower, number, special char.", "error")
            return render_template("signup.html", entered=entered)

        try:
            if db.collection("HealthCareP").document(username).get().exists:
                flash("Username already exists.", "error")
                return render_template("signup.html", entered=entered)

            email_exists = db.collection("HealthCareP").where("Email", "==", email).limit(1).get()
            if email_exists:
                flash("Email already registered.", "error")
                return render_template("signup.html", entered=entered)

            hashed_pw = generate_password_hash(password)
            db.collection("HealthCareP").document(username).set({
                "UserID": username,
                "Email": email,
                "Password": hashed_pw,
                "Name": f"{first} {last}",
                "email_confirmed": 0
            })

        except Exception as e:
            print("❌ Firestore save error:", e)
            traceback.print_exc()
            flash("Account creation failed.", "error")
            return render_template("signup.html", entered=entered)

        # ----------------------------
        # Send confirmation email (Brevo API)
        # ----------------------------
        s = get_serializer()
        token = s.dumps({"username": username, "email": email}, salt="email-confirm")

        confirm_link = url_for("Authentication.confirm_email", token=token, _external=True)

        html_body = f"""
        <h2>Welcome to OuwN!</h2>
        <p>Hello {first} {last},</p>
        <p>Click below to confirm your email:</p>
        <a href="{confirm_link}" style="padding:10px 20px;background:#6a2b8f;color:white;border-radius:5px;text-decoration:none;">
            Confirm Email
        </a>
        <p>If you didn't sign up, ignore this email.</p>
        """

        send_confirmation_email(email, html_body)

        flash("Account created! Please check your email to confirm.", "success")
        return redirect(url_for("Authentication.login"))

    return render_template("signup.html", entered=entered)


# ----------------------------
# CONFIRM EMAIL
# ----------------------------
@auth_bp.route("/confirm/<token>")
def confirm_email(token):
    try:
        s = get_serializer()
        data = s.loads(token, salt="email-confirm", max_age=3600)
    except SignatureExpired:
        return render_template("confirm.html", msg="Confirmation link expired.")
    except BadSignature:
        return render_template("confirm.html", msg="Invalid confirmation link.")

    username = data.get("username")

    try:
        user_ref = db.collection("HealthCareP").document(username)
        user_doc = user_ref.get()

        if not user_doc.exists:
            return render_template("confirm.html", msg="Account not found.")

        user_ref.update({"email_confirmed": 1})
        return render_template("confirm.html", msg="Email confirmed! You can now log in.")

    except Exception as e:
        print("❌ Confirm error:", e)
        traceback.print_exc()
        return render_template("confirm.html", msg="Error confirming account.")


# ----------------------------
# AJAX CHECK FIELD
# ----------------------------
@auth_bp.route("/check", methods=["GET"])
def check_field():
    field = request.args.get("field")
    value = request.args.get("value", "").strip()
    result = {"ok": True, "exists": False, "valid": True}

    try:
        if field == "username":
            result["valid"] = bool(re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", value))
            if result["valid"]:
                result["exists"] = db.collection("HealthCareP").document(value).get().exists

        elif field == "email":
            result["valid"] = "@" in value and "." in value
            if result["valid"]:
                found = db.collection("HealthCareP").where("Email", "==", value).limit(1).get()
                result["exists"] = len(found) > 0

        else:
            result["ok"] = False

    except Exception as e:
        print("AJAX check error:", e)
        result["ok"] = False

    return jsonify(result)
