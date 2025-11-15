# ---------------------------------------------------------
# routes/Authentication.py
# ---------------------------------------------------------
# Handles:
# - Login
# - Signup
# - Email confirmation (Brevo API)
# - Live AJAX validation
#
# Uses:
# - Firestore initialized in firebase/Initialization.py
# - Brevo API for sending confirmation emails
# ---------------------------------------------------------

from flask import Blueprint, request, render_template, redirect, url_for, flash, session, current_app, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from firebase.Initialization import db     # Firestore object
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import re
import os
import threading
import traceback
import requests


# ---------------------------------------------------------
# Blueprint
# ---------------------------------------------------------
auth_bp = Blueprint("Authentication", __name__)


# ---------------------------------------------------------
# Serializer (for email tokens)
# ---------------------------------------------------------
def get_serializer():
    secret = current_app.config.get("SECRET_KEY")
    return URLSafeTimedSerializer(secret)


# ---------------------------------------------------------
# Brevo Email Setup
# ---------------------------------------------------------
BREVO_API_KEY = os.environ.get("BREVO_API_KEY", "")
BREVO_SENDER_EMAIL = os.environ.get("BREVO_SENDER_EMAIL", "ouwnsystem@gmail.com")
BREVO_SENDER_NAME = os.environ.get("BREVO_SENDER_NAME", "OuwN System")
BREVO_ENDPOINT = "https://api.brevo.com/v3/smtp/email"


def send_brevo_email(to_email: str, subject: str, html: str, text: str = None):
    """Send email using Brevo REST API."""

    if not BREVO_API_KEY:
        print("❌ BREVO_API_KEY is missing!")
        return

    payload = {
        "sender": {"email": BREVO_SENDER_EMAIL, "name": BREVO_SENDER_NAME},
        "to": [{"email": to_email}],
        "subject": subject,
        "htmlContent": html
    }

    if text:
        payload["textContent"] = text

    headers = {
        "api-key": BREVO_API_KEY,
        "Content-Type": "application/json",
    }

    try:
        print(f"📨 Sending email → {to_email}")
        res = requests.post(BREVO_ENDPOINT, json=payload, headers=headers)

        if res.status_code >= 400:
            print("❌ Brevo error:", res.text)
        else:
            print("✅ Brevo email sent:", res.json())

    except Exception as e:
        print("❌ Brevo send error:", e)
        traceback.print_exc()


def send_email_async(to, subject, html, text=None):
    t = threading.Thread(target=lambda: send_brevo_email(to, subject, html, text))
    t.daemon = True
    t.start()


# ---------------------------------------------------------
# LOGIN
# ---------------------------------------------------------
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    entered_username = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        entered_username = username

        if not username or not password:
            flash("Please enter both username and password.", "error")
            return render_template("login.html", entered_username=username)

        try:
            users = db.collection("HealthCareP").where("UserID", "==", username).limit(1).get()

            if not users:
                flash("Invalid username or password.", "error")
                return render_template("login.html", entered_username=username)

            user_doc = users[0]
            user = user_doc.to_dict()

            # Must confirm email
            if not user.get("email_confirmed", 0):
                flash("⚠️ Please confirm your email first.", "error")
                return render_template("login.html", entered_username=username)

            # Check password
            if not check_password_hash(user.get("Password", ""), password):
                flash("Invalid username or password.", "error")
                return render_template("login.html", entered_username=username)

            # Login success
            session["user_id"] = user_doc.id
            session["user_name"] = user.get("Name")
            session["user_email"] = user.get("Email")

            flash("✅ Logged in successfully!", "success")
            return redirect(url_for("dashboard"))

        except Exception as e:
            print("❌ LOGIN ERROR:", e)
            traceback.print_exc()
            flash("Login failed. Please try again.", "error")

    return render_template("login.html", entered_username=entered_username)


# ---------------------------------------------------------
# SIGNUP
# ---------------------------------------------------------
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

        # ----------------------------------------
        # Required Fields
        # ----------------------------------------
        if not all([first, last, username, email, password]):
            flash("All fields are required.", "error")
            return render_template("signup.html", entered=entered)

        # ----------------------------------------
        # Email must be in a valid email format
        # ----------------------------------------
        if not re.fullmatch(r"^[^@]+@[^@]+\.[A-Za-z]{2,}$", email):
            flash("Please enter a valid email address.", "error")
            return render_template("signup.html", entered=entered)

        # ----------------------------------------
        # Username rule
        # ----------------------------------------
        username_regex = r"^[A-Za-z][A-Za-z0-9._-]{2,31}$"
        if not re.fullmatch(username_regex, username):
            flash("Username must start with a letter and be 3–32 characters.", "error")
            return render_template("signup.html", entered=entered)

        # ----------------------------------------
        # Password Strength
        # ----------------------------------------
        if (
            len(password) < 8
            or not any(c.isupper() for c in password)
            or not any(c.islower() for c in password)
            or not any(c.isdigit() for c in password)
            or not any(not c.isalnum() for c in password)
        ):
            flash("Password must include uppercase, lowercase, number, and special character.", "error")
            return render_template("signup.html", entered=entered)

        # ----------------------------------------
        # Check duplicates
        # ----------------------------------------
        if db.collection("HealthCareP").document(username).get().exists:
            flash("Username already exists.", "error")
            return render_template("signup.html", entered=entered)

        if db.collection("HealthCareP").where("Email", "==", email).get():
            flash("Email already exists.", "error")
            return render_template("signup.html", entered=entered)

        # ----------------------------------------
        # Create user
        # ----------------------------------------
        hashed = generate_password_hash(password)

        db.collection("HealthCareP").document(username).set({
            "UserID": username,
            "Email": email,
            "Password": hashed,
            "Name": f"{first} {last}",
            "email_confirmed": 0
        })

        # ----------------------------------------
        # Send confirmation email (Brevo)
        # ----------------------------------------
        try:
            s = get_serializer()
            token = s.dumps({"username": username, "email": email}, salt="email-confirm")
            link = url_for("Authentication.confirm_email", token=token, _external=True)

            subject = "Confirm Your Email - OuwN"
            text = f"Click to confirm your account: {link}"

            html = f"""
            <h2>Welcome {first} {last}</h2>
            <p>Please confirm your email:</p>
            <a href="{link}" style="padding:10px 20px;background:#9975C1;color:white;border-radius:8px;text-decoration:none;">
                Confirm Email
            </a>
            """

            send_email_async(email, subject, html, text)

        except Exception as e:
            print("❌ Email send error:", e)
            traceback.print_exc()
            flash("Account created, but email failed to send.", "error")

        flash("✅ Account created! Check your email to confirm.", "success")
        return redirect(url_for("Authentication.login"))

    return render_template("signup.html", entered=entered)


# ---------------------------------------------------------
# EMAIL CONFIRMATION
# ---------------------------------------------------------
@auth_bp.route("/confirm/<token>")
def confirm_email(token):
    try:
        s = get_serializer()
        data = s.loads(token, salt="email-confirm", max_age=3600)

    except SignatureExpired:
        return render_template("confirm.html", msg="⚠️ Link expired.")
    except BadSignature:
        return render_template("confirm.html", msg="⚠️ Invalid link.")

    username = data.get("username")

    ref = db.collection("HealthCareP").document(username)
    if not ref.get().exists:
        return render_template("confirm.html", msg="⚠️ Account not found.")

    ref.update({"email_confirmed": 1})
    return render_template("confirm.html", msg="✅ Email confirmed! You may now log in.")


# ---------------------------------------------------------
# AJAX live field validation
# ---------------------------------------------------------
@auth_bp.route("/check")
def check_field():
    field = request.args.get("field", "")
    value = request.args.get("value", "").strip()

    result = {"ok": True, "valid": True, "exists": False}

    try:
        # ----------------------------------------
        # Username
        # ----------------------------------------
        if field == "username":
            regex = r"^[A-Za-z][A-Za-z0-9._-]{2,31}$"
            result["valid"] = bool(re.fullmatch(regex, value))

            if result["valid"]:
                result["exists"] = db.collection("HealthCareP").document(value).get().exists

        # ----------------------------------------
        # Email 
        # ----------------------------------------
        elif field == "email":
            result["valid"] = bool(re.fullmatch(r"^[^@]+@[^@]+\.[A-Za-z]{2,}$", value.lower()))

            if result["valid"]:
                docs = db.collection("HealthCareP").where("Email", "==", value).limit(1).get()
                result["exists"] = len(docs) > 0

        else:
            result = {"ok": False}

    except Exception as e:
        print("AJAX ERROR:", e)
        result = {"ok": False}

    return jsonify(result)
