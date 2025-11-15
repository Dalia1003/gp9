# routes/Authentication.py

from flask import Blueprint, request, render_template, redirect, url_for, flash, session, current_app, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from firebase.Initialization import db
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import os
import re
import threading
import traceback
import requests

# ----------------------------
# Blueprint
# ----------------------------
auth_bp = Blueprint("Authentication", __name__)

# ----------------------------
# Serializer for email confirmation
# ----------------------------
def get_serializer():
    secret = current_app.config.get("SECRET_KEY")
    if not secret:
        raise RuntimeError("SECRET_KEY is missing!")
    return URLSafeTimedSerializer(secret)

# ----------------------------
# Brevo API Email Helper
# ----------------------------
BREVO_API_KEY = os.environ.get("BREVO_API_KEY", "")
BREVO_SENDER_EMAIL = os.environ.get("BREVO_SENDER_EMAIL", "ouwnsystem@gmail.com")
BREVO_SENDER_NAME = os.environ.get("BREVO_SENDER_NAME", "OuwN System")
BREVO_ENDPOINT = "https://api.brevo.com/v3/smtp/email"


def send_brevo_email(to_email: str, subject: str, html_body: str, text_body: str | None = None):
    """Send email through Brevo API"""
    if not BREVO_API_KEY:
        print("❌ BREVO_API_KEY is missing.")
        return

    payload = {
        "sender": {
            "email": BREVO_SENDER_EMAIL,
            "name": BREVO_SENDER_NAME,
        },
        "to": [{"email": to_email}],
        "subject": subject,
        "htmlContent": html_body,
    }

    if text_body:
        payload["textContent"] = text_body

    headers = {
        "api-key": BREVO_API_KEY,
        "Content-Type": "application/json",
        "accept": "application/json",
    }

    try:
        print(f"📨 Sending email → {to_email}")
        resp = requests.post(BREVO_ENDPOINT, json=payload, headers=headers, timeout=30)

        if resp.status_code >= 400:
            print(f"❌ Brevo error [{resp.status_code}]: {resp.text}")
        else:
            print("✅ Email sent:", resp.json())

    except Exception as e:
        print("❌ Brevo Exception:", e)
        traceback.print_exc()


def send_brevo_email_async(to_email, subject, html_body, text_body=None):
    """Send email in background so signup is instant"""
    t = threading.Thread(target=lambda: send_brevo_email(to_email, subject, html_body, text_body))
    t.daemon = True
    t.start()


# ----------------------------
# LOGIN ROUTE
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
            user_data = user_doc.to_dict()

            if not user_data.get("email_confirmed", 0):
                flash("⚠️ Please confirm your email first.", "error")
                return render_template("login.html", entered_username=entered_username)

            if not check_password_hash(user_data.get("Password", ""), password):
                flash("Invalid username or password.", "error")
                return render_template("login.html", entered_username=entered_username)

            # SUCCESS LOGIN
            session["user_id"] = user_doc.id
            session["user_name"] = user_data.get("Name") or user_data.get("UserID")
            session["user_email"] = user_data.get("Email")

            flash("✅ Logged in successfully!", "success")
            return redirect(url_for("dashboard"))

        except Exception as e:
            print("❌ LOGIN ERROR:", e)
            traceback.print_exc()
            flash("Login failed. Please try again.", "error")

    return render_template("login.html", entered_username=entered_username)


# ----------------------------
# SIGNUP ROUTE
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

        # Empty fields
        if not all([first, last, username, email, password]):
            flash("All fields are required.", "error")
            return render_template("signup.html", entered=entered)

        # Username validation
        username_pattern = r"^[A-Za-z][A-Za-z0-9._-]{2,31}$"
        if not re.fullmatch(username_pattern, username):
            flash("Username must start with a letter, be at least 3 characters, and use only letters, numbers, ., -, _.", "error")
            return render_template("signup.html", entered=entered)

        # Password strength
        if (
            len(password) < 8
            or not any(c.isupper() for c in password)
            or not any(c.islower() for c in password)
            or not any(c.isdigit() for c in password)
            or not any(not c.isalnum() for c in password)
        ):
            flash("Password must include uppercase, lowercase, number, and special character.", "error")
            return render_template("signup.html", entered=entered)

        # Firestore save
        try:
            # Check if username exists
            if db.collection("HealthCareP").document(username).get().exists:
                flash("Username already exists.", "error")
                return render_template("signup.html", entered=entered)

            # Check if email exists
            if db.collection("HealthCareP").where("Email", "==", email).limit(1).get():
                flash("Email already exists.", "error")
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
            print("❌ Firestore ERROR:", e)
            traceback.print_exc()
            flash("Failed to create your account.", "error")
            return render_template("signup.html", entered=entered)

        # Email confirmation
        try:
            s = get_serializer()
            token = s.dumps({"username": username, "email": email}, salt="email-confirm")
            confirm_link = url_for("Authentication.confirm_email", token=token, _external=True)

            subject = "Confirm Your Email - OuwN"
            text_body = f"Click the link to activate your OuwN account: {confirm_link}"

            html_body = f"""
            <html><body>
            <h2>Confirm Your Email</h2>
            <p>Hello {first} {last}, click below to activate your account:</p>
            <a href="{confirm_link}" style="padding:12px 20px;background:#9975C1;color:white;border-radius:8px;text-decoration:none;">Confirm Email</a>
            </body></html>
            """

            send_brevo_email_async(email, subject, html_body, text_body)

        except Exception as e:
            print("❌ Email Send ERROR:", e)
            traceback.print_exc()
            flash("Account created, but confirmation email failed. Contact support.", "error")

        flash("✅ Account created! Please check your email.", "success")
        return redirect(url_for("Authentication.login"))

    return render_template("signup.html", entered=entered)


# ----------------------------
# EMAIL CONFIRMATION ROUTE
# ----------------------------
@auth_bp.route("/confirm/<token>")
def confirm_email(token):
    try:
        s = get_serializer()
        data = s.loads(token, salt="email-confirm", max_age=3600)
    except SignatureExpired:
        return render_template("confirm.html", msg="⚠️ Confirmation link expired.")
    except BadSignature:
        return render_template("confirm.html", msg="⚠️ Invalid confirmation link.")

    username = data.get("username")

    doc_ref = db.collection("HealthCareP").document(username)
    doc = doc_ref.get()

    if not doc.exists:
        return render_template("confirm.html", msg="⚠️ Account not found.")

    doc_ref.update({"email_confirmed": 1})
    return render_template("confirm.html", msg="✅ Email confirmed! You may now log in.")


# ----------------------------
# AJAX FIELD CHECKER
# ----------------------------
@auth_bp.route("/check", methods=["GET"])
def check_field():
    field = request.args.get("field", "")
    value = request.args.get("value", "").strip()
    result = {"ok": True, "valid": True, "exists": False}

    try:
        if field == "username":
            # NEW strict rule: must start with letter + allowed chars
            regex = r"^[A-Za-z][A-Za-z0-9_.-]{2,31}$"
            result["valid"] = bool(re.fullmatch(regex, value))

            if result["valid"] and db is not None:
                doc = db.collection("HealthCareP").document(value).get()
                result["exists"] = doc.exists

        elif field == "email":
            result["valid"] = "@" in value and "." in value
            if result["valid"] and db is not None:
                docs = db.collection("HealthCareP").where("Email", "==", value).limit(1).get()
                result["exists"] = len(docs) > 0

        else:
            result = {"ok": False}

    except Exception as e:
        print("AJAX error:", e)
        result = {"ok": False}

    return jsonify(result)


