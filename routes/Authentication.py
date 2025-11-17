from flask import (
    Blueprint, request, render_template, redirect,
    url_for, flash, session, current_app, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash
from firebase.Initialization import db
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from google.cloud import firestore
from datetime import datetime, timedelta, timezone
import re
import os
import threading
import requests
import traceback
import threading
import time
from google.cloud.firestore_v1 import FieldFilter
__all__ = ["auth_bp", "cleanup_unconfirmed_users_background"]


# ---------------------------------------------------------
#  Blueprint Setup
# ---------------------------------------------------------
auth_bp = Blueprint("Authentication", __name__)

def cleanup_unconfirmed_users_background():
    while True:
        try:
            print("🧹 Running auto-cleanup for unconfirmed users...")

            now = datetime.now(timezone.utc)
            one_hour_ago = now - timedelta(hours=1)

            users = db.collection("HealthCareP").where(
                filter=FieldFilter("email_confirmed", "==", 0)
            ).stream()

            for u in users:
                data = u.to_dict()
                created_at = data.get("created_at")

                if not created_at:
                    continue

                # Convert Firestore timestamp to datetime safely
                if hasattr(created_at, "to_datetime"):
                    created_at = created_at.to_datetime()
                elif hasattr(created_at, "datetime"):
                    created_at = created_at.datetime
                else:
                    continue


                if created_at < one_hour_ago:
                    db.collection("HealthCareP").document(u.id).delete()
                    print(f"🗑️ Deleted unconfirmed: {u.id}")

        except Exception as e:
            print("⚠️ Cleanup error:", e)

        time.sleep(3600)  # Run every hour

# ---------------------------------------------------------
#  Serializer for secure tokens
# ---------------------------------------------------------
def get_serializer():
    secret = current_app.config["SECRET_KEY"]
    return URLSafeTimedSerializer(secret)


# ---------------------------------------------------------
#  Brevo Email Setup
# ---------------------------------------------------------
BREVO_API_KEY = os.environ.get("BREVO_API_KEY", "")
BREVO_SENDER_EMAIL = os.environ.get("BREVO_SENDER_EMAIL", "ouwnsystem@gmail.com")
BREVO_SENDER_NAME = os.environ.get("BREVO_SENDER_NAME", "OuwN System")
BREVO_ENDPOINT = "https://api.brevo.com/v3/smtp/email"


def send_brevo_email(to_email: str, subject: str, html: str, text: str = None):
    """Send email using Brevo REST API."""
    if not BREVO_API_KEY:
        print("❌ BREVO_API_KEY missing!")
        return

    payload = {
        "sender": {"email": BREVO_SENDER_EMAIL, "name": BREVO_SENDER_NAME},
        "to": [{"email": to_email}],
        "subject": subject,
        "htmlContent": html,
    }

    if text:
        payload["textContent"] = text

    headers = {
        "api-key": BREVO_API_KEY,
        "Content-Type": "application/json",
    }

    try:
        res = requests.post(BREVO_ENDPOINT, json=payload, headers=headers)
        if res.status_code >= 400:
            print("❌ Brevo error:", res.text)
        else:
            print("✅ Email sent:", res.json())
    except Exception as e:
        print("❌ Email send failed:", e)


def send_email_async(to, subject, html, text=None):
    t = threading.Thread(target=lambda: send_brevo_email(to, subject, html, text))
    t.daemon = True
    t.start()

# ---------------------------------------------------------
#  LOGIN
# ---------------------------------------------------------
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    entered_username = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        entered_username = username

        if not username or not password:
            flash("Please enter both username and password.", "error")
            return render_template("login.html", entered_username=username)

        try:
            q = db.collection("HealthCareP").where("UserID", "==", username).limit(1).get()
            if not q:
                flash("Invalid username or password.", "error")
                return render_template("login.html", entered_username=username)

            user_doc = q[0]
            user = user_doc.to_dict()

            if not user.get("email_confirmed", 0):
                flash("⚠️ Please confirm your email first.", "error")
                return render_template("login.html", entered_username=username)

            if not check_password_hash(user["Password"], password):
                flash("Invalid username or password.", "error")
                return render_template("login.html", entered_username=username)

            session["user_id"] = user_doc.id
            session["user_name"] = user["Name"]
            session["user_email"] = user["Email"]

            return redirect(url_for("dashboard"))

        except Exception as e:
            print("❌ LOGIN ERROR:", e)
            traceback.print_exc()
            flash("Login failed. Try again.", "error")

    return render_template("login.html", entered_username=entered_username)


# ---------------------------------------------------------
#  SIGNUP
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

        # Required fields
        if not all([first, last, username, email, password]):
            flash("All fields are required.", "error")
            return render_template("signup.html", entered=entered)

        # Email validation
        if not re.fullmatch(r"^[^@]+@[^@]+\.[A-Za-z]{2,}$", email):
            flash("Enter a valid email address.", "error")
            return render_template("signup.html", entered=entered)

        # Username validation
        username_regex = r"^[A-Za-z][A-Za-z0-9._-]{2,31}$"
        if not re.fullmatch(username_regex, username):
            flash("Username must start with a letter and be 3–32 characters.", "error")
            return render_template("signup.html", entered=entered)

        # Password checks
        if (
            len(password) < 8
            or not any(c.isupper() for c in password)
            or not any(c.islower() for c in password)
            or not any(c.isdigit() for c in password)
            or not any(not c.isalnum() for c in password)
        ):
            flash("Password must include uppercase, lowercase, number, and special character.", "error")
            return render_template("signup.html", entered=entered)

        # Duplicates
        if db.collection("HealthCareP").document(username).get().exists:
            flash("Username already exists.", "error")
            return render_template("signup.html", entered=entered)

        if db.collection("HealthCareP").where("Email", "==", email).limit(1).get():
            flash("Email already exists.", "error")
            return render_template("signup.html", entered=entered)

        # Create user
        hashed_pw = generate_password_hash(password)
        db.collection("HealthCareP").document(username).set({
            "UserID": username,
            "Email": email,
            "Password": hashed_pw,
            "Name": f"{first} {last}",
            "email_confirmed": 0,
            "created_at": firestore.SERVER_TIMESTAMP   # <-- needed for cleanup
        })

        # Send confirmation
        try:
            s = get_serializer()
            token = s.dumps({"username": username, "email": email}, salt="email-confirm")
            link = url_for("Authentication.confirm_email", token=token, _external=True)

            subject = "Confirm Your Email - OuwN"

            html = f"""
            <html>
            <body style="font-family:'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                        color:#2d004d; background:#f4eefc; padding:20px;">
                        
                <div style="max-width:600px; margin:auto; background:#fff; border-radius:10px;
                            padding:30px; box-shadow:0 5px 15px rgba(0,0,0,0.1);">

                <h2 style="color:#9975C1; text-align:center;">OuwN Email Confirmation</h2>

                <p>Hi {first} {last},</p>

                <p>Welcome! Please confirm your email address by clicking the button below:</p>

                <div style="text-align:center; margin:30px 0;">
                    <a href="{link}" 
                    style="background:#9975C1; color:white; padding:12px 25px;
                            text-decoration:none; border-radius:25px; font-weight:bold;">
                    Confirm Email
                    </a>
                </div>

                <p>If you didn't create an account, you can ignore this email.</p>

                <p>Thanks,<br><strong>OuwN Team</strong></p>

                </div>
            </body>
            </html>
            """

            send_email_async(email, subject, html)

        except Exception as e:
            print("❌ Email send error:", e)

        flash("Account created! Check your email to confirm.", "success")
        return redirect(url_for("Authentication.login"))

    return render_template("signup.html", entered=entered)


# ---------------------------------------------------------
#  EMAIL CONFIRMATION
# ---------------------------------------------------------
@auth_bp.route("/confirm/<token>")
def confirm_email(token):
    s = get_serializer()

    try:
        data = s.loads(token, salt="email-confirm", max_age=3600)
    except SignatureExpired:
        return render_template("confirm.html", msg="⚠️ Link expired. Sign up again.")
    except BadSignature:
        return render_template("confirm.html", msg="⚠️ Invalid confirmation link.")

    username = data.get("username")
    ref = db.collection("HealthCareP").document(username)

    if not ref.get().exists:
        return render_template("confirm.html", msg="⚠️ Account not found.")

    ref.update({"email_confirmed": 1})

    return render_template("confirm.html", msg="✅ Email confirmed! You may now log in.")


# ---------------------------------------------------------
#  AJAX Field Validation (Username + Email)
# ---------------------------------------------------------
@auth_bp.route("/check")
def check_field():
    field = request.args.get("field")
    value = request.args.get("value", "").strip()

    result = {"ok": True, "valid": True, "exists": False}

    try:
        if field == "username":
            regex = r"^[A-Za-z][A-Za-z0-9._-]{2,31}$"
            result["valid"] = bool(re.fullmatch(regex, value))
            if result["valid"]:
                result["exists"] = db.collection("HealthCareP").document(value).get().exists

        elif field == "email":
            result["valid"] = bool(re.fullmatch(r"^[^@]+@[^@]+\.[A-Za-z]{2,}$", value))
            if result["valid"]:
                result["exists"] = len(db.collection("HealthCareP")
                    .where("Email", "==", value)
                    .limit(1).get()) > 0

        else:
            result = {"ok": False}

    except Exception:
        result = {"ok": False}

    return jsonify(result)
