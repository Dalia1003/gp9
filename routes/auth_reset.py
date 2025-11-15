from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from werkzeug.security import generate_password_hash
from firebase.Initialization import db
import os
import re
import threading
import traceback
import requests

reset_bp = Blueprint("auth_reset", __name__, url_prefix="/auth/reset")


# ---------------------------------------------------------
# Token Serializer
# ---------------------------------------------------------
def get_serializer():
    secret = current_app.config.get("SECRET_KEY")
    return URLSafeTimedSerializer(secret)


# ---------------------------------------------------------
# Brevo Email Setup (SAME as Authentication)
# ---------------------------------------------------------
BREVO_API_KEY = os.environ.get("BREVO_API_KEY", "")
BREVO_SENDER_EMAIL = os.environ.get("BREVO_SENDER_EMAIL", "ouwnsystem@gmail.com")
BREVO_SENDER_NAME = os.environ.get("BREVO_SENDER_NAME", "OuwN System")
BREVO_ENDPOINT = "https://api.brevo.com/v3/smtp/email"


def send_brevo_email(to_email: str, subject: str, html: str, text: str = None):
    """Send email using Brevo API."""
    if not BREVO_API_KEY:
        print("❌ Missing BREVO_API_KEY")
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
        "Content-Type": "application/json"
    }

    try:
        print(f"📨 Sending reset email → {to_email}")
        res = requests.post(BREVO_ENDPOINT, json=payload, headers=headers)

        if res.status_code >= 400:
            print("❌ BREVO ERROR:", res.text)
        else:
            print("✅ Email sent:", res.json())

    except Exception as e:
        print("❌ Brevo exception:", e)
        traceback.print_exc()


def send_email_async(to, subject, html, text=None):
    thread = threading.Thread(target=lambda: send_brevo_email(to, subject, html, text))
    thread.daemon = True
    thread.start()


# ---------------------------------------------------------
# Request Password Reset
# ---------------------------------------------------------
@reset_bp.route("/request", methods=["GET", "POST"])
def reset_request():
    message = ""

    if request.method == "POST":
        email = request.form.get("email", "").strip()

        if not email:
            return render_template("reset_password.html", message="Please enter your email.")

        
        # Validate general email format 
        if not re.fullmatch(r"^[^@]+@[^@]+\.[A-Za-z]{2,}$", email):
            return render_template("reset_password.html", message="Please enter a valid email address.")


        # Check if email exists
        users = db.collection("HealthCareP").where("Email", "==", email).get()
        if not users:
            return render_template("reset_password.html", message="No account found with this email.")

        # Create token
        s = get_serializer()
        token = s.dumps({"email": email}, salt="password-reset")
        reset_link = url_for("auth_reset.reset_password", token=token, _external=True)

        # Prepare email
        subject = "OuwN Password Reset"
        text_body = f"Click here to reset your password: {reset_link}"

        html_body = f"""
        <h2 style="color:#9975C1;">Reset Your Password</h2>
        <p>Hello, click below to reset your password:</p>
        <a href="{reset_link}" 
           style="background:#9975C1;color:white;padding:12px 20px;border-radius:8px;text-decoration:none;">
           Reset Password
        </a>
        <p>If you did not request this, ignore this email.</p>
        """

        # Send async
        try:
            send_email_async(email, subject, html_body, text_body)
            message = "✅ Reset email sent! Check your inbox."
        except Exception as e:
            print("❌ Error sending reset email:", e)
            message = "Failed to send email. Try again later."

    return render_template("reset_password.html", message=message)


# ---------------------------------------------------------
# Reset Password Page (token)
# ---------------------------------------------------------
@reset_bp.route("/<token>", methods=["GET", "POST"])
def reset_password(token):
    s = get_serializer()
    message = ""

    # Validate token
    try:
        data = s.loads(token, salt="password-reset", max_age=3600)
        email = data.get("email")
    except SignatureExpired:
        return render_template("reset_password.html", message="⚠️ The reset link expired.")
    except BadSignature:
        return render_template("reset_password.html", message="⚠️ Invalid reset link.")

    #  Update password
    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not password or not confirm:
            return render_template("reset_token.html", message="Please fill all fields.")

        if password != confirm:
            return render_template("reset_token.html", message="Passwords do not match.")

        # Validate strength
        rules = {
            "length": len(password) >= 8,
            "upper": bool(re.search(r"[A-Z]", password)),
            "lower": bool(re.search(r"[a-z]", password)),
            "digit": bool(re.search(r"\d", password)),
            "special": bool(re.search(r"[^A-Za-z0-9]", password))
        }

        if not all(rules.values()):
            return render_template(
                "reset_token.html",
                message="Password must be 8+ chars, include upper/lowercase, digit, and special character."
            )

        # Update in Firestore
        user_docs = db.collection("HealthCareP").where("Email", "==", email).get()

        if not user_docs:
            return render_template("reset_token.html", message="User not found.")

        # Update the password
        user_ref = user_docs[0].reference
        user_ref.update({"Password": generate_password_hash(password)})

        flash("✅ Password reset successfully! Please log in.", "success")
        return redirect(url_for("Authentication.login"))

    return render_template("reset_token.html", message=message)
