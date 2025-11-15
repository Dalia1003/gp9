# routes/auth_reset.py

from flask import Blueprint, render_template, request, flash, redirect, url_for
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from werkzeug.security import generate_password_hash
from firebase.Initialization import db
import os
import re
import threading
import traceback
import requests

reset_bp = Blueprint("auth_reset", __name__, url_prefix="/auth/reset")

# -------------------------------------------------
# Load Brevo settings ONCE (safe for threads)
# -------------------------------------------------
BREVO_API_KEY = os.environ.get("BREVO_API_KEY", "")
BREVO_SENDER_EMAIL = os.environ.get("BREVO_SENDER_EMAIL", "ouwnsystem@gmail.com")
BREVO_SENDER_NAME = os.environ.get("BREVO_SENDER_NAME", "OuwN System")
BREVO_ENDPOINT = "https://api.brevo.com/v3/smtp/email"


# -------------------------------------------------
# Send email (same style as signup)
# -------------------------------------------------
def send_brevo_email(to_email, subject, html_body, text_body=None):
    """Send email via Brevo HTTP API — identical to signup logic"""

    if not BREVO_API_KEY:
        print("❌ BREVO_API_KEY missing!")
        return False

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
        print(f"📨 Sending reset email to {to_email} ...")
        res = requests.post(BREVO_ENDPOINT, json=payload, headers=headers, timeout=30)

        if res.status_code >= 400:
            print(f"❌ Brevo Error [{res.status_code}]: {res.text}")
            return False

        print("✅ Brevo OK:", res.json())
        return True

    except Exception as e:
        print("❌ Reset email exception:", e)
        traceback.print_exc()
        return False


def send_brevo_email_async(to_email, subject, html_body, text_body=None):
    """Run Brevo email in background thread — same as signup"""
    t = threading.Thread(target=lambda: send_brevo_email(to_email, subject, html_body, text_body))
    t.daemon = True
    t.start()


# -------------------------------------------------
# Token Serializer
# -------------------------------------------------
def get_serializer():
    from flask import current_app
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"])


# -------------------------------------------------
# Step 1 — Request Reset Email
# -------------------------------------------------
@reset_bp.route("/request", methods=["GET", "POST"])
def reset_request():
    message = ""

    if request.method == "POST":
        email = request.form.get("email", "").strip()

        if not email:
            message = "Please enter your email."
            return render_template("reset_password.html", message=message)

        # Check user exists
        users = db.collection("HealthCareP").where("Email", "==", email).get()
        if not users:
            message = "No account found with this email."
            return render_template("reset_password.html", message=message)

        # Generate token
        s = get_serializer()
        token = s.dumps({"email": email}, salt="password-reset")
        reset_link = url_for("auth_reset.reset_password", token=token, _external=True)

        # Email HTML
        html_body = f"""
        <html><body style='font-family: Arial; background:#f4eefc; padding:20px;'>
            <div style='max-width:600px;margin:auto;background:#fff;border-radius:10px;padding:25px;'>
                <h2 style='text-align:center;color:#9975C1;'>Reset Your Password</h2>
                <p>Click below to reset your password:</p>
                <div style='text-align:center;margin:20px;'>
                    <a href="{reset_link}" 
                       style='background:#9975C1;color:white;padding:12px 22px;border-radius:8px;text-decoration:none;'>
                        Reset Password
                    </a>
                </div>
                <p>If you did not request this, ignore this email.</p>
            </div>
        </body></html>
        """

        # Send async
        send_brevo_email_async(email, "Reset Your Password – OuwN", html_body)

        message = "✅ Reset email sent — check your inbox."

    return render_template("reset_password.html", message=message)


# -------------------------------------------------
# Step 2 — Reset Password (via token)
# -------------------------------------------------
@reset_bp.route("/<token>", methods=["GET", "POST"])
def reset_password(token):
    s = get_serializer()
    message = ""

    try:
        data = s.loads(token, salt="password-reset", max_age=3600)
        email = data["email"]
    except SignatureExpired:
        message = "⚠️ This reset link has expired."
        return render_template("reset_password.html", message=message)
    except BadSignature:
        message = "⚠️ Invalid or broken reset link."
        return render_template("reset_password.html", message=message)

    if request.method == "POST":
        pw = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not pw or not confirm:
            message = "Please fill all fields."
            return render_template("reset_token.html", message=message)

        if pw != confirm:
            message = "Passwords do not match."
            return render_template("reset_token.html", message=message)

        # Password validation
        if (
            len(pw) < 8
            or not re.search(r"[A-Z]", pw)
            or not re.search(r"[a-z]", pw)
            or not re.search(r"\d", pw)
            or not re.search(r"[^A-Za-z0-9]", pw)
        ):
            message = "Password must include upper, lower, number & special."
            return render_template("reset_token.html", message=message)

        # Update password
        users = db.collection("HealthCareP").where("Email", "==", email).get()
        if not users:
            message = "User not found."
            return render_template("reset_token.html", message=message)

        user_ref = users[0].reference
        user_ref.update({"Password": generate_password_hash(pw)})

        flash("Password successfully reset!", "success")
        return redirect(url_for("Authentication.login"))

    return render_template("reset_token.html", message=message)
