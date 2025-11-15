# routes/auth_reset.py

from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from werkzeug.security import generate_password_hash
import re
import requests
import threading

from firebase.Initialization import db


# ------------------------------------------------------
#  BLUEPRINT
# ------------------------------------------------------
reset_bp = Blueprint("auth_reset", __name__, url_prefix="/auth/reset")


# ------------------------------------------------------
#  HELPER — Brevo API email sender (same as signup)
# ------------------------------------------------------
BREVO_API_KEY = current_app.config.get("BREVO_API_KEY", "")
BREVO_SENDER_EMAIL = current_app.config.get("BREVO_SENDER_EMAIL", "ouwnsystem@gmail.com")
BREVO_SENDER_NAME = current_app.config.get("BREVO_SENDER_NAME", "OuwN System")
BREVO_ENDPOINT = "https://api.brevo.com/v3/smtp/email"


def send_brevo_email(to_email, subject, html_body):
    """
    Sends email via Brevo HTTP API (SMTP disabled on Render).
    """
    if not BREVO_API_KEY:
        print("❌ BREVO_API_KEY is missing")
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

    headers = {
        "api-key": BREVO_API_KEY,
        "Content-Type": "application/json",
        "accept": "application/json",
    }

    try:
        resp = requests.post(BREVO_ENDPOINT, json=payload, headers=headers, timeout=30)

        if resp.status_code >= 400:
            print(f"❌ Brevo error [{resp.status_code}]: {resp.text}")
            return False

        return True

    except Exception as e:
        print("❌ Brevo Exception:", e)
        return False


def send_brevo_email_async(to_email, subject, html_body):
    threading.Thread(
        target=send_brevo_email,
        args=(to_email, subject, html_body),
        daemon=True
    ).start()


# ------------------------------------------------------
#  TOKEN SERIALIZER
# ------------------------------------------------------
def get_serializer():
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"])


# ------------------------------------------------------
#  STEP 1 — REQUEST RESET
# ------------------------------------------------------
@reset_bp.route("/request", methods=["GET", "POST"])
def reset_request():
    message = ""

    if request.method == "POST":
        email = request.form.get("email", "").strip()

        if not email:
            message = "Please enter your email."
            return render_template("reset_password.html", message=message)

        users = db.collection("HealthCareP").where("Email", "==", email).get()
        if not users:
            message = "No account found with this email."
            return render_template("reset_password.html", message=message)

        # Generate reset token
        s = get_serializer()
        token = s.dumps({"email": email}, salt="password-reset")
        reset_link = url_for("auth_reset.reset_password", token=token, _external=True)

        # Email body
        html_body = f"""
        <html>
        <body style="font-family: 'Segoe UI'; background:#f4eefc; padding:20px;">
            <div style="max-width:600px; margin:auto; background:white; border-radius:12px; padding:30px;
                        box-shadow:0 4px 15px rgba(0,0,0,0.1);">

                <h2 style="color:#9975C1; text-align:center;">Reset Your Password</h2>

                <p>Hello,</p>
                <p>You requested a password reset for OuwN.</p>

                <div style="text-align:center; margin:30px 0;">
                    <a href="{reset_link}"
                       style="background:#9975C1; color:white; padding:12px 22px; border-radius:25px;
                              text-decoration:none; font-weight:bold;">
                        Reset Password
                    </a>
                </div>

                <p>If you did not request this, you can ignore this email.</p>

                <p style="margin-top:20px;">— OuwN Team</p>
            </div>
        </body>
        </html>
        """

        send_brevo_email_async(email, "OuwN Password Reset", html_body)
        message = "✅ Password reset email sent. Check your inbox."

    return render_template("reset_password.html", message=message)


# ------------------------------------------------------
#  STEP 2 — RESET PASSWORD PAGE
# ------------------------------------------------------
@reset_bp.route("/<token>", methods=["GET", "POST"])
def reset_password(token):
    s = get_serializer()
    message = ""

    try:
        data = s.loads(token, salt="password-reset", max_age=3600)
        email = data["email"]
    except SignatureExpired:
        return render_template("reset_password.html",
                               message="⚠️ Reset link expired.")
    except BadSignature:
        return render_template("reset_password.html",
                               message="⚠️ Invalid reset link.")

    # POST — update password
    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not password or not confirm:
            return render_template("reset_token.html", message="Please fill all fields.")

        if password != confirm:
            return render_template("reset_token.html", message="Passwords do not match.")

        # Strong password validation
        if not (
            len(password) >= 8 and
            re.search(r"[A-Z]", password) and
            re.search(r"[a-z]", password) and
            re.search(r"\d", password) and
            re.search(r"[^A-Za-z0-9]", password)
        ):
            return render_template(
                "reset_token.html",
                message="Password must include upper, lower, number and special char."
            )

        # Update Firestore
        users = db.collection("HealthCareP").where("Email", "==", email).get()
        if not users:
            return render_template("reset_token.html", message="User not found.")

        user_ref = users[0].reference
        user_ref.update({"Password": generate_password_hash(password)})

        flash("Your password has been reset successfully!", "success")
        return redirect(url_for("Authentication.login"))

    return render_template("reset_token.html", message=message)
