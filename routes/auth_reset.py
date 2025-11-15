# routes/auth_reset.py

from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from werkzeug.security import generate_password_hash
import re
import requests
import threading
from firebase.Initialization import db


reset_bp = Blueprint("auth_reset", __name__, url_prefix="/auth/reset")


# ------------------------------------------------------
# SAFE HELPERS — read config ONLY inside functions
# ------------------------------------------------------
def send_brevo_email(to_email, subject, html_body):
    """
    Safe Brevo API email sender — all config accessed inside function!
    """
    api_key = current_app.config.get("BREVO_API_KEY")
    sender_email = current_app.config.get("BREVO_SENDER_EMAIL", "ouwnsystem@gmail.com")
    sender_name = current_app.config.get("BREVO_SENDER_NAME", "OuwN System")

    if not api_key:
        print("❌ Missing BREVO_API_KEY")
        return False

    payload = {
        "sender": {"email": sender_email, "name": sender_name},
        "to": [{"email": to_email}],
        "subject": subject,
        "htmlContent": html_body,
    }

    headers = {
        "api-key": api_key,
        "Content-Type": "application/json",
    }

    try:
        r = requests.post("https://api.brevo.com/v3/smtp/email",
                          json=payload, headers=headers, timeout=20)

        if r.status_code >= 400:
            print("❌ Brevo error:", r.text)
            return False

        return True

    except Exception as e:
        print("❌ Brevo exception:", e)
        return False


def send_brevo_email_async(to, subject, html):
    threading.Thread(
        target=send_brevo_email,
        args=(to, subject, html),
        daemon=True
    ).start()


def get_serializer():
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"])


# ------------------------------------------------------
# REQUEST RESET
# ------------------------------------------------------
@reset_bp.route("/request", methods=["GET", "POST"])
def reset_request():
    message = ""

    if request.method == "POST":
        email = request.form.get("email", "").strip()

        if not email:
            return render_template("reset_password.html", message="Please enter your email.")

        users = db.collection("HealthCareP").where("Email", "==", email).get()

        if not users:
            return render_template("reset_password.html",
                                   message="No account found with this email.")

        # Token
        s = get_serializer()
        token = s.dumps({"email": email}, salt="password-reset")
        reset_link = url_for("auth_reset.reset_password", token=token, _external=True)

        html_body = f"""
        <h2 style='color:#9975C1;'>Reset Password</h2>
        <p>Click below to reset your password:</p>
        <p><a href="{reset_link}" 
              style="padding:10px 20px; background:#9975C1; color:white; 
                     text-decoration:none; border-radius:6px;">
            Reset Password
        </a></p>
        """

        send_brevo_email_async(email, "OuwN Password Reset", html_body)

        message = "✅ Password reset email sent!"

    return render_template("reset_password.html", message=message)


# ------------------------------------------------------
# RESET TOKEN PAGE
# ------------------------------------------------------
@reset_bp.route("/<token>", methods=["GET", "POST"])
def reset_password(token):
    s = get_serializer()

    try:
        data = s.loads(token, salt="password-reset", max_age=3600)
        email = data["email"]
    except SignatureExpired:
        return render_template("reset_password.html",
                               message="⚠️ Reset link expired.")
    except BadSignature:
        return render_template("reset_password.html",
                               message="⚠️ Invalid reset link.")

    if request.method == "POST":
        pw = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if pw != confirm:
            return render_template("reset_token.html",
                                   message="Passwords do not match.")

        # Strength check
        if not (
            len(pw) >= 8 and re.search(r"[A-Z]", pw) and
            re.search(r"[a-z]", pw) and re.search(r"\d", pw) and
            re.search(r"[^A-Za-z0-9]", pw)
        ):
            return render_template("reset_token.html",
                                   message="Password must include upper, lower, digit & special.")

        users = db.collection("HealthCareP").where("Email", "==", email).get()
        if not users:
            return render_template("reset_token.html", message="User not found.")

        ref = users[0].reference
        ref.update({"Password": generate_password_hash(pw)})

        flash("Password updated successfully!", "success")
        return redirect(url_for("Authentication.login"))

    return render_template("reset_token.html")
