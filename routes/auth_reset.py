from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from werkzeug.security import generate_password_hash
import threading
import re
import requests

from firebase.Initialization import db

reset_bp = Blueprint("auth_reset", __name__, url_prefix="/auth/reset")


# ------------------------------------------------------
# TOKEN SERIALIZER
# ------------------------------------------------------
def get_serializer():
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"])


# ------------------------------------------------------
# THREAD-SAFE BREVO EMAIL FUNCTION
# ------------------------------------------------------
def send_brevo_email_thread(api_key, sender_email, sender_name, to_email, subject, html_body):
    headers = {
        "api-key": api_key,
        "Content-Type": "application/json",
    }

    payload = {
        "sender": {"email": sender_email, "name": sender_name},
        "to": [{"email": to_email}],
        "subject": subject,
        "htmlContent": html_body,
    }

    try:
        r = requests.post(
            "https://api.brevo.com/v3/smtp/email",
            json=payload,
            headers=headers,
            timeout=20
        )
        print("BREVO RESPONSE:", r.status_code, r.text)
    except Exception as e:
        print("❌ Brevo Thread Error:", e)


# ------------------------------------------------------
# SAFE CALLER FUNCTION (RUNS INSIDE FLASK CONTEXT)
# ------------------------------------------------------
def send_brevo_email(to_email, subject, html_body):
    api_key = current_app.config.get("BREVO_API_KEY")
    sender_email = current_app.config.get("BREVO_SENDER_EMAIL", "ouwnsystem@gmail.com")
    sender_name = current_app.config.get("BREVO_SENDER_NAME", "OuwN System")

    if not api_key:
        print("❌ BREVO_API_KEY missing!")
        return False

    # Start background thread
    thread = threading.Thread(
        target=send_brevo_email_thread,
        args=(api_key, sender_email, sender_name, to_email, subject, html_body),
        daemon=True
    )
    thread.start()
    return True


# ------------------------------------------------------
# STEP 1 — REQUEST PASSWORD RESET
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

        # Create reset token
        s = get_serializer()
        token = s.dumps({"email": email}, salt="password-reset")
        reset_link = url_for("auth_reset.reset_password", token=token, _external=True)

        # HTML Body
        html_body = f"""
        <html>
        <body style="font-family: Arial; background: #f4eefc; padding: 20px;">
            <div style="max-width: 600px; margin: auto; background: #fff; border-radius: 10px;
                        padding: 30px; box-shadow: 0 5px 15px rgba(0,0,0,0.1);">
                <h2 style="color: #9975C1; text-align: center;">Reset Your Password</h2>

                <p>You requested a password reset for your OuwN account.</p>

                <div style="text-align: center; margin: 30px 0;">
                    <a href="{reset_link}" 
                       style="background:#9975C1;color:white;padding:12px 25px;
                       text-decoration:none;border-radius:8px;font-size:16px;">
                       Reset Password
                    </a>
                </div>

                <p>If you didn't request this, you can ignore this email.</p>
                <p style="margin-top: 30px;">— OuwN Team</p>
            </div>
        </body>
        </html>
        """

        sent = send_brevo_email(
            to_email=email,
            subject="OuwN Password Reset",
            html_body=html_body
        )

        if sent:
            message = "✅ Password reset email sent. Check your inbox."
        else:
            message = "❌ Failed to send email. Please try again."

    return render_template("reset_password.html", message=message)


# ------------------------------------------------------
# STEP 2 — RESET PASSWORD USING TOKEN
# ------------------------------------------------------
@reset_bp.route("/<token>", methods=["GET", "POST"])
def reset_password(token):
    s = get_serializer()
    message = ""

    # Validate token
    try:
        data = s.loads(token, salt="password-reset", max_age=3600)
        email = data["email"]
    except SignatureExpired:
        message = "⚠️ Reset link expired."
        return render_template("reset_password.html", message=message)
    except BadSignature:
        message = "⚠️ Invalid reset link."
        return render_template("reset_password.html", message=message)

    # POST → Update password
    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not password or not confirm:
            message = "Please fill all fields."
            return render_template("reset_token.html", message=message)

        if password != confirm:
            message = "Passwords do not match."
            return render_template("reset_token.html", message=message)

        # Validate password rules
        pw_ok = (
            len(password) >= 8 and
            re.search(r"[A-Z]", password) and
            re.search(r"[a-z]", password) and
            re.search(r"\d", password) and
            re.search(r"[^A-Za-z0-9]", password)
        )

        if not pw_ok:
            message = "Password must include upper, lower, number, and special character."
            return render_template("reset_token.html", message=message)

        # Save new password
        users = db.collection("HealthCareP").where("Email", "==", email).get()
        if not users:
            message = "User not found."
            return render_template("reset_token.html", message=message)

        user_ref = users[0].reference
        user_ref.update({"Password": generate_password_hash(password)})

        flash("✅ Password updated successfully! Please log in.", "success")
        return redirect(url_for("Authentication.login"))

    return render_template("reset_token.html", message=message)
