from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from werkzeug.security import generate_password_hash
import re

from firebase.Initialization import db  # Firestore client

# -------------------------
# Brevo API
# -------------------------
import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException

reset_bp = Blueprint("auth_reset", __name__, url_prefix="/auth/reset")


# ======================================================
#  HELPER → Brevo Email Sender
# ======================================================
def send_brevo_email(to_email, subject, html_body):
    configuration = sib_api_v3_sdk.Configuration()
    configuration.api_key["api-key"] = current_app.config["BREVO_API_KEY"]

    api_instance = sib_api_v3_sdk.TransactionalEmailsApi(
        sib_api_v3_sdk.ApiClient(configuration)
    )

    email = sib_api_v3_sdk.SendSmtpEmail(
        to=[{"email": to_email}],
        sender={
            "email": current_app.config["BREVO_SENDER"],
            "name": current_app.config["BREVO_SENDER_NAME"]
        },
        subject=subject,
        html_content=html_body
    )

    try:
        api_instance.send_transac_email(email)
        return True
    except ApiException as e:
        print("❌ Brevo Error:", e)
        return False


# ======================================================
#  TOKEN SERIALIZER
# ======================================================
def get_serializer():
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"])


# ======================================================
#  STEP 1 — REQUEST PASSWORD RESET
# ======================================================
@reset_bp.route("/request", methods=["GET", "POST"])
def reset_request():
    message = ""

    if request.method == "POST":
        email = request.form.get("email", "").strip()

        if not email:
            message = "Please enter your email."
            return render_template("reset_password.html", message=message)

        # Check if user exists
        users = db.collection("HealthCareP").where("Email", "==", email).get()
        if not users:
            message = "No account found with this email."
            return render_template("reset_password.html", message=message)

        # Create reset token
        s = get_serializer()
        token = s.dumps({"email": email}, salt="password-reset")

        reset_link = url_for("auth_reset.reset_password", token=token, _external=True)

        # Email HTML body
        html_body = f"""
        <html>
        <body style="font-family: Arial; background: #f4eefc; padding: 20px;">
            <div style="max-width: 600px; margin: auto; background: #fff; 
                        border-radius: 10px; padding: 30px;
                        box-shadow: 0 5px 15px rgba(0,0,0,0.1);">

                <h2 style="color: #9975C1; text-align: center;">Reset Your Password</h2>

                <p>Hello,</p>
                <p>You requested a password reset for your OuwN account.</p>

                <div style="text-align: center; margin: 30px 0;">
                    <a href="{reset_link}" 
                       style="background: #9975C1; color: white; padding: 12px 25px;
                       text-decoration: none; border-radius: 8px; font-size: 16px;">
                       Reset Password
                    </a>
                </div>

                <p>If you didn't request this, feel free to ignore this email.</p>

                <p style="margin-top: 30px;">— OuwN Team</p>
            </div>
        </body>
        </html>
        """

        # Send email using Brevo
        sent = send_brevo_email(
            to_email=email,
            subject="OuwN Password Reset",
            html_body=html_body
        )

        if sent:
            message = "✅ Password reset email sent. Check your inbox."
        else:
            message = "❌ Failed to send email. Please try again later."

    return render_template("reset_password.html", message=message)


# ======================================================
#  STEP 2 — HANDLE RESET TOKEN PAGE
# ======================================================
@reset_bp.route("/<token>", methods=["GET", "POST"])
def reset_password(token):
    s = get_serializer()
    message = ""

    # Validate token
    try:
        data = s.loads(token, salt="password-reset", max_age=3600)
        email = data["email"]
    except SignatureExpired:
        message = "⚠️ The reset link has expired."
        return render_template("reset_password.html", message=message)
    except BadSignature:
        message = "⚠️ Invalid or corrupted reset link."
        return render_template("reset_password.html", message=message)

    # Handle form submission
    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not password or not confirm:
            message = "Please fill all fields."
            return render_template("reset_token.html", message=message)

        if password != confirm:
            message = "Passwords do not match."
            return render_template("reset_token.html", message=message)

        # Validate password
        pw_checks = {
            "len": len(password) >= 8,
            "upper": re.search(r"[A-Z]", password),
            "lower": re.search(r"[a-z]", password),
            "digit": re.search(r"\d", password),
            "special": re.search(r"[^A-Za-z0-9]", password)
        }

        if not all(pw_checks.values()):
            message = "Password must include upper, lower, digit & special."
            return render_template("reset_token.html", message=message)

        # Update Firestore
        users = db.collection("HealthCareP").where("Email", "==", email).get()

        if not users:
            message = "User not found."
            return render_template("reset_token.html", message=message)

        user_ref = users[0].reference
        user_ref.update({"Password": generate_password_hash(password)})

        flash("Your password has been reset successfully!", "success")
        return redirect(url_for("Authentication.login"))

    return render_template("reset_token.html", message=message)
