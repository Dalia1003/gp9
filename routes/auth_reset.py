from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from werkzeug.security import generate_password_hash
from flask_mail import Message
import re
from firebase.Initialization import db  # Firestore client


reset_bp = Blueprint("auth_reset", __name__, url_prefix="/auth/reset")


# ----------------------------
# Serializer for reset tokens
# ----------------------------
def get_serializer():
    return URLSafeTimedSerializer(current_app.secret_key)


# ----------------------------
# Request password reset
# ----------------------------
@reset_bp.route("/request", methods=["GET", "POST"])
def reset_request():
    message = ""

    if request.method == "POST":
        email = request.form.get("email", "").strip()

        if not email:
            return render_template("reset_password.html", message="Please enter your email.")

        # Check Firestore for user
        users = db.collection("HealthCareP").where("Email", "==", email).get()
        if not users:
            return render_template("reset_password.html", message="No account found with this email.")

        # Create token
        s = get_serializer()
        token = s.dumps({"email": email}, salt="password-reset")
        reset_link = url_for("auth_reset.reset_password", token=token, _external=True)

        # Email HTML body
        html_body = f"""
        <html>
        <body style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color: #2d004d; background: #f4eefc; padding: 20px;">
            <div style="max-width: 600px; margin: auto; background: #fff; border-radius: 10px; padding: 30px; box-shadow: 0 5px 15px rgba(0,0,0,0.1);">
                <h2 style="color: #9975C1; text-align: center;">OuwN Password Reset</h2>
                <p>Hi {email},</p>
                <p>You requested to reset your password. Click the button below:</p>

                <div style="text-align: center; margin: 30px 0;">
                    <a href="{reset_link}" style="background: #9975C1; color: white; padding: 12px 25px; text-decoration: none; border-radius: 25px; font-weight: bold;">
                        Reset Password
                    </a>
                </div>

                <p>If you didn’t request this, ignore this email.</p>
                <p>Thanks,<br><strong>OuwN Team</strong></p>
            </div>
        </body>
        </html>
        """

        # Send email
        try:
            msg = Message(
                subject="OuwN Password Reset",
                sender=current_app.config["MAIL_USERNAME"],
                recipients=[email],
                html=html_body
            )
            current_app.extensions['mail'].send(msg)

            message = "✅ Password reset email sent. Check your inbox."

        except Exception as e:
            message = f"Failed to send email: {e}"

        return render_template("reset_password.html", message=message)

    return render_template("reset_password.html", message=message)


# ----------------------------
# Reset password with token
# ----------------------------
@reset_bp.route("/<token>", methods=["GET", "POST"])
def reset_password(token):
    message = ""
    s = get_serializer()

    # Validate token
    try:
        data = s.loads(token, salt="password-reset", max_age=3600)
        email = data.get("email")
    except SignatureExpired:
        return render_template("reset_password.html", message="⚠️ The reset link has expired.")
    except BadSignature:
        return render_template("reset_password.html", message="⚠️ Invalid reset link.")

    if request.method == "POST":
        password = request.form.get("password")
        confirm = request.form.get("confirm_password")

        if not password or not confirm:
            return render_template("reset_token.html", message="Please fill all fields.")

        if password != confirm:
            return render_template("reset_token.html", message="Passwords do not match.")

        # Password strength check
        pw_checks = {
            "len": len(password) >= 8,
            "upper": bool(re.search(r"[A-Z]", password)),
            "lower": bool(re.search(r"[a-z]", password)),
            "digit": bool(re.search(r"\d", password)),
            "special": bool(re.search(r"[^A-Za-z0-9]", password))
        }

        if not all(pw_checks.values()):
            return render_template(
                "reset_token.html",
                message="Password must be at least 8 chars & include upper, lower, number, special."
            )

        # Update Firestore password
        users = db.collection("HealthCareP").where("Email", "==", email).get()
        if users:
            user_ref = users[0].reference
            user_ref.update({"Password": generate_password_hash(password)})

            flash("✅ Password reset successfully! You can now log in.", "success")
            return redirect(url_for("Authentication.login"))

        return render_template("reset_token.html", message="User not found.")

    return render_template("reset_token.html", message=message)
