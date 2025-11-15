from flask import Blueprint, request, render_template, redirect, url_for, flash, session, current_app, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from firebase_admin import credentials, firestore, initialize_app
import firebase_admin
from email.mime.text import MIMEText
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import os
import re
import threading
import traceback

# ----------------------------
# Blueprint
# ----------------------------
auth_bp = Blueprint("Authentication", __name__)

# ----------------------------
# Firebase Setup (robust)
# ----------------------------
try:
    if not firebase_admin._apps:
        cred_path = os.environ.get("FIREBASE_CRED_PATH", "serviceAccountKey.json")
        if not os.path.exists(cred_path):
            raise FileNotFoundError(f"Firebase credential file not found: {cred_path}")
        cred = credentials.Certificate(cred_path)
        initialize_app(cred)
    db = firestore.client()
except Exception as e:
    # If Firebase fails to initialize, we still import the blueprint, but keep db=None
    print("❌ Firebase initialization failed:", e)
    traceback.print_exc()
    db = None

# ----------------------------
# Serializer for email confirmation
# ----------------------------

def get_serializer():
    secret = current_app.config.get("SECRET_KEY")
    if not secret:
        raise RuntimeError("SECRET_KEY is not configured - required for token generation")
    return URLSafeTimedSerializer(secret)

# ----------------------------
# Helper: get_mail() - safe access to flask-mail instance
# ----------------------------

def get_mail():
    # Prefer the extension registered on current_app. This is the standard way.
    mail_ext = current_app.extensions.get("mail") if hasattr(current_app, "extensions") else None
    if mail_ext:
        return mail_ext
    # Fallback: try importing the `mail` global from app module to support older layouts
    try:
        from app import mail as global_mail  # noqa: WPS433 - local import to avoid circular at import time
        return global_mail
    except Exception:
        return None

# ----------------------------
# BREVO SMTP Email Sending helper (Render compatible)
# ----------------------------
import smtplib
from email.mime.multipart import MIMEMultipart

BREVO_HOST = "smtp-relay.brevo.com"
BREVO_PORT = 587

# Username is always "apikey" for Brevo
BREVO_USERNAME = "apikey"
BREVO_PASSWORD = os.environ.get("BREVO_SMTP_KEY", "")  # Store API Key in env


def send_async_email(app, msg):
    """Send email through Brevo SMTP inside app context."""
    try:
        with app.app_context():
            if not BREVO_PASSWORD:
                print("❌ BREVO_SMTP_KEY is missing in environment variables.")
                return

            try:
                server = smtplib.SMTP(BREVO_HOST, BREVO_PORT)
                server.starttls()
                server.login(BREVO_USERNAME, BREVO_PASSWORD)
                server.send_message(msg)
                server.quit()
                print("📨 Email sent via Brevo SMTP")
            except Exception as e:
                print("❌ SMTP Send Failed:", e)
                traceback.print_exc()
    except Exception as outer:
        print("❌ Async email top-level failure:", outer)
        traceback.print_exc()
# ----------------------------

def send_async_email(app, msg):
    """Send email inside provided app context in a daemon thread. Logs errors."""
    try:
        with app.app_context():
            mail = get_mail()
            if not mail:
                print("❌ No mail extension found to send the message")
                return
            # mail might be either the Mail instance or the extension wrapper
            try:
                # If mail has attribute `send`, call it
                mail.send(msg)
            except Exception as e:
                # Some Flask-Mail versions store the Mail instance under mail.mail, try that
                try:
                    getattr(mail, "mail").send(msg)
                except Exception:
                    print("❌ Async email sending failed:", e)
                    traceback.print_exc()
    except Exception as outer_e:
        print("❌ send_async_email top-level failure:", outer_e)
        traceback.print_exc()

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

        if db is None:
            flash("Server configuration error (database). Contact admin.", "error")
            return render_template("login.html", entered_username=entered_username)

        try:
            users = db.collection("HealthCareP").where("UserID", "==", username).limit(1).get()
            if not users:
                flash("Username or password is invalid.", "error")
                return render_template("login.html", entered_username=entered_username)

            user_doc = users[0]
            user = user_doc.to_dict()

            if not user.get("email_confirmed", 0):
                flash("⚠️ Please confirm your email before logging in.", "error")
                return render_template("login.html", entered_username=entered_username)

            if not check_password_hash(user.get("Password", ""), password):
                flash("Username or password is invalid.", "error")
                return render_template("login.html", entered_username=entered_username)

            # Successful login
            session["user_id"] = user_doc.id
            session["user_name"] = user.get("Name") or user.get("UserID")
            session["user_email"] = user.get("Email", "")

            flash("✅ Logged in successfully!", "success")
            return redirect(url_for("dashboard"))

        except Exception as e:
            print("❌ Login error:", e)
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

        # Basic validation
        if not all([first, last, username, email, password]):
            flash("All fields are required.", "error")
            return render_template("signup.html", entered=entered)

        # Password strength
        if len(password) < 8 or not any(c.isupper() for c in password) or not any(c.islower() for c in password) \
                or not any(c.isdigit() for c in password) or not any(not c.isalnum() for c in password):
            flash("Password must include uppercase, lowercase, number, and special character.", "error")
            return render_template("signup.html", entered=entered)

        if db is None:
            flash("Server configuration error (database). Contact admin.", "error")
            return render_template("signup.html", entered=entered)

        # Check duplicates (username and email)
        try:
            user_doc = db.collection("HealthCareP").document(username).get()
            email_docs = db.collection("HealthCareP").where("Email", "==", email).limit(1).get()
            if user_doc.exists or len(email_docs) > 0:
                flash("Username or email already exists.", "error")
                return render_template("signup.html", entered=entered)

            # Save user (hashed password, email_confirmed=0)
            hashed_pw = generate_password_hash(password)
            db.collection("HealthCareP").document(username).set({
                "UserID": username,
                "Email": email,
                "Password": hashed_pw,
                "Name": f"{first} {last}",
                "email_confirmed": 0
            })

        except Exception as e:
            print("❌ Firestore save failed:", e)
            traceback.print_exc()
            flash("Failed to create account. Contact admin.", "error")
            return render_template("signup.html", entered=entered)

        # Email confirmation token + message
        try:
            s = get_serializer()
            token = s.dumps({"username": username, "email": email}, salt="email-confirm")
            confirm_link = url_for("Authentication.confirm_email", token=token, _external=True)

            html_body = f"""
            <html>
            <body style="font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;color:#2d004d;background:#f4eefc;padding:20px;">
                <div style="max-width:600px;margin:auto;background:#fff;border-radius:10px;padding:30px;box-shadow:0 5px 15px rgba(0,0,0,0.1);">
                <h2 style="color:#9975C1;text-align:center;">OuwN Email Confirmation</h2>
                <p>Hi {first} {last},</p>
                <p>Welcome! Please confirm your email address by clicking the button below:</p>
                <div style="text-align:center;margin:30px 0;">
                    <a href="{confirm_link}" style="background:#9975C1;color:white;padding:12px 25px;text-decoration:none;border-radius:25px;font-weight:bold;">Confirm Email</a>
                </div>
                <p>If you didn't create an account, you can ignore this email.</p>
                <p>Thanks,<br><strong>OuwN Team</strong></p>
                </div>
            </body>
            </html>
            """

            # Build message
            sender = current_app.config.get("MAIL_DEFAULT_SENDER") or current_app.config.get("MAIL_USERNAME")
            msg = MIMEMultipart()(
                subject="Confirm Your Email",
                
                
                
            )

            msg['From'] = sender
            msg['To'] = email
            msg['Subject'] = "Confirm Your Email"
            msg.attach(MIMEText(html_body, 'html'))

            # Send async (daemon thread)
            thread = threading.Thread(target=send_async_email, args=(current_app._get_current_object(), msg), daemon=True)
            thread.start()
            flash("✅ Account created! Please check your email to confirm your account.", "success")

        except Exception as e:
            print("❌ Email sending failed:", e)
            traceback.print_exc()
            flash("Account created, but failed to send confirmation email. Please contact support.", "error")

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
        return render_template("confirm.html", msg="⚠️ Confirmation link expired. Please sign up again.")
    except BadSignature:
        return render_template("confirm.html", msg="⚠️ Invalid confirmation link.")

    username = data.get("username")
    if not username:
        return render_template("confirm.html", msg="⚠️ Invalid confirmation data.")

    if db is None:
        return render_template("confirm.html", msg="Server error - contact admin.")

    try:
        doc_ref = db.collection("HealthCareP").document(username)
        doc = doc_ref.get()
        if not doc.exists:
            return render_template("confirm.html", msg="⚠️ Account not found.")

        user = doc.to_dict()
        if user.get("email_confirmed", 0):
            return render_template("confirm.html", msg="✅ Account already confirmed!")

        doc_ref.update({"email_confirmed": 1})
        return render_template("confirm.html", msg="✅ Your email has been confirmed! You can now log in.")

    except Exception as e:
        print("❌ Confirmation update failed:", e)
        traceback.print_exc()
        return render_template("confirm.html", msg="⚠️ Failed to confirm account. Contact support.")

# ----------------------------
# AJAX CHECK FIELD
# ----------------------------
@auth_bp.route("/check", methods=["GET"]) 
def check_field():
    field = request.args.get("field", "")
    value = request.args.get("value", "").strip()
    result = {"ok": True, "exists": False, "valid": True}

    try:
        if field == "username":
            result["valid"] = bool(re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", value))
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
        traceback.print_exc()
        result = {"ok": False}

    return jsonify(result)
