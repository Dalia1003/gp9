# routes/Authentication.py
from flask import Blueprint, request, render_template, redirect, url_for, flash, session, current_app, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from firebase_admin import credentials, firestore, initialize_app
import firebase_admin
from flask_mail import Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import re
import os

# ----------------------------
# Blueprint
# ----------------------------
auth_bp = Blueprint("Authentication", __name__)

# ----------------------------
# Firebase Setup (Render-compatible)
# ----------------------------
if not firebase_admin._apps:
    # Render secretFiles path
    cred_path = "/etc/secrets/serviceAccountKey.json"
    cred = credentials.Certificate(cred_path)
    initialize_app(cred)

db = firestore.client()

# ----------------------------
# Serializer for email confirmation
# ----------------------------
def get_serializer():
    return URLSafeTimedSerializer(current_app.secret_key)

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

            session["user_id"] = user_doc.id
            session["user_name"] = user.get("Name") or user.get("UserID")
            session["user_email"] = user.get("Email", "")

            flash("✅ Logged in successfully!", "success")
            return redirect(url_for("dashboard"))

        except Exception as e:
            print("❌ Login error:", e)
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

        if not all([first, last, username, email, password]):
            flash("All fields are required.", "error")
            return render_template("signup.html", entered=entered)

        if len(password) < 8 or not any(c.isupper() for c in password) or not any(c.islower() for c in password) \
                or not any(c.isdigit() for c in password) or not any(not c.isalnum() for c in password):
            flash("Password must include uppercase, lowercase, number, and special character.", "error")
            return render_template("signup.html", entered=entered)

        user_doc = db.collection("HealthCareP").document(username).get()
        email_docs = db.collection("HealthCareP").where("Email", "==", email).get()
        if user_doc.exists or len(email_docs) > 0:
            flash("Username or email already exists.", "error")
            return render_template("signup.html", entered=entered)

        hashed_pw = generate_password_hash(password)
        db.collection("HealthCareP").document(username).set({
            "UserID": username,
            "Email": email,
            "Password": hashed_pw,
            "Name": f"{first} {last}",
            "email_confirmed": 0
        })

        s = get_serializer()
        token = s.dumps({"username": username, "email": email}, salt="email-confirm")
        confirmLink = url_for("Authentication.confirm_email", token=token, _external=True)

        html_body = f"""
        <html>
        <body style="font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;color:#2d004d;background:#f4eefc;padding:20px;">
            <div style="max-width:600px;margin:auto;background:#fff;border-radius:10px;padding:30px;box-shadow:0 5px 15px rgba(0,0,0,0.1);">
            <h2 style="color:#9975C1;text-align:center;">OuwN Email Confirmation</h2>
            <p>Hi {first} {last},</p>
            <p>Welcome! Please confirm your email address by clicking the button below:</p>
            <div style="text-align:center;margin:30px 0;">
                <a href="{confirmLink}" style="background:#9975C1;color:white;padding:12px 25px;text-decoration:none;border-radius:25px;font-weight:bold;">Confirm Email</a>
            </div>
            <p>If you didn't create an account, you can ignore this email.</p>
            <p>Thanks,<br><strong>OuwN Team</strong></p>
            </div>
        </body>
        </html>
        """

        try:
            from app import mail
            msg = Message(
                subject="Confirm Your Email",
                sender=current_app.config["MAIL_USERNAME"],
                recipients=[email],
                html=html_body
            )
            mail.send(msg)
            flash("✅ Account created! Please check your email to confirm your account.", "success")
        except Exception as e:
            print("❌ Email sending failed:", e)
            flash("Account created, but failed to send confirmation email.", "error")

        return redirect(url_for("Authentication.login"))

    return render_template("signup.html", entered=entered)

# ----------------------------
# EMAIL CONFIRMATION ROUTE
# ----------------------------
@auth_bp.route("/confirm/<token>")
def confirm_email(token):
    s = get_serializer()
    try:
        data = s.loads(token, salt="email-confirm", max_age=3600)
    except SignatureExpired:
        return render_template("confirm.html", msg="⚠️ Confirmation link expired. Please sign up again.")
    except BadSignature:
        return render_template("confirm.html", msg="⚠️ Invalid confirmation link.")

    username = data.get("username")
    doc_ref = db.collection("HealthCareP").document(username)
    doc = doc_ref.get()
    if not doc.exists:
        return render_template("confirm.html", msg="⚠️ Account not found.")

    user = doc.to_dict()
    if user.get("email_confirmed", 0):
        return render_template("confirm.html", msg="✅ Account already confirmed!")

    doc_ref.update({"email_confirmed": 1})
    return render_template("confirm.html", msg="✅ Your email has been confirmed! You can now log in.")

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
            if result["valid"]:
                doc = db.collection("HealthCareP").document(value).get()
                result["exists"] = doc.exists
        elif field == "email":
            result["valid"] = "@" in value and "." in value
            if result["valid"]:
                docs = db.collection("HealthCareP").where("Email", "==", value).get()
                result["exists"] = len(docs) > 0
        else:
            result = {"ok": False}
    except Exception as e:
        print("AJAX error:", e)
        result = {"ok": False}

    return jsonify(result)
