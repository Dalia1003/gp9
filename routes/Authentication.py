from flask import Blueprint, request, render_template, redirect, url_for, flash, session, current_app, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from firebase_admin import credentials, firestore, initialize_app
import firebase_admin
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import os
import re
import threading
import traceback
import requests

# ---------------------------------------------
# Blueprint
# ---------------------------------------------
auth_bp = Blueprint("Authentication", __name__)

# ---------------------------------------------
# Firebase Init
# ---------------------------------------------
try:
    if not firebase_admin._apps:
        cred_path = os.environ.get("FIREBASE_CRED_PATH", "serviceAccountKey.json")
        if not os.path.exists(cred_path):
            raise FileNotFoundError(f"Firebase credential file not found: {cred_path}")
        cred = credentials.Certificate(cred_path)
        initialize_app(cred)
    db = firestore.client()
except Exception as e:
    print("❌ Firebase initialization failed:", e)
    traceback.print_exc()
    db = None


# ---------------------------------------------
# Serializer used for email confirmation tokens
# ---------------------------------------------
def get_serializer():
    secret = current_app.config.get("SECRET_KEY")
    if not secret:
        raise RuntimeError("SECRET_KEY is missing")
    return URLSafeTimedSerializer(secret)


# ---------------------------------------------
# Brevo API Email Settings
# ---------------------------------------------
BREVO_API_KEY = os.environ.get("BREVO_API_KEY", "")
BREVO_SENDER_EMAIL = os.environ.get("BREVO_SENDER_EMAIL", "ouwnsystem@gmail.com")
BREVO_SENDER_NAME = os.environ.get("BREVO_SENDER_NAME", "OuwN System")
BREVO_ENDPOINT = "https://api.brevo.com/v3/smtp/email"


# ---------------------------------------------
# Actual email sending using Brevo API
# ---------------------------------------------
def send_brevo_email(to_email, subject, html_body, text_body=None):

    if not BREVO_API_KEY:
        print("❌ BREVO_API_KEY missing (set it in Render Environment Variables)")
        return

    payload = {
        "sender": {
            "email": BREVO_SENDER_EMAIL,
            "name": BREVO_SENDER_NAME,
        },
        "to": [{"email": to_email}],
        "subject": subject,
        "htmlContent": html_body
    }

    if text_body:
        payload["textContent"] = text_body

    headers = {
        "api-key": BREVO_API_KEY,
        "Content-Type": "application/json",
        "accept": "application/json",
    }

    try:
        print(f"📨 Sending Brevo API email to {to_email} ...")
        resp = requests.post(BREVO_ENDPOINT, json=payload, headers=headers, timeout=20)

        if resp.status_code >= 400:
            print(f"❌ Brevo Error {resp.status_code}: {resp.text}")
        else:
            print("✅ Brevo Email Sent:", resp.text)

    except Exception as e:
        print("❌ Brevo Exception:", e)
        traceback.print_exc()


# ---------------------------------------------
# Threaded email sending (non-blocking)
# ---------------------------------------------
def send_brevo_async(to_email, subject, html_body, text_body=None):
    thread = threading.Thread(
        target=send_brevo_email,
        args=(to_email, subject, html_body, text_body),
        daemon=True
    )
    thread.start()


# ---------------------------------------------
# LOGIN ROUTE
# ---------------------------------------------
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
            flash("Database error. Contact admin.", "error")
            return render_template("login.html", entered_username=entered_username)

        try:
            users = db.collection("HealthCareP").where("UserID", "==", username).limit(1).get()
            if not users:
                flash("Invalid username or password.", "error")
                return render_template("login.html", entered_username=entered_username)

            user_doc = users[0]
            user = user_doc.to_dict()

            if not user.get("email_confirmed", 0):
                flash("⚠️ Please confirm your email first.", "error")
                return render_template("login.html", entered_username=entered_username)

            if not check_password_hash(user.get("Password", ""), password):
                flash("Invalid username or password.", "error")
                return render_template("login.html", entered_username=entered_username)

            # Login success
            session["user_id"] = user_doc.id
            session["user_name"] = user.get("Name", username)
            session["user_email"] = user.get("Email", "")

            flash("✅ Logged in successfully!", "success")
            return redirect(url_for("dashboard"))

        except Exception as e:
            print("❌ Login error:", e)
            traceback.print_exc()
            flash("Login failed. Please try again.", "error")

    return render_template("login.html", entered_username=entered_username)


# ---------------------------------------------
# SIGNUP ROUTE
# ---------------------------------------------
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

        # --- Validate fields ---
        if not all([first, last, username, email, password]):
            flash("All fields are required.", "error")
            return render_template("signup.html", entered=entered)

        if len(password) < 8 or not any(c.isupper() for c in password) or not any(c.islower() for c in password) or not any(c.isdigit() for c in password) or not any(not c.isalnum() for c in password):
            flash("Password must include upper, lower, digit, and special char.", "error")
            return render_template("signup.html", entered=entered)

        if db is None:
            flash("Database error.", "error")
            return render_template("signup.html", entered=entered)

        # Duplicate check
        try:
            doc = db.collection("HealthCareP").document(username).get()
            email_docs = db.collection("HealthCareP").where("Email", "==", email).limit(1).get()

            if doc.exists or email_docs:
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

        except Exception as e:
            print("❌ Firestore save error:", e)
            traceback.print_exc()
            flash("Signup failed. Try again.", "error")
            return render_template("signup.html", entered=entered)

        # Send email confirmation
        try:
            s = get_serializer()
            token = s.dumps({"username": username, "email": email}, salt="email-confirm")

            confirm_link = url_for("Authentication.confirm_email", token=token, _external=True)

            subject = "Confirm Your Email - OuwN"
            text_body = f"Hello {first} {last}, please confirm: {confirm_link}"
            html_body = f"""
            <h2>Email Confirmation - OuwN</h2>
            <p>Hello {first} {last},</p>
            <p>Please confirm your account:</p>
            <a href="{confirm_link}">Confirm Email</a>
            """

            send_brevo_async(email, subject, html_body, text_body)

            flash("✅ Account created! Please check your email.", "success")
        except Exception as e:
            print("❌ Failed to send email:", e)
            traceback.print_exc()
            flash("Account created, but email failed.", "error")

        return redirect(url_for("Authentication.login"))

    return render_template("signup.html", entered=entered)


# ---------------------------------------------
# CONFIRMATION ROUTE
# ---------------------------------------------
@auth_bp.route("/confirm/<token>")
def confirm_email(token):
    try:
        s = get_serializer()
        data = s.loads(token, salt="email-confirm", max_age=3600)
    except SignatureExpired:
        return render_template("confirm.html", msg="⚠️ Link expired.")
    except BadSignature:
        return render_template("confirm.html", msg="⚠️ Invalid link.")

    username = data.get("username")

    try:
        doc_ref = db.collection("HealthCareP").document(username)
        doc = doc_ref.get()

        if not doc.exists:
            return render_template("confirm.html", msg="⚠️ User not found.")

        user = doc.to_dict()

        if user.get("email_confirmed", 0):
            return render_template("confirm.html", msg="✔️ Already confirmed.")

        doc_ref.update({"email_confirmed": 1})
        return render_template("confirm.html", msg="🎉 Email confirmed! You can now log in.")

    except Exception as e:
        print("❌ Confirm error:", e)
        traceback.print_exc()
        return render_template("confirm.html", msg="❌ Failed to confirm email.")


# ---------------------------------------------
# AJAX CHECK
# ---------------------------------------------
@auth_bp.route("/check", methods=["GET"])
def check_field():
    field = request.args.get("field", "")
    value = request.args.get("value", "").strip()
    result = {"ok": True, "exists": False, "valid": True}

    try:
        if field == "username":
            result["valid"] = bool(re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", value))
            if result["valid"]:
                result["exists"] = db.collection("HealthCareP").document(value).get().exists

        elif field == "email":
            result["valid"] = "@" in value and "." in value
            if result["valid"]:
                docs = db.collection("HealthCareP").where("Email", "==", value).limit(1).get()
                result["exists"] = bool(docs)

        else:
            result["ok"] = False

    except Exception as e:
        print("❌ AJAX error:", e)
        traceback.print_exc()
        result["ok"] = False

    return jsonify(result)
