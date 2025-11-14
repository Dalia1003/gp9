from flask import Flask, render_template, jsonify, request, session, redirect, url_for, flash
from flask_mail import Mail, Message
from firebase.Initialization import db  # Firestore client
from datetime import datetime, date
import os, json, re
from werkzeug.security import generate_password_hash

# Initialize Mail globally
mail = Mail()

def create_app():
    app = Flask(__name__)

    # ----------------------------
    # Secret Key
    # ----------------------------
    # ----------------------------
# Email Configuration
# ----------------------------
    MAIL_SERVER = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT = os.environ.get("MAIL_PORT", 587)
    try:
        MAIL_PORT = int(MAIL_PORT)
    except (ValueError, TypeError):
        MAIL_PORT = 587  # default fallback
    
    MAIL_USE_TLS = os.environ.get("MAIL_USE_TLS", "true").lower() == "true"
    MAIL_USE_SSL = os.environ.get("MAIL_USE_SSL", "false").lower() == "true"
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME", "")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD", "")
    
    app.config.update(
        MAIL_SERVER=MAIL_SERVER,
        MAIL_PORT=MAIL_PORT,
        MAIL_USE_TLS=MAIL_USE_TLS,
        MAIL_USE_SSL=MAIL_USE_SSL,
        MAIL_USERNAME=MAIL_USERNAME,
        MAIL_PASSWORD=MAIL_PASSWORD
    )


    # Initialize Flask-Mail
    mail.init_app(app)


    # ----------------------------
    # Blueprints
    # ----------------------------
    from routes.Authentication import auth_bp
    app.register_blueprint(auth_bp)

    from routes.auth_reset import reset_bp
    app.register_blueprint(reset_bp)

    # ----------------------------
    # Load ICD Data
    # ----------------------------
    ICD_FILE = os.path.join(app.root_path, "static", "icd_data.json")
    if os.path.exists(ICD_FILE):
        with open(ICD_FILE, "r", encoding="utf-8") as f:
            app.icd_data = json.load(f)
    else:
        app.icd_data = []

    # ----------------------------
    # Routes
    # ----------------------------
    @app.route("/")
    def home():
        return render_template("homePage.html")

    @app.route("/dashboard")
    def dashboard():
        if 'user_id' not in session:
            return redirect(url_for('Authentication.login'))

        patients = []
        try:
            docs = db.collection("Patients").stream()
            for doc in docs:
                data = doc.to_dict()
                patients.append({
                    "ID": doc.id,
                    "FullName": data.get("FullName", "Unknown")
                })
        except Exception as e:
            flash(f"Error fetching patients: {e}", "danger")

        msg = request.args.get('msg', '')
        msg_text = ""
        if msg in ['patient_added', 'added']:
            msg_text = "Patient added successfully!"
        elif msg == 'note_added':
            msg_text = "Medical note and ICD codes added successfully!"

        return render_template("dashboard.html", patients=patients, msg_text=msg_text)

    # ----------------------------
    # Add Patient
    # ----------------------------
    @app.route("/add_patient", methods=["GET", "POST"])
    def add_patient():
        if 'user_id' not in session:
            return redirect(url_for('Authentication.login'))

        errors = []
        if request.method == "POST":
            pid = request.form.get("ID", "").strip()
            name = request.form.get("full_name", "").strip()
            dob = request.form.get("dob", "").strip()
            gender = request.form.get("gender", "").strip()
            phone = request.form.get("phone", "").strip()
            email = request.form.get("email", "").strip()
            address = request.form.get("address", "").strip()
            blood = request.form.get("blood_type", "").strip()

            # Validation
            if not all([pid, name, dob, gender, phone, email, address, blood]):
                errors.append("All fields are required.")

            if pid and not re.match(r'^\d{10}$', pid):
                errors.append("ID must be exactly 10 digits.")
            if phone and not re.match(r'^05\d{8}$', phone):
                errors.append("Phone must start with 05 and be 10 digits.")
            if email and not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
                errors.append("Invalid email format.")

            if dob:
                try:
                    dob_date = datetime.strptime(dob, "%Y-%m-%d").date()
                    if dob_date > date.today():
                        errors.append("Date of Birth cannot be in the future.")
                except ValueError:
                    errors.append("Invalid date format.")

            # Check if patient exists
            if not errors:
                doc_ref = db.collection("Patients").document(pid)
                if doc_ref.get().exists:
                    errors.append("Patient already exists with this ID.")

            if not errors:
                db.collection("Patients").document(pid).set({
                    "FullName": name,
                    "DOB": dob,
                    "Gender": gender,
                    "Phone": phone,
                    "Email": email,
                    "Address": address,
                    "BloodType": blood,
                    "UserID": session['user_id']
                })
                return redirect(url_for("dashboard", msg="added"))

        return render_template("add_patient.html", errors=errors)

    # ----------------------------
    # Add Medical Note with ICD Codes
    # ----------------------------
    @app.route("/MedicalNotes", methods=["GET", "POST"])
    def add_note():
        if 'user_id' not in session:
            return redirect(url_for('Authentication.login'))

        if request.method == "GET":
            prefilled_pid = request.args.get("pid", "")
            return render_template(
                "MedicalNotes.html",
                prefilled_pid=prefilled_pid,
                note_text="",
                selected_icd_codes=[]
            )

        try:
            data = request.get_json() or request.form
            pid = data.get("pid")
            note_text = data.get("note_text")
            icd_codes = data.get("icd_codes", [])

            if not pid or not note_text or not icd_codes:
                return jsonify({"status": "error", "message": "Missing patient ID, note text, or ICD codes"}), 400

            patient_ref = db.collection("Patients").document(pid)
            note_ref = patient_ref.collection("MedicalNotes").document()  # Auto ID
            note_data = {
                "NoteID": note_ref.id,
                "Note": note_text,
                "CreatedDate": datetime.now()
            }
            note_ref.set(note_data)

            # Save each ICD code
            for code in icd_codes:
                icd_ref = note_ref.collection("ICDCode").document()  # Auto ID
                icd_data = {
                    "ICD_ID": icd_ref.id,
                    "Adjusted": [{"Code": code.get("Code"), "Description": code.get("Description")}],
                    "Predicted": [],
                    "AdjustedBy": session.get("user_id"),
                    "AdjustedAt": datetime.now()
                }
                icd_ref.set(icd_data)

            return jsonify({"status": "success", "redirect": url_for("dashboard")})

        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    # ----------------------------
    # Check Patient ID
    # ----------------------------
    @app.route("/check_id")
    def check_id():
        v = request.args.get("v", "").strip()
        exists = False
        if v:
            doc_ref = db.collection("Patients").document(v)
            exists = doc_ref.get().exists
        return jsonify({"exists": exists})

    # ----------------------------
    # ICD Routes
    # ----------------------------
    @app.route("/icd_categories")
    def icd_categories():
        categories = sorted({cat["Category"] for cat in app.icd_data if "Category" in cat})
        categories.insert(0, "All")
        return jsonify(categories)

    @app.route("/icd_by_category/<string:category>")
    def icd_by_category(category):
        results = []
        if category.lower() == "all":
            for cat in app.icd_data:
                results.extend(cat.get("Codes", []))
        else:
            for cat in app.icd_data:
                if cat["Category"].lower() == category.lower():
                    results = cat.get("Codes", [])
                    break
        return jsonify(results[:100])

    @app.route("/search_icd", methods=["GET"])
    def search_icd():
        term = request.args.get("term", "").lower()
        category = request.args.get("category", "").lower()
        if not term:
            return jsonify([])

        results = []
        for cat in app.icd_data:
            if category and category != "all" and cat["Category"].lower() != category:
                continue
            for code in cat.get("Codes", []):
                if term in code["Description"].lower() or term in code["Code"].lower():
                    results.append(code)
        return jsonify(results[:30])

    # ----------------------------
    # Profile
    # ----------------------------
    @app.route("/profile", methods=["GET", "POST"])
    def profile():
        if 'user_id' not in session:
            return redirect(url_for('Authentication.login'))

        doc_id = session['user_id']
        success_msg = ""
        error_msg = ""

        try:
            doc_ref = db.collection('HealthCareP').document(doc_id)
            doc = doc_ref.get()
            current_user = doc.to_dict() if doc.exists else {"Name": "", "UserID": "", "Email": ""}
            if not doc.exists:
                error_msg = "User data not found."
        except Exception as e:
            current_user = {"Name": "", "UserID": "", "Email": ""}
            error_msg = f"Error fetching user data: {e}"

        if request.method == "POST" and request.form.get("action") == "update_profile":
            new_name = request.form.get("name", "").strip()
            new_email = request.form.get("email", "").strip()
            new_username = request.form.get("username", "").strip()

            try:
                if not new_name or not new_email or not new_username:
                    raise ValueError("All fields are required.")
                if not re.match(r"[^@]+@[^@]+\.[^@]+", new_email):
                    raise ValueError("Invalid email format.")

                if new_username != current_user.get("UserID"):
                    query = db.collection("HealthCareP").where("UserID", "==", new_username).get()
                    if query:
                        raise ValueError("Username already taken.")

                doc_ref.update({
                    "Name": new_name,
                    "Email": new_email,
                    "UserID": new_username
                })
                success_msg = "Profile updated successfully."
                current_user = doc_ref.get().to_dict()
            except Exception as e:
                error_msg = str(e)

        return render_template("profile.html", user=current_user, success_msg=success_msg, error_msg=error_msg)

    # ----------------------------
    # Logout
    # ----------------------------
    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("home"))

    return app

# ----------------------------
# Run App
# ----------------------------
if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)




