# ---------------------------------------------------------
#  app.py  —  Main Flask App Entry
# ---------------------------------------------------------
# Loads .env for local development
# Registers blueprints (Authentication + Password Reset)
# Loads ICD data
# Handles dashboard, patient management, ICD search, etc.
# ---------------------------------------------------------

from dotenv import load_dotenv     # Load .env variables locally
load_dotenv()                      # Must be FIRST before imports using env vars

from flask import Flask, render_template, jsonify, request, session, redirect, url_for, flash
from firebase.Initialization import db   # Firebase initialized ONLY in Initialization.py
from datetime import datetime, date
import os, json, re


# ---------------------------------------------------------
# Create Flask App
# ---------------------------------------------------------
def create_app():
    app = Flask(__name__)

    # ----------------------------
    # Secret Key (used for sessions + tokens)
    # If SECRET_KEY not found in environment → fallback
    # ----------------------------
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "fallback-secret-key")
    app.config["PROPAGATE_EXCEPTIONS"] = True

    # -----------------------------------------------------
    # No Flask-Mail Here
    # No Firebase Initialization Here
    #
    # Firebase Admin is initialized ONLY inside:
    #     firebase/Initialization.py
    #
    # Emails are sent via Brevo API inside routes/*.py
    # -----------------------------------------------------

    # ----------------------------
    # Register Blueprints
    # ----------------------------
    from routes.Authentication import auth_bp
    app.register_blueprint(auth_bp)

    from routes.auth_reset import reset_bp
    app.register_blueprint(reset_bp)

    # ----------------------------
    # Load ICD JSON Data
    # ----------------------------
    ICD_FILE = os.path.join(app.root_path, "static", "icd_data.json")

    if os.path.exists(ICD_FILE):
        with open(ICD_FILE, "r", encoding="utf-8") as f:
            app.icd_data = json.load(f)
    else:
        print("⚠️ icd_data.json missing in /static")
        app.icd_data = []


    # ---------------------------------------------------------
    # ROUTES
    # ---------------------------------------------------------

    @app.route("/")
    def home():
        return render_template("homePage.html")


    # ----------------------------
    # Dashboard
    # ----------------------------
    @app.route("/dashboard")
    def dashboard():
        if 'user_id' not in session:
            return redirect(url_for('Authentication.login'))

        patients = []

        try:
            # Fetch all patients from Firestore
            docs = db.collection("Patients").stream()
            for doc in docs:
                data = doc.to_dict()
                patients.append({
                    "ID": doc.id,
                    "FullName": data.get("FullName", "Unknown")
                })

        except Exception as e:
            flash(f"Error fetching patients: {e}", "danger")

        # Display success messages
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

            # ----- Validation -----
            if not all([pid, name, dob, gender, phone, email, address, blood]):
                errors.append("All fields are required.")

            if pid and not re.match(r'^\d{10}$', pid):
                errors.append("ID must be exactly 10 digits.")

            if phone and not re.match(r'^05\d{8}$', phone):
                errors.append("Phone must start with 05 and be 10 digits.")

            if email and not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
                errors.append("Invalid email format.")

            # Validate DOB
            if dob:
                try:
                    dob_date = datetime.strptime(dob, "%Y-%m-%d").date()
                    if dob_date > date.today():
                        errors.append("Date of Birth cannot be in the future.")
                except ValueError:
                    errors.append("Invalid date format.")

            # Check duplicate ID
            if not errors:
                if db.collection("Patients").document(pid).get().exists:
                    errors.append("Patient already exists with this ID.")

            # ----- Save to Firestore -----
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
    # Add Medical Notes + ICD Codes
    # ----------------------------
    @app.route("/MedicalNotes", methods=["GET", "POST"])
    def add_note():
        if 'user_id' not in session:
            return redirect(url_for('Authentication.login'))

        # GET /MedicalNotes
        if request.method == "GET":
            return render_template(
                "MedicalNotes.html",
                prefilled_pid=request.args.get("pid", ""),
                note_text="",
                selected_icd_codes=[]
            )

        # POST /MedicalNotes
        try:
            data = request.get_json() or request.form
            pid = data.get("pid")
            note_text = data.get("note_text")
            icd_codes = data.get("icd_codes", [])

            if not pid or not note_text or not icd_codes:
                return jsonify({"status": "error", "message": "Missing fields"}), 400

            # Save Note
            patient_ref = db.collection("Patients").document(pid)
            note_ref = patient_ref.collection("MedicalNotes").document()

            note_ref.set({
                "NoteID": note_ref.id,
                "Note": note_text,
                "CreatedDate": datetime.now(),
                "CreatedBy": session.get("user_id")
            })

            # Save ICD Codes
            for code in icd_codes:
                icd_ref = note_ref.collection("ICDCode").document()
                icd_ref.set({
                    "ICD_ID": icd_ref.id,
                    "Adjusted": [{"Code": code["Code"], "Description": code["Description"]}],
                    "Predicted": [],
                    "AdjustedBy": session.get("user_id"),
                    "AdjustedAt": datetime.now()
                })

            return jsonify({"status": "success", "redirect": url_for("dashboard")})

        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500


    # ----------------------------
    # Check ID (AJAX)
    # ----------------------------
    @app.route("/check_id")
    def check_id():
        v = request.args.get("v", "").strip()
        exists = db.collection("Patients").document(v).get().exists if v else False
        return jsonify({"exists": exists})


    # ----------------------------
    # ICD Routes
    # ----------------------------
    @app.route("/icd_categories")
    def icd_categories():
        categories = sorted({cat["Category"] for cat in app.icd_data})
        categories.insert(0, "All")
        return jsonify(categories)

    @app.route("/icd_by_category/<category>")
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

    @app.route("/search_icd")
    def search_icd():
        term = request.args.get("term", "").lower()
        category = request.args.get("category", "").lower()

        if not term:
            return jsonify([])

        results = []
        for cat in app.icd_data:
            if category and category != "all" and cat["Category"].lower() != category:
                continue
            for code in cat["Codes"]:
                if term in code["Description"].lower() or term in code["Code"].lower():
                    results.append(code)

        # Remove duplicates by ICD Code
        unique = {item["Code"]: item for item in results}

        return jsonify(list(unique.values())[:30])


    # ----------------------------
    # Profile
    # ----------------------------
    @app.route("/profile", methods=["GET", "POST"])
    def profile():
        if 'user_id' not in session:
            return redirect(url_for('Authentication.login'))

        user_id = session['user_id']
        doc_ref = db.collection('HealthCareP').document(user_id)
        doc = doc_ref.get()

        current_user = doc.to_dict() if doc.exists else {"Name": "", "UserID": "", "Email": ""}
        success_msg = ""
        error_msg = ""

        if request.method == "POST" and request.form.get("action") == "update_profile":
            new_name = request.form.get("name", "").strip()
            new_email = request.form.get("email", "").strip()
            new_username = request.form.get("username", "").strip()

            try:
                # Validate fields
                if not new_name or not new_email or not new_username:
                    raise ValueError("All fields are required.")

                if not re.match(r"[^@]+@[^@]+\.[^@]+", new_email):
                    raise ValueError("Invalid email format.")

                # Username change check
                if new_username != current_user["UserID"]:
                    if db.collection("HealthCareP").document(new_username).get().exists:
                        raise ValueError("Username already taken.")

                # Update Firestore
                doc_ref.update({
                    "Name": new_name,
                    "Email": new_email,
                    "UserID": new_username
                })

                success_msg = "Profile updated successfully."
                current_user = doc_ref.get().to_dict()

            except Exception as e:
                error_msg = str(e)

        return render_template("profile.html",
            user=current_user,
            success_msg=success_msg,
            error_msg=error_msg
        )


    # ----------------------------
    # Logout
    # ----------------------------
    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("home"))

    return app



# ---------------------------------------------------------
# Run App (Local Development)
# ---------------------------------------------------------
if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)
