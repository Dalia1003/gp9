# ---------------------------------------------------------
#  app.py  —  Main Flask App Entry
# ---------------------------------------------------------
# Loads .env for local development
# Registers blueprints (Authentication + Password Reset)
# Loads ICD data
# Handles dashboard, patient management, ICD search, etc.
# ---------------------------------------------------------

from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, jsonify, request, session, redirect, url_for, flash
from firebase.Initialization import db
from datetime import datetime, date
import os, json, re, uuid
import threading



# ---------------------------------------------------------
# Create Flask App
# ---------------------------------------------------------
def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "fallback-secret-key")
    app.config["PROPAGATE_EXCEPTIONS"] = True

    from routes.Authentication import auth_bp, cleanup_unconfirmed_users_background

    # Detect if running on Render
    IS_RENDER = os.environ.get("RENDER") == "true"
    
    # Only run the cleanup thread on local machine
    if not IS_RENDER:
        threading.Thread(
            target=cleanup_unconfirmed_users_background,
            daemon=True
        ).start()


    # Register blueprints
    from routes.Authentication import auth_bp
    app.register_blueprint(auth_bp)

    from routes.auth_reset import reset_bp
    app.register_blueprint(reset_bp)

    # Load ICD JSON data
    ICD_FILE = os.path.join(app.root_path, "static", "icd_data.json")
    if os.path.exists(ICD_FILE):
        with open(ICD_FILE, "r", encoding="utf-8") as f:
            app.icd_data = json.load(f)
    else:
        print("⚠️ icd_data.json missing in /static")
        app.icd_data = []


    # ---------------------------------------------------------
    # PUBLIC ROUTE
    # ---------------------------------------------------------
    @app.route("/")
    def home():
        return render_template("homePage.html")


    # ---------------------------------------------------------
    # DASHBOARD
    # ---------------------------------------------------------
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

        msg_key = request.args.get('msg', '')
        msg_text = {
            "patient_added": "Patient added successfully!",
            "added": "Patient added successfully!",
            "note_added": "Medical note and ICD codes added successfully!"
        }.get(msg_key, "")

        return render_template("dashboard.html", patients=patients, msg_text=msg_text)


    # ---------------------------------------------------------
    # ADD PATIENT
    # ---------------------------------------------------------
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

            if pid and not re.fullmatch(r'\d{10}', pid):
                errors.append("ID must be exactly 10 digits.")

            if phone and not re.fullmatch(r'^05\d{8}$', phone):
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

            if not errors:
                if db.collection("Patients").document(pid).get().exists:
                    errors.append("Patient already exists with this ID.")

            if not errors:
                db.collection("Patients").document(pid).set({
                    "UserID": pid,                     # PATIENT ID = National ID
                    "FullName": name,
                    "DOB": dob,
                    "Gender": gender,
                    "Phone": phone,
                    "Email": email,
                    "Address": address,
                    "BloodType": blood,
                    "CreatedBy": session['user_id']    #  Doctor who added the patient
                })
                return redirect(url_for("dashboard", msg="added"))

        return render_template("add_patient.html", errors=errors)


    # ---------------------------------------------------------
    # MEDICAL NOTES + ICD CODES
    # ---------------------------------------------------------
    @app.route("/MedicalNotes", methods=["GET", "POST"])
    def add_note():
        if 'user_id' not in session:
            return redirect(url_for('Authentication.login'))

        # GET
        if request.method == "GET":
            return render_template(
                "MedicalNotes.html",
                prefilled_pid=request.args.get("pid", ""),
                note_text="",
                selected_icd_codes=[]
            )

        # POST
        try:
            data = request.get_json() or request.form
            pid = data.get("pid")
            note_text = data.get("note_text")
            icd_codes = data.get("icd_codes", [])

            if not pid or not note_text or not icd_codes:
                return jsonify({"status": "error", "message": "Missing fields"}), 400

            patient_ref = db.collection("Patients").document(pid)

            # Generate custom Note ID
            note_id = "note_id_" + uuid.uuid4().hex[:8]
            note_ref = patient_ref.collection("MedicalNotes").document(note_id)

            note_ref.set({
                "NoteID": note_id,
                "Note": note_text,
                "CreatedDate": datetime.now(),
                "CreatedBy": session.get("user_id")
            })

            # ICD IDs starting with icdcode_id_XXXXX
            icd_id = "icdcode_id_" + uuid.uuid4().hex[:8]

            icd_doc_ref = note_ref.collection("ICDCode").document(icd_id)

            icd_doc_ref.set({
                "ICD_ID": icd_id,
                "Adjusted": [c["Code"] for c in icd_codes],   # ARRAY of ALL selected codes
                "Predicted": [],
                "AdjustedBy": session.get("user_id"),
                "AdjustedAt": datetime.now()
            })

            return jsonify({"status": "success", "redirect": url_for("dashboard")})

        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500


    # ---------------------------------------------------------
    # AJAX CHECK ID
    # ---------------------------------------------------------
    @app.route("/check_id")
    def check_id():
        if 'user_id' not in session:
            return jsonify({"error": "Unauthorized"}), 401

        v = request.args.get("v", "").strip()
        exists = db.collection("Patients").document(v).get().exists if v else False
        return jsonify({"exists": exists})


    # ---------------------------------------------------------
    # ICD ROUTES (secure)
    # ---------------------------------------------------------
    @app.route("/icd_categories")
    def icd_categories():
        if 'user_id' not in session:
            return jsonify({"error": "Unauthorized"}), 401

        categories = sorted({cat["Category"] for cat in app.icd_data})
        categories.insert(0, "All")
        return jsonify(categories)


    @app.route("/icd_by_category/<path:category>")
    def icd_by_category(category):
        if 'user_id' not in session:
            return jsonify({"error": "Unauthorized"}), 401

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
        if 'user_id' not in session:
            return jsonify({"error": "Unauthorized"}), 401

        term = request.args.get("term", "").lower()
        category = request.args.get("category", "").lower()

        if not term:
            return jsonify([])

        results = []
        for cat in app.icd_data:
            if category and category != "all" and cat["Category"].lower() != category:
                continue
            for code in cat["Codes"]:
                if term in code["Code"].lower() or term in code["Description"].lower():
                    results.append(code)

        unique = {item["Code"]: item for item in results}
        return jsonify(list(unique.values())[:30])


    
    # ---------------------------------------------------------
    # PROFILE
    # ---------------------------------------------------------
    @app.route("/profile", methods=["GET", "POST"])
    def profile():
        if 'user_id' not in session:
            return redirect(url_for('Authentication.login'))

        old_id = session['user_id']
        old_ref = db.collection('HealthCareP').document(old_id)
        doc = old_ref.get()

        current_user = doc.to_dict() if doc.exists else {"Name": "", "UserID": "", "Email": ""}

        # ---------- POST (Update Profile) ----------
        if request.method == "POST" and request.form.get("action") == "update_profile":

            new_name = request.form.get("name", "").strip()
            new_email = request.form.get("email", "").strip()
            new_username = request.form.get("username", "").strip()

            try:
                # Required fields
                if not new_name or not new_email or not new_username:
                    flash("All fields are required.", "error")
                    return redirect(url_for("profile"))

                # Email validation
                if not re.match(r"^[^@]+@[^@]+\.[^@]+$", new_email):
                    flash("Invalid email format.", "error")
                    return redirect(url_for("profile"))

                # Username validation
                if not re.fullmatch(r"^[A-Za-z][A-Za-z0-9._-]{2,31}$", new_username):
                    flash("Username must start with a letter and be 3–32 characters.", "error")
                    return redirect(url_for("profile"))

                # If username DID NOT change → just update fields
                if new_username == old_id:
                    old_ref.update({
                        "Name": new_name,
                        "Email": new_email
                    })
                    flash("Profile updated successfully!", "success")
                    return redirect(url_for("profile"))

                # If username CHANGED → create new doc + delete old doc
                new_ref = db.collection("HealthCareP").document(new_username)

                # Check if new username exists
                if new_ref.get().exists:
                    flash("Username already taken.", "error")
                    return redirect(url_for("profile"))

                # Copy data
                new_ref.set({
                    "Name": new_name,
                    "Email": new_email,
                    "UserID": new_username,
                    "Password": current_user["Password"],
                    "email_confirmed": current_user.get("email_confirmed", 1)
                })

                # Delete old document
                old_ref.delete()

                # Update session
                session['user_id'] = new_username
                session['user_name'] = new_name
                session['user_email'] = new_email

                # -----------------------------------------
                # UPDATE CreatedBy & AdjustedBy references
                # -----------------------------------------
                old_doctor_id = old_id
                new_doctor_id = new_username

                # 1️⃣ Update Patients.CreatedBy
                patients = db.collection("Patients").where("CreatedBy", "==", old_doctor_id).stream()
                for p in patients:
                    p.reference.update({"CreatedBy": new_doctor_id})

                # 2️⃣ Update MedicalNotes.CreatedBy
                patients_all = db.collection("Patients").stream()
                for p in patients_all:
                    notes = p.reference.collection("MedicalNotes").where("CreatedBy", "==", old_doctor_id).stream()
                    for n in notes:
                        n.reference.update({"CreatedBy": new_doctor_id})

                # 3️⃣ Update ICDCode.AdjustedBy
                patients_all = db.collection("Patients").stream()
                for p in patients_all:
                    notes = p.reference.collection("MedicalNotes").stream()
                    for n in notes:
                        icds = n.reference.collection("ICDCode").where("AdjustedBy", "==", old_doctor_id).stream()
                        for icd in icds:
                            icd.reference.update({"AdjustedBy": new_doctor_id})

                flash("Profile + all related records updated successfully!", "success")
                return redirect(url_for("profile"))

            except Exception as e:
                flash(str(e), "error")
                return redirect(url_for("profile"))

        return render_template("profile.html", user=current_user)



    # ---------------------------------------------------------
    # LOGOUT
    # ---------------------------------------------------------
    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("home"))

    return app



# ---------------------------------------------------------
# Local Development
# ---------------------------------------------------------
if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)

