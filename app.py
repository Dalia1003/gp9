from dotenv import load_dotenv
load_dotenv() # Load environment variables from .env file
from flask import Flask, render_template, jsonify, request, session, redirect, url_for, flash
# Flask → Needed
# render_template → Used for HTML pages
# jsonify → Used for AJAX responses
# request → Used to read form/AJAX data
# session → Needed for login sessions
# redirect, url_for → Needed for redirects
# flash → Needed for error/success messages
from firebase.Initialization import db # Needed — Firestore reference
from datetime import datetime, date
# datetime → Needed for note creation time
# date → Needed for DOB validation
import os, json, re, uuid
# os → file paths, reading .env variables  
# json → loading icd_data.json  
# re → regex validation  
# uuid → unique IDs for notes + ICD records


# Create Flask App
def create_app():
    app = Flask(__name__)
    # secret key for sessions
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "fallback-secret-key")
    app.config["PROPAGATE_EXCEPTIONS"] = True # Allow Flask to show detailed exceptions


     # loading all blueprints (auth + reset)
    from routes.Authentication import auth_bp
    app.register_blueprint(auth_bp)

    from routes.auth_reset import reset_bp
    app.register_blueprint(reset_bp)

    # Load ICD JSON data
    ICD_FILE = os.path.join(app.root_path, "static", "icd_data.json")
    if os.path.exists(ICD_FILE):
        with open(ICD_FILE, "r", encoding="utf-8") as f:
            app.icd_data = json.load(f) # Store JSON in memory
    else:
        print("⚠️ icd_data.json missing in /static")
        app.icd_data = []

    # homePage
    @app.route("/")
    def home():
        return render_template("homePage.html")


    # DASHBOARD
    @app.route("/dashboard")
    def dashboard():
        if 'user_id' not in session: # Block access if not logged in
            return redirect(url_for('Authentication.login'))

        patients = [] # Store all patients to display
        try:
            docs = db.collection("Patient").stream()
            for doc in docs:
                data = doc.to_dict()
                patients.append({
                    "ID": doc.id,
                    "FullName": data.get("FullName", "Unknown")
                })
        except Exception as e:
            flash(f"Error fetching patients: {e}", "danger")

        # message after adding patient
        msg_key = request.args.get('msg', '')
        msg_text = {
            "patient_added": "Patient added successfully!",
            "added": "Patient added successfully!"
        }.get(msg_key, "")

        return render_template("dashboard.html", patients=patients, msg_text=msg_text)


    # ADD PATIENT
    @app.route("/add_patient", methods=["GET", "POST"])
    def add_patient():
        if 'user_id' not in session:
            return redirect(url_for('Authentication.login'))

        errors = [] # Collect validation errors
        # form data
        if request.method == "POST":
            pid = request.form.get("ID", "").strip()
            name = request.form.get("full_name", "").strip()
            dob = request.form.get("dob", "").strip()
            gender = request.form.get("gender", "").strip()
            phone = request.form.get("phone", "").strip()
            email = request.form.get("email", "").strip()
            address = request.form.get("address", "").strip()
            blood = request.form.get("blood_type", "").strip()

            # Required fields check
            if not all([pid, name, dob, gender, phone, email, address, blood]):
                errors.append("All fields are required.")

            # ID format check (National ID must be 10 digits)
            if pid and not re.fullmatch(r'\d{10}', pid):
                errors.append("ID must be exactly 10 digits.")

            # Phone format check
            if phone and not re.fullmatch(r'^05\d{8}$', phone):
                errors.append("Phone must start with 05 and be 10 digits.")

            # Email format check
            if email and not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
                errors.append("Invalid email format.")
            
            # dob validation
            if dob:
                try:
                    dob_date = datetime.strptime(dob, "%Y-%m-%d").date()
                    if dob_date > date.today():
                        errors.append("Date of Birth cannot be in the future.")

                    # 2) Age must be <= 130
                    age = date.today().year - dob_date.year
                    if (date.today().month, date.today().day) < (dob_date.month, dob_date.day):
                        age -= 1

                    if age > 130:
                        errors.append("Age cannot exceed 130 years.")
                except ValueError:
                    errors.append("Invalid date format.")
            # check if patient exists already
            if not errors:
                if db.collection("Patient").document(pid).get().exists:
                    errors.append("Patient already exists with this ID.")
            # save to Firestore if everything is good
            if not errors:
                db.collection("Patient").document(pid).set({
                    "ID": pid,                     # PATIENT ID = National ID
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


    # MEDICAL NOTES + ICD CODES
    @app.route("/MedicalNotes", methods=["GET", "POST"])
    def add_note():
        if 'user_id' not in session:
            return redirect(url_for('Authentication.login'))

        if request.method == "GET":
            return render_template(
                "MedicalNotes.html",
                prefilled_pid=request.args.get("pid", ""),
                note_text="",
                selected_icd_codes=[]
            )

        try:
            data = request.get_json() or request.form
            pid = data.get("pid")
            note_text = data.get("note_text")
            icd_codes = data.get("icd_codes", [])
            
            # check missing fields 
            if not pid or not note_text or not icd_codes:
                return jsonify({"status": "error", "message": "Missing fields"}), 400

            patient_ref = db.collection("Patient").document(pid)

            # Generate unique Note ID
            note_id = "note_id_" + uuid.uuid4().hex[:8]
            note_ref = patient_ref.collection("MedicalNote").document(note_id)

             # saving the note
            note_ref.set({
                "NoteID": note_id,
                "Note": note_text,
                "CreatedDate": datetime.now(),
                "CreatedBy": session.get("user_id")
            })

            # Generate unique icd ID
            icd_id = "icdcode_id_" + uuid.uuid4().hex[:8]
            icd_doc_ref = note_ref.collection("ICDcode").document(icd_id)

             # saving the icd code
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


    # AJAX CHECK ID
    @app.route("/check_id")
    def check_id():
        if 'user_id' not in session:
            return jsonify({"error": "Unauthorized"}), 401

        v = request.args.get("v", "").strip()
        exists = db.collection("Patient").document(v).get().exists if v else False
        return jsonify({"exists": exists})

    
    # extract categories from JSON 
    @app.route("/icd_categories")
    def icd_categories():
        if 'user_id' not in session:
            return jsonify({"error": "Unauthorized"}), 401

        categories = sorted({cat["Category"] for cat in app.icd_data})
        categories.insert(0, "All") # Add "All" option
        return jsonify(categories)


    # Return ICD codes by category
    @app.route("/icd_by_category/<path:category>")
    def icd_by_category(category):
        if 'user_id' not in session:
            return jsonify({"error": "Unauthorized"}), 401

        results = []

        if category.lower() == "all":
             # Return all codes
            for cat in app.icd_data:
                results.extend(cat.get("Codes", []))
        else:
            # Return only selected category
            for cat in app.icd_data:
                if cat["Category"].lower() == category.lower():
                    results = cat.get("Codes", [])
                    break

        return jsonify(results[:100])

    # Search ICD codes by term and code
    @app.route("/search_icd")
    def search_icd():
        if 'user_id' not in session:
            return jsonify({"error": "Unauthorized"}), 401

        term = request.args.get("term", "").lower()
        category = request.args.get("category", "").lower()

        if not term:
            return jsonify([])

        results = []
        # search inside ICD JSON
        for cat in app.icd_data:
            if category and category != "all" and cat["Category"].lower() != category:
                continue
            for code in cat["Codes"]:
                if term in code["Code"].lower() or term in code["Description"].lower():
                    results.append(code)

        # remove duplicates
        unique = {item["Code"]: item for item in results}
        return jsonify(list(unique.values())[:30])

 
    # PROFILE
    @app.route("/profile", methods=["GET", "POST"])
    def profile():
        if 'user_id' not in session:
            return redirect(url_for('Authentication.login'))

        old_id = session['user_id']
        old_ref = db.collection('HealthCareP').document(old_id)
        doc = old_ref.get()

        # Load current user data
        current_user = doc.to_dict() if doc.exists else {"Name": "", "UserID": "", "Email": ""}

        # Update Profile
        if request.method == "POST" and request.form.get("action") == "update_profile":

            new_name = request.form.get("name", "").strip()
            new_email = request.form.get("email", "").strip()
            new_username = request.form.get("username", "").strip()

            try:

                # Email validation
                if not re.match(r"^[^@]+@[^@]+\.[^@]+$", new_email):
                    flash("Invalid email format.", "error")
                    return redirect(url_for("profile"))

                # Username validation
                if not re.fullmatch(r"^[A-Z][A-Za-z0-9._-]{2,31}$", new_username):
                    flash("Username must start with a CAPITAL letter and be 3–32 characters.", "error")
                    return redirect(url_for("profile"))
   
                # No changes → do nothing and show no message
                if (new_name == current_user["Name"] 
                    and new_email == current_user["Email"] 
                    and new_username.strip().lower() == old_id.strip().lower()):
                    return redirect(url_for("profile"))
                
                # Check if email belongs to another user
                email_query = db.collection("HealthCareP").where("Email", "==", new_email).stream()
                for docx in email_query:
                    if docx.id != old_id:  # email belongs to different user
                        return redirect(url_for("profile"))  # silently ignore update
                    
                if new_username.strip().lower() != old_id.strip().lower():
                    all_users = db.collection("HealthCareP").stream()
                    for u in all_users:
                        if u.id.strip().lower() == new_username.strip().lower():
                            return redirect(url_for("profile"))  # silent abort

    
                # updating without username change 
                if new_username.strip().lower() == old_id.strip().lower():
                    old_ref.update({
                        "Name": new_name,
                        "Email": new_email
                    })
                    flash("Profile updated successfully!", "success")
                    return redirect(url_for("profile"))

                # If username CHANGED , create new doc 
                clean_username = new_username.strip()
                new_ref = db.collection("HealthCareP").document(clean_username)


                # Copy data to new doc
                new_ref.set({
                    "Name": new_name,
                    "Email": new_email,
                    "UserID": clean_username,
                    "Password": current_user["Password"]
                })

                # Delete old document
                old_ref.delete()

                # Update session
                session['user_id'] = clean_username
                session['user_name'] = new_name
                session['user_email'] = new_email

                
                # fix all Firestore references that stored the old doctor ID
                old_doctor_id = old_id
                new_doctor_id = new_username

                # Update Patients.CreatedBy
                patients = db.collection("Patient").where("CreatedBy", "==", old_doctor_id).stream()
                for p in patients:
                    p.reference.update({"CreatedBy": new_doctor_id})

                # Update MedicalNotes.CreatedBy
                patients_all = db.collection("Patient").stream()
                for p in patients_all:
                    notes = p.reference.collection("MedicalNote").where("CreatedBy", "==", old_doctor_id).stream()
                    for n in notes:
                        n.reference.update({"CreatedBy": new_doctor_id})

                # Update ICDCode.AdjustedBy
                patients_all = db.collection("Patient").stream()
                for p in patients_all:
                    notes = p.reference.collection("MedicalNote").stream()
                    for n in notes:
                        icds = n.reference.collection("ICDcode").where("AdjustedBy", "==", old_doctor_id).stream()
                        for icd in icds:
                            icd.reference.update({"AdjustedBy": new_doctor_id})

                flash("Profile + all related records updated successfully!", "success")
                return redirect(url_for("profile"))

            except Exception as e:
                flash(str(e), "error")
                return redirect(url_for("profile"))

        return render_template("profile.html", user=current_user)

    @app.route("/check")
    def check_unique():
        if 'user_id' not in session:
            return jsonify({"ok": False, "valid": False, "exists": False})

        field = request.args.get("field", "")
        value = request.args.get("value", "").strip()
        current_user = session['user_id'].strip().lower()

        # 1) Validate empty field
        if not field or not value:
            return jsonify({"ok": True, "valid": False, "exists": False})

        # 2) Username validation
        if field == "username":
            value_lower = value.lower()

            # Local validation rule (Capital letter, 3-32 chars)
            if not re.fullmatch(r"^[A-Z][A-Za-z0-9._-]{2,31}$", value):
                return jsonify({"ok": True, "valid": False, "exists": False})

            # Ignore your own username
            if value_lower == current_user:
                return jsonify({"ok": True, "valid": True, "exists": False})

            # Check Firestore for duplicates
            all_users = db.collection("HealthCareP").stream()
            for u in all_users:
                if u.id.strip().lower() == value_lower:
                    return jsonify({"ok": True, "valid": True, "exists": True})

            return jsonify({"ok": True, "valid": True, "exists": False})


        # 3) Email validation
        if field == "email":
            if not re.match(r"^[^@]+@[^@]+\.[^@]+$", value):
                return jsonify({"ok": True, "valid": False, "exists": False})

            value_lower = value.lower()
            # Ignore your own email
            # (email stored inside Firestore doc)
            user_doc = db.collection("HealthCareP").document(current_user).get()
            if user_doc.exists:
                if user_doc.to_dict().get("Email", "").strip().lower() == value_lower:
                    return jsonify({"ok": True, "valid": True, "exists": False})

            # Check duplicates
            email_query = db.collection("HealthCareP").where("Email", "==", value).stream()
            for doc in email_query:
                if doc.id != current_user:
                    return jsonify({"ok": True, "valid": True, "exists": True})

            return jsonify({"ok": True, "valid": True, "exists": False})

        # 4) Default fallback
        return jsonify({"ok": False, "valid": False, "exists": False})


    # LOGOUT
    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("home"))

    return app

# Local Development
if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)
