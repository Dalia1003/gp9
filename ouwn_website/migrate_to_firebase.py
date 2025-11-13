import firebase_admin
from firebase_admin import credentials, firestore
from datetime import datetime
import random

# -----------------------------
# 1️⃣ Connect to Firestore
# -----------------------------
cred = credentials.Certificate("C:/MAMP/htdocs/ouwn_website/serviceAccountKey.json")
firebase_admin.initialize_app(cred)
db = firestore.client()
print("✅ Connected to Firestore")

# -----------------------------
# 2️⃣ Add doctors (email_confirmed=1, random hash for password)
# -----------------------------
doctors = [
    {
        "UserID": "D001",
        "Email": "dr.alotaibi@gmail.com",
        "Name": "Dr. Faisal Alotaibi",
        "Password": "$2b$12$ZnzmdbV5T5fI/jp38zpBquT6.cxI9te1A/cyJE08V6WDxvXpToAAu", #Mohammed@1003
        "email_confirmed": 1
    },
    {
        "UserID": "D002",
        "Email": "dr.ahmed@gmail.com",
        "Name": "Dr. Ahmed Alshammari",
        "Password": "$2b$12$G7fXbW7d8/2kO/r8ZkHpruZnIq.4OIk1lKZK8dJrS2OxP1T8M1fKe", #Ahmed@2025
        "email_confirmed": 1
    }
]

for doc in doctors:
    db.collection("HealthCareP").document(doc["UserID"]).set(doc)
print("👩‍⚕️ Doctors added with email confirmed and hashed passwords.")

# -----------------------------
# 3️⃣ Function for doctor to add a patient
# -----------------------------
def add_patient(patient_id, full_name, dob, address, phone, gender, blood_type):
    """
    Doctor adds a new patient.
    Patients have no password.
    """
    patient_data = {
        "UserID": patient_id,   # National ID
        "FullName": full_name,
        "DOB": dob,
        "Address": address,
        "Phone": phone,
        "Gender": gender,
        "BloodType": blood_type
    }
    db.collection("Patients").document(patient_id).set(patient_data)
    print(f"🧍‍♂️ Patient added: {full_name}")

# -----------------------------
# 4️⃣ Function to add medical note with ICD code (random IDs, Predicted empty)
# -----------------------------
def add_medical_note(patient_id, note_text, adjusted_icd, doctor_id="D001"):
    """
    Add a note and ICD code for a patient.
    Note ID and ICD ID are random numbers 1–1,000,000.
    Predicted is always empty.
    """
    patient_ref = db.collection("Patients").document(patient_id)

    # Random Note ID
    note_id = f"note{random.randint(1, 1_000_000)}"

    note_data = {
        "NoteID": note_id,
        "Note": note_text,
        "CreatedDate": datetime.now()
    }
    note_ref = patient_ref.collection("MedicalNotes").document(note_id)
    note_ref.set(note_data)

    # Random ICD ID
    icd_id = f"icd{random.randint(1, 1_000_000)}"

    icd_data = {
        "ICD_ID": icd_id,
        "Adjusted": [adjusted_icd],
        "Predicted": [],  # always empty
        "AdjustedBy": doctor_id,
        "AdjustedAt": datetime.now()
    }
    note_ref.collection("ICDCode").document(icd_id).set(icd_data)
    print(f"🩺 Note added for patient {patient_id}, ICD assigned: {adjusted_icd} | NoteID: {note_id}, ICD_ID: {icd_id}")

# -----------------------------
# 5️⃣ Example usage
# -----------------------------
add_patient("1111111111", "Noura Alsubaie", datetime(1990, 5, 14), "Riyadh", "0501234567", "F", "O+")
add_patient("2222222222", "Mohammed Alotaibi", datetime(1985, 7, 20), "Jeddah", "0509876543", "M", "O-")

add_medical_note("1111111111", "Patient reports mild headache.", "R51", doctor_id="D001")
add_medical_note("1111111111", "Patient has chest pain.", "I20.9", doctor_id="D002")
add_medical_note("2222222222", "Patient reports dizziness.", "R42", doctor_id="D001")
