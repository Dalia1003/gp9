import firebase_admin
from firebase_admin import credentials, firestore
import os
import json

print("DEBUG: Starting Firebase Initialization...")
print("DEBUG: FIREBASE_JSON present?", "FIREBASE_JSON" in os.environ)
print("DEBUG: FIREBASE_JSON length:", len(os.environ.get("FIREBASE_JSON", "")))

# Load Firebase JSON from environment variable
firebase_json = os.environ.get("FIREBASE_JSON")

if not firebase_json:
    print("⚠️ FIREBASE_JSON not found in environment variables!")
    raise Exception("FIREBASE_JSON env variable not found!")

try:
    # Convert JSON string to Python dict
    firebase_dict = json.loads(firebase_json)
except json.JSONDecodeError:
    print("⚠️ FIREBASE_JSON is not valid JSON. Check Render variable formatting.")
    raise

# Initialize Firebase once
if not firebase_admin._apps:
    cred = credentials.Certificate(firebase_dict)
    firebase_admin.initialize_app(cred)

db = firestore.client()

