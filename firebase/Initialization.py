import os
import firebase_admin
from firebase_admin import credentials, firestore

# ----------------------------
# Firestore Initialization
# ----------------------------

# Use a service account JSON if provided via environment variable
# Render allows you to add files in secret or use base64 env variables
FIREBASE_CREDENTIAL_JSON = os.environ.get("FIREBASE_CREDENTIAL_JSON")

if FIREBASE_CREDENTIAL_JSON:
    import json
    cred_dict = json.loads(FIREBASE_CREDENTIAL_JSON)
    cred = credentials.Certificate(cred_dict)
else:
    # Fallback to local file for development
    cred_path = os.path.join(os.path.dirname(__file__), "serviceAccountKey.json")
    if not os.path.exists(cred_path):
        raise FileNotFoundError("Firebase credentials not found!")
    cred = credentials.Certificate(cred_path)

# Initialize the app only once
if not firebase_admin._apps:
    firebase_admin.initialize_app(cred)

# Firestore client
db = firestore.client()
