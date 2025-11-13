import os
import json
from firebase_admin import credentials, initialize_app, firestore
import tempfile

# ----------------------------
# Firebase Initialization
# ----------------------------
if not firebase_admin._apps:
    firebase_json = os.environ.get("FIREBASE_JSON")
    if not firebase_json:
        raise Exception("FIREBASE_JSON env variable not found!")

    # Write JSON content to a temp file
    with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.json') as tmp:
        tmp.write(firebase_json)
        tmp_path = tmp.name

    cred = credentials.Certificate(tmp_path)
    initialize_app(cred)

db = firestore.client()
