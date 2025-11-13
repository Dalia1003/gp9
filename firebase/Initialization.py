import os
import json
from firebase_admin import credentials, initialize_app, firestore

firebase_key = os.getenv("FIREBASE_KEY")

if firebase_key:
    cred = credentials.Certificate(json.loads(firebase_key))
else:
    # fallback for local dev
    cred_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "serviceAccountKey.json")
    cred = credentials.Certificate(cred_path)

initialize_app(cred)
db = firestore.client()
