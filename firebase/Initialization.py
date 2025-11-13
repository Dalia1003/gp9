import firebase_admin
from firebase_admin import credentials, firestore

cred_path = "/etc/secrets/serviceAccountKey.json"  # Render secret path
cred = credentials.Certificate(cred_path)
firebase_admin.initialize_app(cred)

db = firestore.client()
