import firebase_admin
from firebase_admin import credentials, firestore

# This should match the "File Path" you set in Render
cred_path = "/etc/secrets/serviceAccountKey.json"

cred = credentials.Certificate(cred_path)
firebase_admin.initialize_app(cred)

db = firestore.client()
