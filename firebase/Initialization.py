import os
from firebase_admin import credentials, initialize_app, firestore

# Path to secret file on Render
cred_path = "/etc/secrets/serviceAccountKey.json"

# Initialize Firebase
cred = credentials.Certificate(cred_path)
initialize_app(cred)

# Firestore client
db = firestore.client()
