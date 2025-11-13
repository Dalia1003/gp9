import os
from firebase_admin import credentials, initialize_app, firestore

cred_path = "/etc/secrets/serviceAccountKey.json"
cred = credentials.Certificate(cred_path)
initialize_app(cred)

db = firestore.client()
