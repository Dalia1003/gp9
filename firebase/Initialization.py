import os
import json
from firebase_admin import credentials, initialize_app, firestore

# Read the secret file from /etc/secrets/
cred_path = "/etc/secrets/serviceAccountKey.json"
cred_json = json.load(open(cred_path))

cred = credentials.Certificate(cred_json)
initialize_app(cred)

db = firestore.client()
