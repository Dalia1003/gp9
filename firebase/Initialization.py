import firebase_admin
from firebase_admin import credentials, firestore
import os

# Use Render secret file
cred = credentials.Certificate("/etc/secrets/serviceAccountKey.json")

firebase_admin.initialize_app(cred)
db = firestore.client()
