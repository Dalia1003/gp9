import firebase_admin
from firebase_admin import credentials, firestore

# Path to your key file
cred = credentials.Certificate(r"C:\MAMP\htdocs\ouwn_website\serviceAccountKey.json")

# Initialize only once
if not firebase_admin._apps:
    firebase_admin.initialize_app(cred)

# Get Firestore client
db = firestore.client()
