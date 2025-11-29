import firebase_admin
from firebase_admin import credentials, firestore


if not firebase_admin._apps:
    cred = credentials.Certificate(r"C:\MAMP\htdocs\ouwn_website\serviceAccountKey.json")
    firebase_admin.initialize_app(cred)

# Get Firestore client
db = firestore.client()
