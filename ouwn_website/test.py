import firebase_admin
from firebase_admin import credentials, auth

cred = credentials.Certificate("C:/MAMP/htdocs/ouwn_website/serviceAccountKey.json")
firebase_admin.initialize_app(cred)

print("✅ Firebase connected successfully!")
