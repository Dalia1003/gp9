import os
from firebase_admin import credentials, initialize_app

# Get absolute path to the root of the project
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
cred_path = os.path.join(BASE_DIR, "serviceAccountKey.json")

cred = credentials.Certificate(cred_path)
initialize_app(cred)

# Then your db setup
from firebase_admin import firestore
db = firestore.client()
