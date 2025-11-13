import firebase_admin
from firebase_admin import credentials, firestore

# Initialize Firebase
cred = credentials.Certificate("C:/MAMP/htdocs/ouwn_website/serviceAccountKey.json")
firebase_admin.initialize_app(cred)
db = firestore.client()

# List all top-level collections
collections = db.collections()

for coll in collections:
    print(f"Deleting collection: {coll.id}")
    # Delete documents recursively
    docs = coll.stream()
    for doc in docs:
        doc.reference.delete()
        print(f"Deleted document: {doc.id}")

print("✅ All collections cleared")
