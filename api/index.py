from flask import Flask, request, jsonify
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, firestore
import uuid

app = Flask(__name__)
CORS(app)

# ফায়ারবেস অ্যাডমিন সেটআপ (যদি JSON ফাইল থাকে তবেই এটি কাজ করবে)
# যদি কি-ফাইল না থাকে তবে আপাতত সাধারণ লিস্ট দিয়ে টেস্ট করতে পারো
keys_db = [] 

@app.route('/api/generate', methods=['POST'])
def generate_key():
    data = request.json
    email = data.get('email')
    project = data.get('project')
    
    new_key = {
        "id": str(uuid.uuid4())[:8],
        "email": email,
        "project": project,
        "key": f"tc_{uuid.uuid4().hex[:16]}"
    }
    keys_db.append(new_key)
    return jsonify({"status": "success", "key": new_key['key']})

@app.route('/api/my-keys', methods=['POST'])
def get_keys():
    data = request.json
    email = data.get('email')
    user_keys = [k for k in keys_db if k['email'] == email]
    return jsonify(user_keys)

@app.route('/api/delete-key', methods=['POST'])
def delete_key():
    data = request.json
    key_id = data.get('id')
    global keys_db
    keys_db = [k for k in keys_db if k['id'] != key_id]
    return jsonify({"status": "deleted"})

# Vercel এর জন্য এটি জরুরি
def handler(event, context):
    return app(event, context)

if __name__ == '__main__':
    app.run()
