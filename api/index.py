from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route('/api/generate', methods=['POST'])
def generate():
    data = request.json
    project_name = data.get('project', 'Unknown')
    # তোমার সেই TITAN_VOID কী জেনারেশন লজিক
    generated_key = f"TITAN_VOID_{project_name.upper()}_KEY_777" 
    return jsonify({"status": "success", "key": generated_key})

@app.route('/api/my-keys', methods=['POST'])
def get_keys():
    return jsonify([])

# Vercel এর জন্য এটি সবথেকে গুরুত্বপূর্ণ অংশ
app = app
