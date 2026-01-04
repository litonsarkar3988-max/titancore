import os
import zlib
import base64
import hashlib
import hmac
import secrets
from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

app = Flask(__name__)
CORS(app)

class TitanSupremeCore:
    def __init__(self):
        # Vercel এর জন্য এনভায়রনমেন্টাল আইডি বাইন্ডিং
        self.secret_gate = os.getenv("TITAN_SECRET", "RAHUL_SUPREME_2026")
        self._master_entropy = hashlib.sha512(self.secret_gate.encode()).digest()

    def _generate_kinetic_key(self, salt):
        return HKDF(
            algorithm=hashes.SHA3_512(),
            length=32,
            salt=salt,
            info=b"titan-eternity-void-protocol",
        ).derive(self._master_entropy)

    def power_lock(self, plain_text):
        try:
            salt = secrets.token_bytes(32)
            dynamic_key = self._generate_kinetic_key(salt)
            
            # Layer 1: Compression
            compressed_data = zlib.compress(plain_text.encode())
            
            # Layer 2: ChaCha20
            chacha = ChaCha20Poly1305(dynamic_key)
            nonce1 = secrets.token_bytes(12)
            inter_data = chacha.encrypt(nonce1, compressed_data, b"TITAN_SECURE_AUTH")
            
            # Layer 3: AES-GCM
            aesgcm = AESGCM(dynamic_key)
            nonce2 = secrets.token_bytes(12)
            final_cipher = aesgcm.encrypt(nonce2, inter_data, salt)
            
            # Layer 4: HMAC Signature
            signature = hmac.new(dynamic_key, final_cipher, hashlib.sha3_512).digest()
            
            # Final Ghost Encoding
            full_bundle = salt + nonce1 + nonce2 + signature[:16] + final_cipher
            encoded_payload = base64.b85encode(full_bundle).decode()
            
            return f"TITAN_VOID_{encoded_payload}"
        except Exception as e:
            return f"LOCK_ERROR: {str(e)}"

# ইঞ্জিন ইনিশিয়ালাইজেশন
titan_engine = TitanSupremeCore()

@app.route('/api/generate', methods=['POST'])
def generate():
    data = request.json
    raw_data = data.get('project', 'Unknown_Project')
    # তোমার ইঞ্জিন দিয়ে ডাটা এনক্রিপ্ট করা হচ্ছে
    encrypted_key = titan_engine.power_lock(raw_data)
    
    return jsonify({
        "status": "success",
        "project": raw_data,
        "key": encrypted_key
    })

@app.route('/api/my-keys', methods=['POST'])
def get_keys():
    # আপাতত স্ট্যাটিক ডাটা (ডাটাবেস কানেক্ট করলে এটি ডাইনামিক হবে)
    return jsonify([])

def handler(event, context):
    return app(event, context)
