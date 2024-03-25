from flask import Flask, jsonify, request
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
import base64
import sqlite3

app = Flask(__name__)

# Constants
DB_FILE = "totally_not_my_privateKeys.db"
KID_NORMAL = "normal"
KID_EXPIRED = "expired"

# Database Operations
def initialize_database():
    connection = sqlite3.connect(DB_FILE)
    connection.execute('''
        CREATE TABLE IF NOT EXISTS keys (
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    connection.commit()
    connection.close()

def save_private_key_to_database(key_bytes, expiration):
    connection = sqlite3.connect(DB_FILE)
    connection.execute('''
        INSERT INTO keys (key, exp) VALUES (?, ?)
    ''', (key_bytes, expiration))
    connection.commit()
    connection.close()

def read_private_keys_from_database():
    connection = sqlite3.connect(DB_FILE)
    cursor = connection.cursor()
    cursor.execute('''
        SELECT key, exp FROM keys WHERE exp > ?
    ''', (int(datetime.utcnow().timestamp()),))
    rows = cursor.fetchall()
    keys = [{'key': row[0], 'exp': row[1]} for row in rows]
    cursor.close()
    connection.close()
    return keys

# Key Generation
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key, public_key, private_key_bytes, public_key_bytes

# Helper Functions
def extract_private_key_from_bytes(key_bytes):
    private_key = load_pem_private_key(key_bytes, password=None)
    return private_key

def encode_number_to_base64(number):
    byte_representation = number.to_bytes((number.bit_length() + 7) // 8, byteorder='big', signed=False)
    base64url_encoded = base64.urlsafe_b64encode(byte_representation).decode('utf-8').rstrip('=')
    return base64url_encoded

# Initialization
initialize_database()
private_key, _, private_key_bytes, _ = generate_rsa_keys()
expired_key, _, expired_key_bytes, _ = generate_rsa_keys()

expiry_normal = int((datetime.utcnow() + timedelta(hours=1)).timestamp())
expiry_expired = int((datetime.utcnow() - timedelta(hours=1)).timestamp())

save_private_key_to_database(private_key_bytes, expiry_normal)
save_private_key_to_database(expired_key_bytes, expiry_expired)

# Routes
@app.route('/.well-known/jwks.json', methods=['GET'])
def get_jwks():
    if request.method == 'GET':
        keys_data = read_private_keys_from_database()
        numbers = private_key.private_numbers()
        public_key_numbers = numbers.public_numbers
        public_key_n = encode_number_to_base64(public_key_numbers.n)
        public_key_e = encode_number_to_base64(public_key_numbers.e)
        jwks = {
            "keys": [{"kid": KID_NORMAL, "kty": "RSA", "alg": "RS256", "use": "sig", "n": public_key_n, "e": public_key_e}]
        }
        return jsonify(jwks)
    else:
        return jsonify({'message': 'Method Not Allowed'}), 405

@app.route('/auth', methods=['POST'])
def authenticate():
    if request.method == 'POST':
        expired = request.args.get('expired')
        keys_data = read_private_keys_from_database()
        valid_key_info = keys_data[0]  # Using a valid key by default
        expired_key_info = keys_data[1]  # Accessing the expired key from the database
        
        headers = {"kid": KID_NORMAL}
        payload = {"user": "username", "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp())}
        key_info = valid_key_info
        
        if expired == 'true':
            headers["kid"] = KID_EXPIRED
            payload["exp"] = int((datetime.utcnow() - timedelta(hours=1)).timestamp())
            key_info = expired_key_info  # Using the expired key
        
        token = jwt.encode(payload, key_info['key'], algorithm='RS256', headers=headers)
        return token
    else:
        return jsonify({'message': 'Method Not Allowed'}), 405

# Running the app
if __name__ == '__main__':
    app.run(port=8080)
