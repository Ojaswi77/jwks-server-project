import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta, timezone
import json
from flask import Flask, jsonify, request

app = Flask(__name__)

@app.route('/')
def home():
    return "Welcome to the JWKS Server!"

def generate_rsa_key():
    # Generate a new RSA key pair
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Serialize the private key in PEM format (for signing JWTs)
    private_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize the public key in PEM format (for serving in JWKS endpoint)
    public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Generate a Key ID (kid) using the current timestamp
    kid = str(datetime.now(timezone.utc).timestamp())

    # Set the expiry of the key (e.g., 1 day from now)
    expiry = datetime.now(timezone.utc) + timedelta(days=1)

    return private_key, public_key, kid, expiry

# Dictionary to store keys (private and public), key IDs, and expiry times
keys_store = []

# Function to add keys to the key store
def add_key_to_store():
    private_key, public_key, kid, expiry = generate_rsa_key()

    # Add a valid key (expiry set for 1 day in the future)
    keys_store.append({
        'private_key': private_key,
        'public_key': public_key,
        'kid': kid,
        'expiry': expiry
    })

    # Add an expired key for testing (expiry set in the past)
    expired_private_key, expired_public_key, expired_kid, expired_expiry = generate_rsa_key()
    expired_expiry = datetime.now(timezone.utc) - timedelta(days=1)  # Set expiry to 1 day in the past
    keys_store.append({
        'private_key': expired_private_key,
        'public_key': expired_public_key,
        'kid': expired_kid,
        'expiry': expired_expiry
    })

    print(f"Added valid key with kid {kid}, expiry {expiry}")
    print(f"Added expired key with kid {expired_kid}, expiry {expired_expiry}")

# Add keys to the store at startup
add_key_to_store()

@app.route('/jwks', methods=['GET'])
def jwks():
    # Only return unexpired public keys
    public_keys = [
        {
            "kid": key["kid"],
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "n": key["public_key"].decode('utf-8').replace("\n", "").strip(),
            "e": "AQAB"
        }
        for key in keys_store if key["expiry"] > datetime.now(timezone.utc)
    ]

    return jsonify({"keys": public_keys})

@app.route('/auth', methods=['POST'])
def auth():
    # Check if the "expired" query parameter is present
    expired = request.args.get('expired', default=False, type=bool)

    # Choose either a valid or expired key
    if expired:
        # Find the expired key
        key_data = next((key for key in keys_store if key["expiry"] < datetime.now(timezone.utc)), None)
    else:
        # Find an unexpired key
        key_data = next((key for key in keys_store if key["expiry"] > datetime.now(timezone.utc)), None)

    if not key_data:
        return jsonify({"error": "No valid key available"}), 400

    # Create a JWT token (valid for 5 minutes)
    token = jwt.encode(
        {
            'user': 'example',
            'exp': datetime.now(timezone.utc) + timedelta(minutes=5) if not expired else datetime.now(timezone.utc) - timedelta(days=1)
        },
        key_data["private_key"],
        algorithm='RS256',
        headers={'kid': key_data["kid"]}
    )

    return jsonify({'token': token})

# Start the Flask app at the end of the file
if __name__ == '__main__':
    app.run(port=8080)
