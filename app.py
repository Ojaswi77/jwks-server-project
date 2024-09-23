from flask import Flask, jsonify, request
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import jwt
import datetime

app = Flask(__name__)

# Dictionary to hold RSA keys and their expiry times
key_store = {}

def create_rsa_key():
    # Generate a new RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Convert the keys into PEM format (Public and Private)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem

# Create and store RSA keys with expiration times and key IDs (kids)
def add_key_to_store():
    kid = str(len(key_store) + 1)
    private_key, public_key = create_rsa_key()
    expiry_time = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)  # Key expires in 10 minutes
    key_store[kid] = {
        'private_key': private_key,
        'public_key': public_key,
        'expiry': expiry_time
    }
    return kid

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    # Create a JSON Web Key Set (JWKS) response
    jwks_response = {
        "keys": []
    }
    
    for kid, key_data in key_store.items():
        # Only return keys that haven't expired
        if key_data['expiry'] > datetime.datetime.utcnow():
            public_key = key_data['public_key']

            # Extract 'n' and 'e' values from the public RSA key
            public_numbers = serialization.load_pem_public_key(
                public_key,
                backend=default_backend()
            ).public_numbers()

            jwk = {
                "kid": kid,
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "n": jwt.utils.base64url_encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder='big')).decode('utf-8'),
                "e": jwt.utils.base64url_encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, byteorder='big')).decode('utf-8')
            }
            jwks_response['keys'].append(jwk)

    return jsonify(jwks_response)


@app.route('/auth', methods=['POST'])
def authenticate():
    expired = request.args.get('expired', 'false').lower() == 'true'
    kid = list(key_store.keys())[0]  # Select the first key from the store

    if expired:
        key_data = key_store[kid]
        expiration = datetime.datetime.utcnow() - datetime.timedelta(minutes=5)  # Set expiration in the past
    else:
        key_data = key_store[kid]
        expiration = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)  # Set expiration in the future

    private_key = key_data['private_key']
    
    # Add `kid` to the JWT header and payload
    token = jwt.encode(
        {"exp": expiration, "kid": kid},  # Include `kid` in the payload
        private_key,
        algorithm="RS256",
        headers={"kid": kid}  # Also include `kid` in the JWT header
    )
    
    return jsonify({"token": token})


# Automatically add an RSA key to the store on startup
add_key_to_store()

if __name__ == '__main__':
    app.run(port=8080)
