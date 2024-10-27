from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import os

host = "0.0.0.0"
port = 8080

def initialize_db():
    """Create SQLite database and keys table if they don't exist"""
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    
    # Create table with explicit column definitions
    create_table_sql = '''CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )'''
    cursor.execute(create_table_sql)
    conn.commit()
    conn.close()

def create_and_save_keys():
    """Generate and store both valid and expired keys in the database"""
    # Generate RSA keys
    active_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    expired_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Serialize keys to PEM format
    active_pem = active_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    expired_pem = expired_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Calculate expiration times
    active_expiration = int((datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)).timestamp())
    expired_expiration = int((datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=1)).timestamp())
    
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    
    # Insert active key into the DB
    insert_key_sql = "INSERT INTO keys (key, exp) VALUES (?, ?)"
    cursor.execute(insert_key_sql, (active_pem, active_expiration))
    
    # Insert expired key into the DB
    cursor.execute(insert_key_sql, (expired_pem, expired_expiration))
    
    conn.commit()
    conn.close()

def fetch_key(expired=False):
    """Retrieve a key from the database based on its expiration status"""
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    
    current_time = int(datetime.datetime.now(datetime.UTC).timestamp())
    
    if expired:
        query_sql = "SELECT kid, key, exp FROM keys WHERE exp < ? ORDER BY exp DESC LIMIT 1"
        cursor.execute(query_sql, (current_time,))
    else:
        query_sql = "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp DESC LIMIT 1"
        cursor.execute(query_sql, (current_time,))
    
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return {
            'kid': str(result[0]),
            'key': serialization.load_pem_private_key(result[1], password=None),
            'exp': result[2]
        }
    return None

def fetch_all_valid_keys():
    """Get all valid keys from the database"""
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    
    current_time = int(datetime.datetime.now(datetime.UTC).timestamp())
    fetch_keys_sql = "SELECT kid, key FROM keys WHERE exp > ?"
    cursor.execute(fetch_keys_sql, (current_time,))
    
    valid_keys = cursor.fetchall()
    conn.close()
    return valid_keys

def integer_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    hex_value = format(value, 'x')
    if len(hex_value) % 2 == 1:
        hex_value = '0' + hex_value
    byte_value = bytes.fromhex(hex_value)
    base64_value = base64.urlsafe_b64encode(byte_value).rstrip(b'=')
    return base64_value.decode('utf-8')

class JWKSHandler(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self):
        parsed_url = urlparse(self.path)
        params = parse_qs(parsed_url.query)
        
        if parsed_url.path == "/auth":
            expired_key_required = 'expired' in params
            key_data = fetch_key(expired=expired_key_required)
            
            if not key_data:
                self.send_response(500)
                self.end_headers()
                return
            
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length) if content_length > 0 else None
            
            if body:
                try:
                    auth_data = json.loads(body)
                    username = auth_data.get('username')
                    password = auth_data.get('password')
                    if username != "userABC" or password != "password123":
                        self.send_response(401)
                        self.end_headers()
                        return
                except json.JSONDecodeError:
                    pass
            
            headers = {
                "kid": key_data['kid']
            }
            
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.fromtimestamp(key_data['exp'], tz=datetime.UTC)
            }
            
            signed_jwt = jwt.encode(
                token_payload, 
                key_data['key'], 
                algorithm="RS256", 
                headers=headers
            )
            
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(signed_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            valid_keys = fetch_all_valid_keys()
            
            jwks_keys = []
            for kid, key_pem in valid_keys:
                private_key = serialization.load_pem_private_key(key_pem, password=None)
                numbers = private_key.private_numbers()
                
                jwks_keys.append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": str(kid),
                    "n": integer_to_base64(numbers.public_numbers.n),
                    "e": integer_to_base64(numbers.public_numbers.e),
                })
            
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            
            jwks_response = {"keys": jwks_keys}
            self.wfile.write(bytes(json.dumps(jwks_response), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

if __name__ == "__main__":
    if not os.path.exists('totally_not_my_privateKeys.db'):
        initialize_db()
        create_and_save_keys()
    
    server = HTTPServer((host, port), JWKSHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass

    server.server_close()
