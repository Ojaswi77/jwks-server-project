import unittest
import requests
import json

class JWKSAPITests(unittest.TestCase):
    
    def setUp(self):
        """Setup test environment, ensuring the server is running"""
        # Assuming the server is already running on localhost:8080
        self.base_url = "http://localhost:8080"
    
    def test_valid_auth(self):
        """Test the /auth endpoint for valid credentials and keys"""
        auth_data = {"username": "userABC", "password": "password123"}
        response = requests.post(f"{self.base_url}/auth", json=auth_data)
        
        self.assertEqual(response.status_code, 200, "Expected status code 200 for valid credentials")
        jwt_token = response.text
        self.assertTrue(jwt_token, "JWT should be returned upon successful authentication")
    
    def test_jwks_response(self):
        """Test the /well-known/jwks.json endpoint for valid JWKS response"""
        response = requests.get(f"{self.base_url}/.well-known/jwks.json")
        
        self.assertEqual(response.status_code, 200, "Expected status code 200 for valid JWKS response")
        jwks_response = response.json()
        
        self.assertIn("keys", jwks_response, "JWKS response should contain 'keys' field")
        self.assertGreaterEqual(len(jwks_response["keys"]), 1, "There should be at least one valid key in JWKS response")
    
    def test_invalid_auth(self):
        """Test the /auth endpoint with invalid credentials"""
        invalid_auth_data = {"username": "invalidUser", "password": "wrongPassword"}
        response = requests.post(f"{self.base_url}/auth", json=invalid_auth_data)
        
        self.assertEqual(response.status_code, 401, "Expected status code 401 for invalid credentials")

if __name__ == "__main__":
    unittest.main()
