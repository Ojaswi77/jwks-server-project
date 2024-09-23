import unittest
import json
from app import app
from datetime import datetime, timedelta

class JWKSAppTest(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def test_jwks_endpoint(self):
        # Test the JWKS endpoint to ensure it returns the proper keys
        response = self.app.get('/.well-known/jwks.json')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('keys', data)
        self.assertGreater(len(data['keys']), 0)

    def test_auth_endpoint_valid(self):
        # Test the /auth endpoint for a valid JWT
        response = self.app.post('/auth')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('token', data)

    def test_auth_endpoint_expired(self):
        # Test the /auth endpoint with an expired JWT
        response = self.app.post('/auth?expired=true')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('token', data)

    def test_jwks_with_invalid_method(self):
        # Test JWKS endpoint with invalid methods
        methods = ['POST', 'PUT', 'DELETE', 'PATCH']
        for method in methods:
            response = self.app.open('/.well-known/jwks.json', method=method)
            self.assertEqual(response.status_code, 405)

    def test_auth_with_invalid_method(self):
        # Test auth endpoint with invalid methods
        methods = ['GET', 'PUT', 'DELETE', 'PATCH']
        for method in methods:
            response = self.app.open('/auth', method=method)
            self.assertEqual(response.status_code, 405)

    def test_invalid_jwt(self):
        # Test with an invalid JWT to ensure it's rejected
        response = self.app.post('/auth', headers={'Authorization': 'Bearer invalidtoken'})
        self.assertNotEqual(response.status_code, 200)

    def test_expired_jwt(self):
        # Ensure expired JWT is handled correctly
        expired_time = datetime.utcnow() - timedelta(minutes=1)
        expired_token = jwt.encode({"exp": expired_time}, 'secret', algorithm="HS256")
        response = self.app.post('/auth', headers={'Authorization': f'Bearer {expired_token}'})
        self.assertNotEqual(response.status_code, 200)


if __name__ == '__main__':
    unittest.main()
