# JWKS Server with SQLite Implementation

## Overview
An implementation of a RESTful JWKS (JSON Web Key Set) server that manages cryptographic keys for JWT verification. The server stores keys in a SQLite database, handles key expiration, and provides authentication endpoints.

## Features
- RESTful API endpoints
- SQLite database for key storage
- JWT token generation and management
- Support for expired and valid keys
- Parameterized SQL queries for security
- 96% test coverage achieved
- Full points (65/65) on gradebot testing

## Setup Instructions

### Prerequisites
- Python 3.8+
- SQLite3

### Installation
1. Set up Python environment:
```bash
python -m venv venv
venv\Scripts\activate  # On Windows
source venv/bin/activate  # On Unix/MacOS
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Running the Server
```bash
python main.py
```
Server runs on: `http://localhost:8080`

## API Endpoints

### 1. JWKS Endpoint
```
GET /.well-known/jwks.json
```
Returns: Active public keys in JWKS format

### 2. Auth Endpoint
```
POST /auth
```
Parameters:
- `expired` (optional query parameter for expired key)



## Database Structure
```sql
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
```

## Test Coverage
- Test Coverage: 96%
- To run tests:
```bash
coverage run -m unittest test.py
coverage report -m
```

## Testing Results
- Coverage Test: 96% achieved
- Gradebot Score: 65/65 points


## Technical Implementation
- Uses RSA key pairs for JWT signing
- Implements key expiration mechanism
- Secure database operations with parameterized queries
- RESTful API design
- Comprehensive error handling

## Course Information
- Course: CSCE3550
- Assignment: Project 2
- Score: 65/65

## Note
This project is for educational purposes and demonstrates implementation of:
- JWT handling
- Database integration
- Secure coding practices
- API endpoint design
- Test coverage implementation

Author: Ojaswi Subedi (Student ID: 11592640)
