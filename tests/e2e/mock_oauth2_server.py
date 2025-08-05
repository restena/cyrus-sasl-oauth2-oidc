#!/usr/bin/env python3
"""
Mock OAuth2/OIDC Server for E2E Testing
Provides JWKS endpoint and token validation for testing
"""

import json
import time
from datetime import datetime, timedelta
from flask import Flask, jsonify, request
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import jwt
import base64

app = Flask(__name__)

# Generate RSA key pair for testing
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# Get public key components for JWKS
public_numbers = public_key.public_numbers()
n = public_numbers.n
e = public_numbers.e

# Convert to base64url encoding
def int_to_base64url(val):
    """Convert integer to base64url encoding"""
    # Convert to bytes
    byte_length = (val.bit_length() + 7) // 8
    val_bytes = val.to_bytes(byte_length, 'big')
    # Base64url encode
    return base64.urlsafe_b64encode(val_bytes).decode('ascii').rstrip('=')

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "timestamp": datetime.utcnow().isoformat()})

@app.route('/.well-known/openid-configuration')
def openid_configuration():
    """OpenID Connect Discovery endpoint"""
    base_url = request.url_root.rstrip('/')
    return jsonify({
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/auth",
        "token_endpoint": f"{base_url}/token",
        "userinfo_endpoint": f"{base_url}/userinfo",
        "jwks_uri": f"{base_url}/.well-known/jwks.json",
        "response_types_supported": ["code", "token", "id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "email", "profile"],
        "claims_supported": ["sub", "email", "name", "preferred_username"]
    })

@app.route('/.well-known/jwks.json')
def jwks():
    """JSON Web Key Set endpoint"""
    return jsonify({
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": "test-key-1",
                "n": int_to_base64url(n),
                "e": int_to_base64url(e)
            }
        ]
    })

@app.route('/token', methods=['POST'])
def token():
    """Token endpoint for client credentials flow"""
    grant_type = request.form.get('grant_type')
    client_id = request.form.get('client_id')
    client_secret = request.form.get('client_secret')
    scope = request.form.get('scope', 'openid email profile')
    
    if grant_type != 'client_credentials':
        return jsonify({"error": "unsupported_grant_type"}), 400
    
    if not client_id:
        return jsonify({"error": "invalid_client"}), 400
    
    # Generate access token
    now = datetime.utcnow()
    payload = {
        'iss': request.url_root.rstrip('/'),
        'sub': f"client_{client_id}",
        'aud': ["test_audience"],
        'exp': int((now + timedelta(hours=1)).timestamp()),
        'iat': int(now.timestamp()),
        'nbf': int(now.timestamp()),
        'scope': scope,
        'client_id': client_id
    }
    
    access_token = jwt.encode(
        payload,
        private_key,
        algorithm='RS256',
        headers={'kid': 'test-key-1'}
    )
    
    return jsonify({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": scope
    })

@app.route('/userinfo')
def userinfo():
    """UserInfo endpoint"""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"error": "invalid_token"}), 401
    
    token = auth_header[7:]  # Remove 'Bearer ' prefix
    
    try:
        # Verify token
        payload = jwt.decode(
            token,
            public_key,
            algorithms=['RS256'],
            audience="test_audience",
            issuer=request.url_root.rstrip('/')
        )
        
        return jsonify({
            "sub": payload.get('sub'),
            "email": f"{payload.get('sub')}@test.local",
            "name": f"Test User {payload.get('sub')}",
            "preferred_username": payload.get('sub')
        })
        
    except jwt.InvalidTokenError as e:
        return jsonify({"error": "invalid_token", "description": str(e)}), 401

@app.route('/generate_token')
def generate_token():
    """Generate a test token (for testing purposes)"""
    subject = request.args.get('sub', 'testuser')
    audience = request.args.get('aud', 'test_audience')
    expires_in = int(request.args.get('expires_in', '3600'))
    scope = request.args.get('scope', 'openid email profile')
    
    now = datetime.utcnow()
    payload = {
        'iss': request.url_root.rstrip('/'),
        'sub': subject,
        'aud': [audience],
        'exp': int((now + timedelta(seconds=expires_in)).timestamp()),
        'iat': int(now.timestamp()),
        'nbf': int(now.timestamp()),
        'scope': scope,
        'email': f"{subject}@test.local",
        'preferred_username': subject
    }
    
    token = jwt.encode(
        payload,
        private_key,
        algorithm='RS256',
        headers={'kid': 'test-key-1'}
    )
    
    return jsonify({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": expires_in,
        "scope": scope,
        "payload": payload
    })

if __name__ == '__main__':
    print("Starting Mock OAuth2 Server...")
    print(f"JWKS endpoint: http://localhost:8080/.well-known/jwks.json")
    print(f"Discovery endpoint: http://localhost:8080/.well-known/openid-configuration")
    print(f"Token generation: http://localhost:8080/generate_token?sub=testuser")
    
    app.run(host='0.0.0.0', port=8080, debug=True)
