#!/usr/bin/env python3
"""
End-to-End Tests for OAuth2 SASL Plugin
Tests the complete authentication flow with real Cyrus IMAP server
"""

import os
import sys
import time
import json
import base64
import subprocess
import tempfile
import shutil
from typing import Dict, List, Optional, Tuple
import requests
import imaplib
import socket
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
import jwt


class OAuth2TestConfig:
    """Configuration for OAuth2 E2E tests"""
    
    def __init__(self):
        # Test server configuration
        self.imap_host = os.getenv('TEST_IMAP_HOST', 'localhost')
        self.imap_port = int(os.getenv('TEST_IMAP_PORT', '143'))
        self.imap_ssl_port = int(os.getenv('TEST_IMAP_SSL_PORT', '993'))
        
        # OAuth2 configuration
        self.issuer = os.getenv('TEST_OAUTH2_ISSUER', 'https://test.issuer.com')
        self.client_id = os.getenv('TEST_OAUTH2_CLIENT_ID', 'test_client_id')
        self.audience = os.getenv('TEST_OAUTH2_AUDIENCE', 'test_audience')
        self.user_claim = os.getenv('TEST_OAUTH2_USER_CLAIM', 'sub')
        self.scope = os.getenv('TEST_OAUTH2_SCOPE', 'openid email profile')
        
        # Test user
        self.test_user = os.getenv('TEST_USER', 'testuser@example.com')
        self.test_password = os.getenv('TEST_PASSWORD', 'testpass')
        
        # Authentik configuration (if available)
        self.authentik_url = os.getenv('AUTHENTIK_URL')
        self.authentik_client_id = os.getenv('AUTHENTIK_CLIENT_ID')
        self.authentik_client_secret = os.getenv('AUTHENTIK_CLIENT_SECRET')


class JWTGenerator:
    """Generate JWT tokens for testing"""
    
    def __init__(self):
        # Generate RSA key pair for testing
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
    
    def generate_token(self, issuer: str, subject: str, audience: str, 
                      scope: str = "openid email profile", 
                      expires_in: int = 3600) -> str:
        """Generate a JWT token for testing"""
        now = datetime.utcnow()
        
        payload = {
            'iss': issuer,
            'sub': subject,
            'aud': [audience],
            'exp': int((now + timedelta(seconds=expires_in)).timestamp()),
            'iat': int(now.timestamp()),
            'nbf': int(now.timestamp()),
            'scope': scope,
            'email': subject if '@' in subject else f"{subject}@example.com",
            'preferred_username': subject.split('@')[0] if '@' in subject else subject
        }
        
        # Sign with RS256
        token = jwt.encode(
            payload, 
            self.private_key, 
            algorithm='RS256',
            headers={'typ': 'JWT', 'alg': 'RS256'}
        )
        
        return token
    
    def get_public_key_pem(self) -> str:
        """Get public key in PEM format for JWKS"""
        return self.public_key.public_bytes(
            encoding=Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')


class CyrusIMAPTestServer:
    """Manage Cyrus IMAP test server"""
    
    def __init__(self, config: OAuth2TestConfig):
        self.config = config
        self.temp_dir = None
        self.process = None
        self.jwt_generator = JWTGenerator()
    
    def setup(self):
        """Set up test server configuration"""
        self.temp_dir = tempfile.mkdtemp(prefix='cyrus_oauth2_test_')
        
        # Create imapd.conf for testing
        imapd_conf = f"""
# Cyrus IMAP Test Configuration
configdirectory: {self.temp_dir}/conf
partition-default: {self.temp_dir}/spool
sievedir: {self.temp_dir}/sieve
admins: cyrus testadmin
allowanonymouslogin: no
allowplaintext: yes

# SASL configuration
sasl_mech_list: xoauth2 oauthbearer plain login
sasl_pwcheck_method: auxprop
sasl_auxprop_plugin: sasldb

# OAuth2 configuration
sasl_oauth2_issuers: {self.config.issuer}
sasl_oauth2_audiences: {self.config.audience}
sasl_oauth2_client_id: {self.config.client_id}
sasl_oauth2_user_claim: {self.config.user_claim}
sasl_oauth2_scope: {self.config.scope}

# Logging
syslog_prefix: cyrus-test
"""
        
        with open(f"{self.temp_dir}/imapd.conf", 'w') as f:
            f.write(imapd_conf)
        
        # Create necessary directories
        os.makedirs(f"{self.temp_dir}/conf", exist_ok=True)
        os.makedirs(f"{self.temp_dir}/spool", exist_ok=True)
        os.makedirs(f"{self.temp_dir}/sieve", exist_ok=True)
        
        return True
    
    def start(self) -> bool:
        """Start the test server"""
        if not self.temp_dir:
            self.setup()
        
        # Start master process (simplified for testing)
        cmd = [
            'imapd', 
            '-C', f"{self.temp_dir}/imapd.conf",
            '-D'  # Don't fork
        ]
        
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.temp_dir
            )
            
            # Wait a bit for server to start
            time.sleep(2)
            
            # Check if process is still running
            if self.process.poll() is None:
                return True
            else:
                print(f"Server failed to start: {self.process.stderr.read().decode()}")
                return False
                
        except FileNotFoundError:
            print("imapd binary not found. Please ensure Cyrus IMAP is installed.")
            return False
    
    def stop(self):
        """Stop the test server"""
        if self.process:
            self.process.terminate()
            self.process.wait(timeout=10)
            self.process = None
        
        if self.temp_dir:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
            self.temp_dir = None
    
    def is_running(self) -> bool:
        """Check if server is running"""
        return self.process is not None and self.process.poll() is None


class OAuth2IMAPClient:
    """IMAP client with OAuth2 support"""
    
    def __init__(self, host: str, port: int, ssl: bool = False):
        self.host = host
        self.port = port
        self.ssl = ssl
        self.connection = None
    
    def connect(self) -> bool:
        """Connect to IMAP server"""
        try:
            if self.ssl:
                self.connection = imaplib.IMAP4_SSL(self.host, self.port)
            else:
                self.connection = imaplib.IMAP4(self.host, self.port)
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            return False
    
    def authenticate_xoauth2(self, user: str, token: str) -> bool:
        """Authenticate using XOAUTH2"""
        if not self.connection:
            return False
        
        # Format XOAUTH2 string
        auth_string = f"user={user}\x01auth=Bearer {token}\x01\x01"
        auth_bytes = base64.b64encode(auth_string.encode()).decode()
        
        try:
            typ, data = self.connection.authenticate('XOAUTH2', lambda x: auth_bytes)
            return typ == 'OK'
        except Exception as e:
            print(f"XOAUTH2 authentication failed: {e}")
            return False
    
    def authenticate_oauthbearer(self, user: str, token: str) -> bool:
        """Authenticate using OAUTHBEARER"""
        if not self.connection:
            return False
        
        # Format OAUTHBEARER string
        auth_string = f"n,a={user},\x01auth=Bearer {token}\x01\x01"
        auth_bytes = base64.b64encode(auth_string.encode()).decode()
        
        try:
            typ, data = self.connection.authenticate('OAUTHBEARER', lambda x: auth_bytes)
            return typ == 'OK'
        except Exception as e:
            print(f"OAUTHBEARER authentication failed: {e}")
            return False
    
    def list_folders(self) -> List[str]:
        """List IMAP folders"""
        if not self.connection:
            return []
        
        try:
            typ, data = self.connection.list()
            if typ == 'OK':
                return [item.decode() for item in data]
            return []
        except Exception as e:
            print(f"List folders failed: {e}")
            return []
    
    def disconnect(self):
        """Disconnect from server"""
        if self.connection:
            try:
                self.connection.logout()
            except:
                pass
            self.connection = None


class OAuth2E2ETests:
    """End-to-End test suite for OAuth2 SASL plugin"""
    
    def __init__(self):
        self.config = OAuth2TestConfig()
        self.server = CyrusIMAPTestServer(self.config)
        self.jwt_generator = JWTGenerator()
        self.tests_passed = 0
        self.tests_failed = 0
        self.tests_total = 0
    
    def run_test(self, test_name: str, test_func) -> bool:
        """Run a single test"""
        print(f"Running {test_name}... ", end='', flush=True)
        self.tests_total += 1
        
        try:
            result = test_func()
            if result:
                print("PASS")
                self.tests_passed += 1
                return True
            else:
                print("FAIL")
                self.tests_failed += 1
                return False
        except Exception as e:
            print(f"ERROR: {e}")
            self.tests_failed += 1
            return False
    
    def test_server_startup(self) -> bool:
        """Test that the server starts correctly"""
        return self.server.setup() and self.server.start() and self.server.is_running()
    
    def test_imap_connection(self) -> bool:
        """Test basic IMAP connection"""
        client = OAuth2IMAPClient(self.config.imap_host, self.config.imap_port)
        result = client.connect()
        client.disconnect()
        return result
    
    def test_xoauth2_valid_token(self) -> bool:
        """Test XOAUTH2 authentication with valid token"""
        # Generate valid token
        token = self.jwt_generator.generate_token(
            issuer=self.config.issuer,
            subject=self.config.test_user,
            audience=self.config.audience,
            scope=self.config.scope
        )
        
        # Test authentication
        client = OAuth2IMAPClient(self.config.imap_host, self.config.imap_port)
        if not client.connect():
            return False
        
        result = client.authenticate_xoauth2(self.config.test_user, token)
        client.disconnect()
        return result
    
    def test_xoauth2_expired_token(self) -> bool:
        """Test XOAUTH2 authentication with expired token"""
        # Generate expired token
        token = self.jwt_generator.generate_token(
            issuer=self.config.issuer,
            subject=self.config.test_user,
            audience=self.config.audience,
            expires_in=-3600  # Expired 1 hour ago
        )
        
        # Test authentication should fail
        client = OAuth2IMAPClient(self.config.imap_host, self.config.imap_port)
        if not client.connect():
            return False
        
        result = client.authenticate_xoauth2(self.config.test_user, token)
        client.disconnect()
        return not result  # Should fail
    
    def test_xoauth2_wrong_audience(self) -> bool:
        """Test XOAUTH2 authentication with wrong audience"""
        # Generate token with wrong audience
        token = self.jwt_generator.generate_token(
            issuer=self.config.issuer,
            subject=self.config.test_user,
            audience="wrong_audience",
            scope=self.config.scope
        )
        
        # Test authentication should fail
        client = OAuth2IMAPClient(self.config.imap_host, self.config.imap_port)
        if not client.connect():
            return False
        
        result = client.authenticate_xoauth2(self.config.test_user, token)
        client.disconnect()
        return not result  # Should fail
    
    def test_xoauth2_wrong_issuer(self) -> bool:
        """Test XOAUTH2 authentication with wrong issuer"""
        # Generate token with wrong issuer
        token = self.jwt_generator.generate_token(
            issuer="https://wrong.issuer.com",
            subject=self.config.test_user,
            audience=self.config.audience,
            scope=self.config.scope
        )
        
        # Test authentication should fail
        client = OAuth2IMAPClient(self.config.imap_host, self.config.imap_port)
        if not client.connect():
            return False
        
        result = client.authenticate_xoauth2(self.config.test_user, token)
        client.disconnect()
        return not result  # Should fail
    
    def test_oauthbearer_valid_token(self) -> bool:
        """Test OAUTHBEARER authentication with valid token"""
        # Generate valid token
        token = self.jwt_generator.generate_token(
            issuer=self.config.issuer,
            subject=self.config.test_user,
            audience=self.config.audience,
            scope=self.config.scope
        )
        
        # Test authentication
        client = OAuth2IMAPClient(self.config.imap_host, self.config.imap_port)
        if not client.connect():
            return False
        
        result = client.authenticate_oauthbearer(self.config.test_user, token)
        client.disconnect()
        return result
    
    def test_post_auth_operations(self) -> bool:
        """Test IMAP operations after successful authentication"""
        # Generate valid token
        token = self.jwt_generator.generate_token(
            issuer=self.config.issuer,
            subject=self.config.test_user,
            audience=self.config.audience,
            scope=self.config.scope
        )
        
        # Test authentication and operations
        client = OAuth2IMAPClient(self.config.imap_host, self.config.imap_port)
        if not client.connect():
            return False
        
        if not client.authenticate_xoauth2(self.config.test_user, token):
            client.disconnect()
            return False
        
        # Try to list folders
        folders = client.list_folders()
        client.disconnect()
        
        # Should have at least INBOX
        return len(folders) > 0
    
    def test_authentik_integration(self) -> bool:
        """Test integration with real Authentik server (if configured)"""
        if not all([self.config.authentik_url, 
                   self.config.authentik_client_id, 
                   self.config.authentik_client_secret]):
            print("SKIP (Authentik not configured)")
            return True  # Skip test
        
        # Get real token from Authentik
        token_url = f"{self.config.authentik_url}/application/o/token/"
        
        try:
            response = requests.post(token_url, data={
                'grant_type': 'client_credentials',
                'client_id': self.config.authentik_client_id,
                'client_secret': self.config.authentik_client_secret,
                'scope': self.config.scope
            })
            
            if response.status_code != 200:
                return False
            
            token_data = response.json()
            access_token = token_data.get('access_token')
            
            if not access_token:
                return False
            
            # Test authentication with real token
            client = OAuth2IMAPClient(self.config.imap_host, self.config.imap_port)
            if not client.connect():
                return False
            
            result = client.authenticate_xoauth2(self.config.test_user, access_token)
            client.disconnect()
            return result
            
        except Exception as e:
            print(f"Authentik integration error: {e}")
            return False
    
    def run_all_tests(self) -> bool:
        """Run all E2E tests"""
        print("OAuth2 SASL Plugin E2E Tests")
        print("============================")
        
        # Start test server
        if not self.run_test("Server Startup", self.test_server_startup):
            print("Cannot continue without server")
            return False
        
        try:
            # Run all tests
            self.run_test("IMAP Connection", self.test_imap_connection)
            self.run_test("XOAUTH2 Valid Token", self.test_xoauth2_valid_token)
            self.run_test("XOAUTH2 Expired Token", self.test_xoauth2_expired_token)
            self.run_test("XOAUTH2 Wrong Audience", self.test_xoauth2_wrong_audience)
            self.run_test("XOAUTH2 Wrong Issuer", self.test_xoauth2_wrong_issuer)
            self.run_test("OAUTHBEARER Valid Token", self.test_oauthbearer_valid_token)
            self.run_test("Post-Auth Operations", self.test_post_auth_operations)
            self.run_test("Authentik Integration", self.test_authentik_integration)
            
        finally:
            # Stop test server
            self.server.stop()
        
        # Print results
        print(f"\nResults: {self.tests_passed}/{self.tests_total} tests passed ({self.tests_failed} failed)")
        
        return self.tests_failed == 0


def main():
    """Main test runner"""
    if len(sys.argv) > 1 and sys.argv[1] == '--help':
        print("""
OAuth2 SASL Plugin E2E Tests

Environment Variables:
  TEST_IMAP_HOST          IMAP server host (default: localhost)
  TEST_IMAP_PORT          IMAP server port (default: 143)
  TEST_IMAP_SSL_PORT      IMAP SSL port (default: 993)
  TEST_OAUTH2_ISSUER      OAuth2 issuer URL
  TEST_OAUTH2_CLIENT_ID   OAuth2 client ID
  TEST_OAUTH2_AUDIENCE    OAuth2 audience
  TEST_USER               Test user email
  AUTHENTIK_URL           Authentik server URL (optional)
  AUTHENTIK_CLIENT_ID     Authentik client ID (optional)
  AUTHENTIK_CLIENT_SECRET Authentik client secret (optional)
        """)
        return 0
    
    # Run tests
    test_suite = OAuth2E2ETests()
    success = test_suite.run_all_tests()
    
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
