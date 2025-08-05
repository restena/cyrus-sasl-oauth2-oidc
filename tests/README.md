# OAuth2 SASL Plugin Tests

This directory contains both **unit** and **end-to-end (E2E)** tests for the Cyrus IMAP OAuth2 SASL plugin.

## Test Tree

```text
tests/
├── unit/                     # Unit tests (pure C)
│   ├── test_framework.h      # Tiny test framework (header)
│   ├── test_framework.c      # Test framework implementation
│   ├── test_config.c         # Configuration tests
│   ├── test_jwt.c            # JWT validation tests
│   ├── test_plugin.c         # Plugin-initialisation tests
│   └── Makefile.tests        # Makefile for unit tests
├── e2e/                      # End-to-end tests
│   ├── test_e2e.py           # Main E2E test suite
│   ├── mock_oauth2_server.py # Mock OAuth2 server
│   ├── docker-compose.test.yml # Docker environment for E2E tests
│   ├── test.dockerfile       # Test-runner Dockerfile
│   └── requirements.txt      # Python dependencies
├── run_tests.sh              # Convenience launcher
└── README.md                 # This document
```

---

## Unit Tests

Unit tests validate individual components of the plugin.

### Components Covered

- **Configuration (`test_config.c`)**
  - Parsing multiple issuers
  - Audience validation
  - Auto-generating discovery URLs
  - Error handling

- **JWT (`test_jwt.c`)**
  - Header & payload parsing
  - Timestamp validation (`exp`, `iat`, `nbf`)
  - Issuer & audience checks
  - Base64 decoding

- **Plugin (`test_plugin.c`)**
  - Server / client plugin initialisation
  - SASL version compatibility
  - Mechanism properties (XOAUTH2, OAUTHBEARER)

### Running Unit Tests

```bash
# Install build dependencies (Ubuntu/Debian)
cd tests/unit
make -f Makefile.tests install-deps

# Build and run *all* unit tests
make -f Makefile.tests test

# Run a single test target
make -f Makefile.tests test-config
make -f Makefile.tests test-jwt
make -f Makefile.tests test-plugin
```

---

## End-to-End (E2E) Tests

E2E tests exercise the **full stack** against a real Cyrus IMAP server.

### Scenarios Covered

- **XOAUTH2 authentication**
  - Valid token → success
  - Expired token → failure
  - Wrong audience → failure
  - Wrong issuer → failure

- **OAUTHBEARER authentication**
  - Valid token → success
  - Same error cases as XOAUTH2

- **Post-authentication operations**
  - Folder listing (IMAP `LIST`)
  - Basic operations after login

- **Authentik integration** (optional)
  - Validate login against a live Authentik server

### Running E2E Tests

#### With Docker (recommended)

```bash
cd tests/e2e
docker-compose -f docker-compose.test.yml up --build
```

#### Locally (without Docker)

```bash
cd tests/e2e

# Python virtual-env
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run tests
python3 test_e2e.py
```

### E2E Environment Variables

```bash
# Cyrus IMAP test server
export TEST_IMAP_HOST=localhost
export TEST_IMAP_PORT=143
export TEST_IMAP_SSL_PORT=993

# OAuth2 configuration
export TEST_OAUTH2_ISSUER=https://test.issuer.com
export TEST_OAUTH2_CLIENT_ID=test_client_id
export TEST_OAUTH2_AUDIENCE=test_audience
export TEST_USER=testuser@example.com

# Authentik integration (optional)
export AUTHENTIK_URL=https://auth.example.com
export AUTHENTIK_CLIENT_ID=your_client_id
export AUTHENTIK_CLIENT_SECRET=your_client_secret
```

---

## Master Script

`run_tests.sh` provides a single entry-point:

```bash
# Run *all* tests
./tests/run_tests.sh

# Unit tests only
./tests/run_tests.sh unit

# E2E tests only (Docker)
./tests/run_tests.sh e2e

# E2E tests locally
./tests/run_tests.sh e2e-local

# Install deps then run everything
./tests/run_tests.sh --install-deps all

# Help
./tests/run_tests.sh --help
```

---

## Mock OAuth2 Server

`mock_oauth2_server.py` spins up a lightweight OAuth2/OIDC server for testing.

### Endpoints

- `/.well-known/openid-configuration` – Discovery
- `/.well-known/jwks.json` – JWKS
- `/token` – Token endpoint
- `/userinfo` – UserInfo endpoint
- `/generate_token` – Generate test tokens

### Features

- RSA key generation
- JWT signing (`RS256`)
- Token validation
- `client_credentials` flow

---

## Continuous Integration

Example GitHub Actions snippet:

```yaml
- name: Run OAuth2 SASL Tests
  run: |
    cd cyrus-sasl-oauth2-oidc
    ./tests/run_tests.sh --install-deps all
```

---

## Troubleshooting

### Unit Tests

- **Compilation error** – Check SASL and liboauth2 headers are installed
- **Missing symbols** – Ensure libraries are correctly linked

### E2E Tests

- **Cannot connect to IMAP** – Ensure Cyrus server is running and reachable
- **Authentication fails** – Verify OAuth2 settings in `imapd.conf`
- **Docker issues** – Confirm Docker & Docker Compose are installed

### Logs

```bash
# Unit tests with debug flags
make -f Makefile.tests CFLAGS="-DDEBUG" test

# E2E tests with verbose logs
TEST_DEBUG=1 python3 test_e2e.py
```

---

## Contributing New Tests

1. **Unit tests** – Add functions to existing `test_*.c` files.
2. **E2E tests** – Add methods in `OAuth2E2ETests`.
3. **New components** – Create additional test files following the existing pattern.

Always ensure **all tests pass** before submitting a merge request:

```bash
./tests/run_tests.sh all
```
