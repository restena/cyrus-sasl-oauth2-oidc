# OAuth2 SASL Integration Tests

This directory contains integration tests for the OAuth2 SASL plugin that verify end-to-end interactions between client and server.

## Structure

- `mini_client.c` – Minimal SASL client to test OAuth2 authentication
- `mini_server.c` – Minimal SASL server to validate OAuth2 authentication  
- `integration_test.c` – Full client↔server integration tests
- `test_utils.h` – Shared utilities for the integration tests
- `Makefile.integration` – Build system for the integration tests

## Tests Performed

1. **Client→Server Basic** – XOAUTH2 test with a valid JWT
2. **Client→Server OAUTHBEARER** – OAUTHBEARER test with a valid JWT  
3. **JWT Invalid** – Test with an invalid JWT token
4. **JWT Expired** – Test with an expired JWT token
5. **Missing Claims** – Test with a JWT missing required claims
6. **Multiple Issuers** – Test with multiple configured issuers
7. **Audience Validation** – Audience claim validation test

## Usage

```bash
# Build the integration tests
make integration

# Run the integration tests
make test-integration

# Debug mode
make test-integration-debug
```

## Test Configuration

The tests use sample JWTs generated with test keys to validate plugin behaviour without requiring a real OAuth2 infrastructure.