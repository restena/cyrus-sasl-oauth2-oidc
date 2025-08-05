/*
 * Integration Test Utilities for OAuth2 SASL Plugin
 * Copyright (c) 2025 Stephane Benoit <stefb@wizzz.net>
 */

#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sasl/sasl.h>
#include <sasl/saslplug.h>

/* Test result tracking */
extern int integration_tests_total;
extern int integration_tests_passed;
extern int integration_tests_failed;

/* Test macros */
#define INTEGRATION_TEST_ASSERT(condition, message) \
    do { \
        integration_tests_total++; \
        if (!(condition)) { \
            fprintf(stderr, "INTEGRATION FAIL: %s - %s\n", __func__, message); \
            integration_tests_failed++; \
            return -1; \
        } else { \
            fprintf(stdout, "INTEGRATION PASS: %s - %s\n", __func__, message); \
            integration_tests_passed++; \
        } \
    } while(0)

#define INTEGRATION_TEST_ASSERT_EQ(expected, actual, message) \
    INTEGRATION_TEST_ASSERT((expected) == (actual), message)

#define INTEGRATION_TEST_ASSERT_NOT_NULL(ptr, message) \
    INTEGRATION_TEST_ASSERT((ptr) != NULL, message)

#define RUN_INTEGRATION_TEST(test_func) \
    do { \
        printf("Running integration test: %s\n", #test_func); \
        if (test_func() == 0) { \
            printf("✓ %s PASSED\n", #test_func); \
        } else { \
            printf("✗ %s FAILED\n", #test_func); \
        } \
        printf("\n"); \
    } while(0)

/* Test JWT tokens for integration testing */
#define TEST_JWT_VALID_XOAUTH2 \
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9." \
    "eyJpc3MiOiJodHRwczovL3Rlc3QuaXNzdWVyLmNvbSIsImF1ZCI6InRlc3RfYXVkaWVuY2UiLCJlbWFpbCI6InRlc3RAdGVzdC5jb20iLCJleHAiOjk5OTk5OTk5OTl9." \
    "test_signature_here"

#define TEST_JWT_INVALID \
    "invalid.jwt.token"

#define TEST_JWT_EXPIRED \
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9." \
    "eyJpc3MiOiJodHRwczovL3Rlc3QuaXNzdWVyLmNvbSIsImF1ZCI6InRlc3RfYXVkaWVuY2UiLCJlbWFpbCI6InRlc3RAdGVzdC5jb20iLCJleHAiOjF9." \
    "expired_signature"

/* Helper functions */
char* create_xoauth2_string(const char* username, const char* token);
char* create_oauthbearer_string(const char* username, const char* token);
int setup_test_sasl_config(void);
void cleanup_test_sasl_config(void);
void print_integration_test_results(void);

#endif /* TEST_UTILS_H */