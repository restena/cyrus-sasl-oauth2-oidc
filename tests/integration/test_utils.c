/*
 * Integration Test Utilities Implementation
 * Copyright (c) 2025 Stephane Benoit <stefb@wizzz.net>
 */

#include "test_utils.h"

/* Test result counters */
int integration_tests_total = 0;
int integration_tests_passed = 0;
int integration_tests_failed = 0;

/* Create XOAUTH2 authentication string */
char* create_xoauth2_string(const char* username, const char* token) {
    if (!username || !token) return NULL;
    
    /* Format: "user=" + username + "^Aauth=Bearer " + token + "^A^A" */
    size_t len = strlen("user=") + strlen(username) + 
                 strlen("\x01auth=Bearer ") + strlen(token) + 
                 strlen("\x01\x01") + 1;
    
    char* result = malloc(len);
    if (!result) return NULL;
    
    snprintf(result, len, "user=%s\x01auth=Bearer %s\x01\x01", username, token);
    return result;
}

/* Create OAUTHBEARER authentication string */
char* create_oauthbearer_string(const char* username, const char* token) {
    if (!username || !token) return NULL;
    
    /* Format: "n,a=" + username + ",^Aauth=Bearer " + token + "^A^A" */
    size_t len = strlen("n,a=") + strlen(username) + 
                 strlen(",\x01auth=Bearer ") + strlen(token) + 
                 strlen("\x01\x01") + 1;
    
    char* result = malloc(len);
    if (!result) return NULL;
    
    snprintf(result, len, "n,a=%s,\x01auth=Bearer %s\x01\x01", username, token);
    return result;
}

/* Setup test SASL configuration */
int setup_test_sasl_config(void) {
    int result;
    
    /* Initialize SASL library */
    result = sasl_server_init(NULL, "test-oauth2");
    if (result != SASL_OK) {
        fprintf(stderr, "Failed to initialize SASL server: %d\n", result);
        return -1;
    }
    
    result = sasl_client_init(NULL);
    if (result != SASL_OK) {
        fprintf(stderr, "Failed to initialize SASL client: %d\n", result);
        sasl_server_done();
        return -1;
    }
    
    return 0;
}

/* Cleanup test SASL configuration */
void cleanup_test_sasl_config(void) {
    sasl_client_done();
    sasl_server_done();
}

/* Print integration test results */
void print_integration_test_results(void) {
    printf("\n==================================================\n");
    printf("Integration Test Results\n");
    printf("==================================================\n");
    printf("Total Tests: %d\n", integration_tests_total);
    printf("Passed: %d\n", integration_tests_passed);
    printf("Failed: %d\n", integration_tests_failed);
    
    if (integration_tests_failed == 0) {
        printf("🎉 ALL INTEGRATION TESTS PASSED!\n");
    } else {
        printf("❌ %d INTEGRATION TESTS FAILED\n", integration_tests_failed);
    }
    printf("==================================================\n");
}