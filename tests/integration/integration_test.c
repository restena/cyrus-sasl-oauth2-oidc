/*
 * OAuth2 SASL Plugin Integration Tests
 * Copyright (c) 2025 Stephane Benoit <stefb@wizzz.net>
 */

#include "test_utils.h"
#include <stdarg.h>

/* Forward declarations from mini_client.c */
typedef struct mini_client_t mini_client_t;
mini_client_t* mini_client_create(const char* mechanism, const char* username, const char* token);
int mini_client_authenticate(mini_client_t *client, const char **clientout, unsigned *clientoutlen);
int mini_client_step(mini_client_t *client, const char *serverin, unsigned serverinlen,
                    const char **clientout, unsigned *clientoutlen);
const char* mini_client_get_username(mini_client_t *client);
void mini_client_destroy(mini_client_t *client);

/* Forward declarations from mini_server.c */
typedef struct mini_server_t mini_server_t;
mini_server_t* mini_server_create(const char* service, const char* hostname);
int mini_server_start_auth(mini_server_t *server, const char *mechanism,
                          const char *clientin, unsigned clientinlen,
                          const char **serverout, unsigned *serveroutlen);
int mini_server_step_auth(mini_server_t *server,
                         const char *clientin, unsigned clientinlen,
                         const char **serverout, unsigned *serveroutlen);
const char* mini_server_get_username(mini_server_t *server);
int mini_server_has_mechanism(mini_server_t *server, const char *mechanism);
void mini_server_destroy(mini_server_t *server);

/* Forward declarations for individual component tests */
int test_mini_client_xoauth2_basic(void);
int test_mini_client_oauthbearer_basic(void);
int test_mini_client_invalid_mechanism(void);
int test_mini_server_creation(void);
int test_mini_server_xoauth2_auth(void);
int test_mini_server_oauthbearer_auth(void);
int test_mini_server_invalid_token(void);

/* Integration test: Client-Server XOAUTH2 flow */
int test_integration_xoauth2_flow() {
    printf("=== Testing XOAUTH2 Client-Server Integration ===\n");
    
    /* Create client and server */
    mini_client_t *client = mini_client_create("XOAUTH2", "test@test.com", TEST_JWT_VALID_XOAUTH2);
    INTEGRATION_TEST_ASSERT_NOT_NULL(client, "Client should be created");
    
    mini_server_t *server = mini_server_create("imap", "localhost");
    INTEGRATION_TEST_ASSERT_NOT_NULL(server, "Server should be created");
    
    /* Check if XOAUTH2 is supported */
    if (!mini_server_has_mechanism(server, "XOAUTH2")) {
        printf("XOAUTH2 not supported, skipping integration test\n");
        mini_client_destroy(client);
        mini_server_destroy(server);
        return 0;
    }
    
    /* Client authentication step */
    const char *clientout;
    unsigned clientoutlen;
    int client_result = mini_client_authenticate(client, &clientout, &clientoutlen);
    INTEGRATION_TEST_ASSERT_EQ(SASL_OK, client_result, "Client authentication should start");
    INTEGRATION_TEST_ASSERT_NOT_NULL(clientout, "Client should provide auth data");
    
    printf("Client sending %u bytes to server\n", clientoutlen);
    
    /* Server authentication step */
    const char *serverout;
    unsigned serveroutlen;
    int server_result = mini_server_start_auth(server, "XOAUTH2", 
                                              clientout, clientoutlen,
                                              &serverout, &serveroutlen);
    INTEGRATION_TEST_ASSERT_EQ(SASL_OK, server_result, "Server authentication should succeed");
    
    /* Verify authenticated username */
    const char *server_username = mini_server_get_username(server);
    INTEGRATION_TEST_ASSERT_NOT_NULL(server_username, "Server should have authenticated username");
    printf("Server authenticated user: %s\n", server_username);
    
    /* Cleanup */
    mini_client_destroy(client);
    mini_server_destroy(server);
    
    printf("✓ XOAUTH2 Client-Server integration test passed\n\n");
    return 0;
}

/* Integration test: Client-Server OAUTHBEARER flow */
int test_integration_oauthbearer_flow() {
    printf("=== Testing OAUTHBEARER Client-Server Integration ===\n");
    
    /* Create client and server */
    mini_client_t *client = mini_client_create("OAUTHBEARER", "test@test.com", TEST_JWT_VALID_XOAUTH2);
    INTEGRATION_TEST_ASSERT_NOT_NULL(client, "Client should be created");
    
    mini_server_t *server = mini_server_create("imap", "localhost");
    INTEGRATION_TEST_ASSERT_NOT_NULL(server, "Server should be created");
    
    /* Check if OAUTHBEARER is supported */
    if (!mini_server_has_mechanism(server, "OAUTHBEARER")) {
        printf("OAUTHBEARER not supported, skipping integration test\n");
        mini_client_destroy(client);
        mini_server_destroy(server);
        return 0;
    }
    
    /* Client authentication step */
    const char *clientout;
    unsigned clientoutlen;
    int client_result = mini_client_authenticate(client, &clientout, &clientoutlen);
    INTEGRATION_TEST_ASSERT_EQ(SASL_OK, client_result, "Client authentication should start");
    INTEGRATION_TEST_ASSERT_NOT_NULL(clientout, "Client should provide auth data");
    
    printf("Client sending %u bytes to server\n", clientoutlen);
    
    /* Server authentication step */
    const char *serverout;
    unsigned serveroutlen;
    int server_result = mini_server_start_auth(server, "OAUTHBEARER", 
                                              clientout, clientoutlen,
                                              &serverout, &serveroutlen);
    INTEGRATION_TEST_ASSERT_EQ(SASL_OK, server_result, "Server authentication should succeed");
    
    /* Verify authenticated username */
    const char *server_username = mini_server_get_username(server);
    INTEGRATION_TEST_ASSERT_NOT_NULL(server_username, "Server should have authenticated username");
    printf("Server authenticated user: %s\n", server_username);
    
    /* Cleanup */
    mini_client_destroy(client);
    mini_server_destroy(server);
    
    printf("✓ OAUTHBEARER Client-Server integration test passed\n\n");
    return 0;
}

/* Integration test: Invalid token handling */
int test_integration_invalid_token() {
    printf("=== Testing Invalid Token Handling ===\n");
    
    /* Create client with invalid token and server */
    mini_client_t *client = mini_client_create("XOAUTH2", "test@test.com", TEST_JWT_INVALID);
    INTEGRATION_TEST_ASSERT_NOT_NULL(client, "Client should be created");
    
    mini_server_t *server = mini_server_create("imap", "localhost");
    INTEGRATION_TEST_ASSERT_NOT_NULL(server, "Server should be created");
    
    /* Check if XOAUTH2 is supported */
    if (!mini_server_has_mechanism(server, "XOAUTH2")) {
        printf("XOAUTH2 not supported, skipping integration test\n");
        mini_client_destroy(client);
        mini_server_destroy(server);
        return 0;
    }
    
    /* Client authentication step */
    const char *clientout;
    unsigned clientoutlen;
    int client_result = mini_client_authenticate(client, &clientout, &clientoutlen);
    INTEGRATION_TEST_ASSERT_EQ(SASL_OK, client_result, "Client should prepare auth data");
    
    /* Server authentication step - should fail */
    const char *serverout;
    unsigned serveroutlen;
    int server_result = mini_server_start_auth(server, "XOAUTH2", 
                                              clientout, clientoutlen,
                                              &serverout, &serveroutlen);
    INTEGRATION_TEST_ASSERT(server_result != SASL_OK, "Server should reject invalid token");
    
    printf("Server correctly rejected invalid token with result: %d\n", server_result);
    
    /* Cleanup */
    mini_client_destroy(client);
    mini_server_destroy(server);
    
    printf("✓ Invalid token integration test passed\n\n");
    return 0;
}

/* Main integration test runner */
int main(void) {
    printf("OAuth2 SASL Plugin Integration Tests\n");
    printf("====================================\n\n");
    
    /* Initialize SASL */
    if (setup_test_sasl_config() != 0) {
        fprintf(stderr, "Failed to setup SASL configuration\n");
        return 1;
    }
    
    /* Reset counters */
    integration_tests_total = 0;
    integration_tests_passed = 0;
    integration_tests_failed = 0;
    
    /* Run individual component tests first */
    printf("Running Component Tests:\n");
    printf("========================\n");
    RUN_INTEGRATION_TEST(test_mini_client_xoauth2_basic);
    RUN_INTEGRATION_TEST(test_mini_client_oauthbearer_basic);
    RUN_INTEGRATION_TEST(test_mini_client_invalid_mechanism);
    RUN_INTEGRATION_TEST(test_mini_server_creation);
    RUN_INTEGRATION_TEST(test_mini_server_xoauth2_auth);
    RUN_INTEGRATION_TEST(test_mini_server_oauthbearer_auth);
    RUN_INTEGRATION_TEST(test_mini_server_invalid_token);
    
    /* Run integration tests */
    printf("Running Integration Tests:\n");
    printf("===========================\n");
    RUN_INTEGRATION_TEST(test_integration_xoauth2_flow);
    RUN_INTEGRATION_TEST(test_integration_oauthbearer_flow);
    RUN_INTEGRATION_TEST(test_integration_invalid_token);
    
    /* Print results */
    print_integration_test_results();
    
    /* Cleanup SASL */
    cleanup_test_sasl_config();
    
    return (integration_tests_failed > 0) ? 1 : 0;
}