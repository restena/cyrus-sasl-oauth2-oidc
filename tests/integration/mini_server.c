/*
 * Mini SASL Server for OAuth2 Integration Testing
 * Copyright (c) 2025 Stephane Benoit <stefb@wizzz.net>
 */

#include "test_utils.h"
#include <sasl/sasl.h>
#include <stdarg.h>

typedef struct {
    sasl_conn_t *conn;
    const char **mechanisms;
    int mechanism_count;
    char *username;
} mini_server_t;

/* SASL callback functions for server */
static int server_getopt(void *context, const char *plugin_name, const char *option,
                        const char **result, unsigned *len) {
    /* Provide test configuration */
    if (strcmp(plugin_name, "oauth2") == 0) {
        if (strcmp(option, "oauth2_issuers") == 0) {
            *result = "https://test.issuer.com";
            if (len) *len = strlen(*result);
            return SASL_OK;
        }
        if (strcmp(option, "oauth2_audiences") == 0) {
            *result = "test_audience";
            if (len) *len = strlen(*result);
            return SASL_OK;
        }
        if (strcmp(option, "oauth2_client_id") == 0) {
            *result = "test_client";
            if (len) *len = strlen(*result);
            return SASL_OK;
        }
        if (strcmp(option, "oauth2_user_claim") == 0) {
            *result = "email";
            if (len) *len = strlen(*result);
            return SASL_OK;
        }
        if (strcmp(option, "oauth2_verify_signature") == 0) {
            *result = "no";  /* Disable signature verification for tests */
            if (len) *len = strlen(*result);
            return SASL_OK;
        }
    }
    
    *result = NULL;
    if (len) *len = 0;
    return SASL_FAIL;
}

static void server_log(sasl_conn_t *conn, int level, const char *message) {
    printf("[SERVER LOG] %s\n", message);
}

static void server_seterror(sasl_conn_t *conn, unsigned flags, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    printf("[SERVER ERROR] ");
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
}

static int server_authorize(sasl_conn_t *conn, void *context,
                           const char *authid, const char *authzid,
                           const char *default_realm,
                           unsigned urlen,
                           struct propctx *propctx) {
    printf("[SERVER] Authorizing user: authid=%s, authzid=%s\n", 
           authid ? authid : "NULL", authzid ? authzid : "NULL");
    
    /* For testing, allow all authentications */
    return SASL_OK;
}

static sasl_callback_t server_callbacks[] = {
    { SASL_CB_GETOPT, (int(*)(void))server_getopt, NULL },
    { SASL_CB_LOG, (int(*)(void))server_log, NULL },
    /* SASL_CB_SETERROR not available in all SASL versions */
    { SASL_CB_PROXY_POLICY, (int(*)(void))server_authorize, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};

/* Create mini SASL server */
mini_server_t* mini_server_create(const char* service, const char* hostname) {
    mini_server_t *server = malloc(sizeof(mini_server_t));
    if (!server) return NULL;
    
    memset(server, 0, sizeof(mini_server_t));
    
    /* Create SASL connection */
    int result = sasl_server_new(service ? service : "imap", 
                                hostname ? hostname : "localhost",
                                NULL, NULL, NULL,
                                server_callbacks, 0, &server->conn);
    if (result != SASL_OK) {
        printf("Failed to create SASL server connection: %d\n", result);
        free(server);
        return NULL;
    }
    
    /* Get available mechanisms */
    const char *mechlist;
    unsigned mechlist_len;
    int mechcount;
    
    result = sasl_listmech(server->conn, NULL, "", " ", "",
                          &mechlist, &mechlist_len, &mechcount);
    if (result != SASL_OK) {
        printf("Failed to list mechanisms: %d\n", result);
        sasl_dispose(&server->conn);
        free(server);
        return NULL;
    }
    
    printf("Available mechanisms: %s (%d mechanisms)\n", mechlist, mechcount);
    server->mechanism_count = mechcount;
    
    return server;
}

/* Start authentication with mechanism */
int mini_server_start_auth(mini_server_t *server, const char *mechanism,
                          const char *clientin, unsigned clientinlen,
                          const char **serverout, unsigned *serveroutlen) {
    if (!server || !server->conn) return SASL_FAIL;
    
    printf("[SERVER] Starting authentication with mechanism: %s\n", mechanism);
    printf("[SERVER] Client data length: %u\n", clientinlen);
    int result = sasl_server_start(server->conn, mechanism,
                                  clientin, clientinlen,
                                  serverout, serveroutlen);
    
    if (result == SASL_OK) {
        printf("[SERVER] Authentication completed successfully\n");
        
        /* Get authenticated username */
        const char *username = NULL;
        int prop_result = sasl_getprop(server->conn, SASL_USERNAME, (const void**)&username);
        if (prop_result == SASL_OK && username) {
            server->username = strdup(username);
            printf("[SERVER] Authenticated user: %s\n", username);
        }
    } else if (result == SASL_CONTINUE) {
        printf("[SERVER] Authentication continues\n");
    } else {
        printf("[SERVER] Authentication failed: %d\n", result);
    }
    
    return result;
}

/* Continue authentication step */
int mini_server_step_auth(mini_server_t *server,
                         const char *clientin, unsigned clientinlen,
                         const char **serverout, unsigned *serveroutlen) {
    if (!server || !server->conn) return SASL_FAIL;
    
    printf("[SERVER] Authentication step - client data length: %u\n", clientinlen);
    int result = sasl_server_step(server->conn, clientin, clientinlen,
                                 serverout, serveroutlen);
    
    if (result == SASL_OK) {
        printf("[SERVER] Authentication step completed successfully\n");
        
        /* Get authenticated username */
        const char *username = NULL;
        int prop_result = sasl_getprop(server->conn, SASL_USERNAME, (const void**)&username);
        if (prop_result == SASL_OK && username) {
            if (server->username) free(server->username);
            server->username = strdup(username);
            printf("[SERVER] Authenticated user: %s\n", username);
        }
    } else if (result == SASL_CONTINUE) {
        printf("[SERVER] Authentication step continues\n");
    } else {
        printf("[SERVER] Authentication step failed: %d\n", result);
    }
    
    return result;
}

/* Get authenticated username */
const char* mini_server_get_username(mini_server_t *server) {
    return server ? server->username : NULL;
}

/* Check if mechanism is available */
int mini_server_has_mechanism(mini_server_t *server, const char *mechanism) {
    if (!server || !server->conn || !mechanism) return 0;
    
    const char *mechlist;
    unsigned mechlist_len;
    int mechcount;
    
    int result = sasl_listmech(server->conn, NULL, "", " ", "",
                              &mechlist, &mechlist_len, &mechcount);
    if (result != SASL_OK) return 0;
    
    /* Simple string search for mechanism name */
    return (strstr(mechlist, mechanism) != NULL);
}

/* Cleanup mini server */
void mini_server_destroy(mini_server_t *server) {
    if (!server) return;
    
    if (server->conn) {
        sasl_dispose(&server->conn);
    }
    
    if (server->username) {
        free(server->username);
    }
    
    free(server);
}

/* Test function: Basic server creation */
int test_mini_server_creation() {
    mini_server_t *server = mini_server_create("imap", "localhost");
    INTEGRATION_TEST_ASSERT_NOT_NULL(server, "Server should be created successfully");
    
    /* Check if OAuth2 mechanisms are available */
    int has_xoauth2 = mini_server_has_mechanism(server, "XOAUTH2");
    int has_oauthbearer = mini_server_has_mechanism(server, "OAUTHBEARER");
    
    printf("Server supports XOAUTH2: %s\n", has_xoauth2 ? "yes" : "no");
    printf("Server supports OAUTHBEARER: %s\n", has_oauthbearer ? "yes" : "no");
    
    /* At least one OAuth2 mechanism should be available */
    INTEGRATION_TEST_ASSERT(has_xoauth2 || has_oauthbearer, 
                           "Server should support at least one OAuth2 mechanism");
    
    mini_server_destroy(server);
    return 0;
}

/* Test function: Server XOAUTH2 authentication */
int test_mini_server_xoauth2_auth() {
    mini_server_t *server = mini_server_create("imap", "localhost");
    INTEGRATION_TEST_ASSERT_NOT_NULL(server, "Server should be created successfully");
    
    /* Check XOAUTH2 support */
    if (!mini_server_has_mechanism(server, "XOAUTH2")) {
        printf("XOAUTH2 not supported, skipping test\n");
        mini_server_destroy(server);
        return 0;
    }
    
    /* Create test auth data */
    char *auth_data = create_xoauth2_string("test@test.com", TEST_JWT_VALID_XOAUTH2);
    INTEGRATION_TEST_ASSERT_NOT_NULL(auth_data, "Auth data should be created");
    
    const char *serverout;
    unsigned serveroutlen;
    
    /* Start authentication */
    int result = mini_server_start_auth(server, "XOAUTH2", 
                                       auth_data, strlen(auth_data),
                                       &serverout, &serveroutlen);
    
    /* OAuth2 should complete in one step for valid tokens */
    INTEGRATION_TEST_ASSERT_EQ(SASL_OK, result, "Server authentication should succeed");
    
    /* Check authenticated username */
    const char *username = mini_server_get_username(server);
    INTEGRATION_TEST_ASSERT_NOT_NULL(username, "Authenticated username should be available");
    printf("Authenticated username: %s\n", username);
    
    free(auth_data);
    mini_server_destroy(server);
    return 0;
}

/* Test function: Server OAUTHBEARER authentication */
int test_mini_server_oauthbearer_auth() {
    mini_server_t *server = mini_server_create("imap", "localhost");
    INTEGRATION_TEST_ASSERT_NOT_NULL(server, "Server should be created successfully");
    
    /* Check OAUTHBEARER support */
    if (!mini_server_has_mechanism(server, "OAUTHBEARER")) {
        printf("OAUTHBEARER not supported, skipping test\n");
        mini_server_destroy(server);
        return 0;
    }
    
    /* Create test auth data */
    char *auth_data = create_oauthbearer_string("test@test.com", TEST_JWT_VALID_XOAUTH2);
    INTEGRATION_TEST_ASSERT_NOT_NULL(auth_data, "Auth data should be created");
    
    const char *serverout;
    unsigned serveroutlen;
    
    /* Start authentication */
    int result = mini_server_start_auth(server, "OAUTHBEARER", 
                                       auth_data, strlen(auth_data),
                                       &serverout, &serveroutlen);
    
    /* OAuth2 should complete in one step for valid tokens */
    INTEGRATION_TEST_ASSERT_EQ(SASL_OK, result, "Server authentication should succeed");
    
    /* Check authenticated username */
    const char *username = mini_server_get_username(server);
    INTEGRATION_TEST_ASSERT_NOT_NULL(username, "Authenticated username should be available");
    printf("Authenticated username: %s\n", username);
    
    free(auth_data);
    mini_server_destroy(server);
    return 0;
}

/* Test function: Server authentication with invalid token */
int test_mini_server_invalid_token() {
    mini_server_t *server = mini_server_create("imap", "localhost");
    INTEGRATION_TEST_ASSERT_NOT_NULL(server, "Server should be created successfully");
    
    /* Check XOAUTH2 support */
    if (!mini_server_has_mechanism(server, "XOAUTH2")) {
        printf("XOAUTH2 not supported, skipping test\n");
        mini_server_destroy(server);
        return 0;
    }
    
    /* Create test auth data with invalid token */
    char *auth_data = create_xoauth2_string("test@test.com", TEST_JWT_INVALID);
    INTEGRATION_TEST_ASSERT_NOT_NULL(auth_data, "Auth data should be created");
    
    const char *serverout;
    unsigned serveroutlen;
    
    /* Start authentication - should fail */
    int result = mini_server_start_auth(server, "XOAUTH2", 
                                       auth_data, strlen(auth_data),
                                       &serverout, &serveroutlen);
    
    /* Authentication should fail with invalid token */
    INTEGRATION_TEST_ASSERT(result != SASL_OK, "Server authentication should fail with invalid token");
    printf("Authentication correctly failed with result: %d\n", result);
    
    free(auth_data);
    mini_server_destroy(server);
    return 0;
}