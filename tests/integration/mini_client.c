/*
 * Mini SASL Client for OAuth2 Integration Testing
 * Copyright (c) 2025 Stephane Benoit <stefb@wizzz.net>
 */

#include "test_utils.h"
#include <sasl/sasl.h>
#include <stdarg.h>

typedef struct {
    sasl_conn_t *conn;
    const char *mechanism;
    char *auth_data;
    size_t auth_data_len;
} mini_client_t;

/* SASL callback functions for client */
static int client_getopt(void *context, const char *plugin_name, const char *option,
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
    }
    
    *result = NULL;
    if (len) *len = 0;
    return SASL_FAIL;
}

static void client_log(sasl_conn_t *conn, int level, const char *message) {
    printf("[CLIENT LOG] %s\n", message);
}

static void client_seterror(sasl_conn_t *conn, unsigned flags, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    printf("[CLIENT ERROR] ");
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
}

static sasl_callback_t client_callbacks[] = {
    { SASL_CB_GETOPT, (int(*)(void))client_getopt, NULL },
    { SASL_CB_LOG, (int(*)(void))client_log, NULL },
    /* SASL_CB_SETERROR not available in all SASL versions */
    { SASL_CB_LIST_END, NULL, NULL }
};

/* Create mini SASL client */
mini_client_t* mini_client_create(const char* mechanism, const char* username, const char* token) {
    mini_client_t *client = malloc(sizeof(mini_client_t));
    if (!client) return NULL;
    
    memset(client, 0, sizeof(mini_client_t));
    
    /* Set mechanism */
    client->mechanism = strdup(mechanism);
    if (!client->mechanism) {
        free(client);
        return NULL;
    }
    
    /* Create appropriate auth data based on mechanism */
    if (strcmp(mechanism, "XOAUTH2") == 0) {
        client->auth_data = create_xoauth2_string(username, token);
    } else if (strcmp(mechanism, "OAUTHBEARER") == 0) {
        client->auth_data = create_oauthbearer_string(username, token);
    } else {
        free((char*)client->mechanism);
        free(client);
        return NULL;
    }
    
    if (!client->auth_data) {
        free((char*)client->mechanism);
        free(client);
        return NULL;
    }
    
    client->auth_data_len = strlen(client->auth_data);
    
    /* Create SASL connection */
    int result = sasl_client_new("imap", "localhost", NULL, NULL, 
                                client_callbacks, 0, &client->conn);
    if (result != SASL_OK) {
        printf("Failed to create SASL client connection: %d\n", result);
        free(client->auth_data);
        free((char*)client->mechanism);
        free(client);
        return NULL;
    }
    
    return client;
}

/* Perform SASL authentication step */
int mini_client_authenticate(mini_client_t *client, const char **clientout, unsigned *clientoutlen) {
    if (!client || !client->conn) return SASL_FAIL;
    
    const char *mechusing;
    sasl_interact_t *prompt_need = NULL;
    
    /* Start authentication */
    int result = sasl_client_start(client->conn, client->mechanism, &prompt_need,
                                  clientout, clientoutlen, &mechusing);
    
    if (result == SASL_INTERACT) {
        /* Handle prompts if needed - for OAuth2, we should provide the token */
        printf("Client authentication requires interaction\n");
        return SASL_INTERACT;
    }
    
    if (result == SASL_CONTINUE || result == SASL_OK) {
        /* For OAuth2, we need to send our auth data */
        *clientout = client->auth_data;
        *clientoutlen = client->auth_data_len;
        printf("Client sending auth data (%u bytes)\n", *clientoutlen);
        return SASL_OK;
    }
    
    printf("Client authentication failed: %d\n", result);
    return result;
}

/* Process server response */
int mini_client_step(mini_client_t *client, const char *serverin, unsigned serverinlen,
                    const char **clientout, unsigned *clientoutlen) {
    if (!client || !client->conn) return SASL_FAIL;
    
    sasl_interact_t *prompt_need = NULL;
    
    int result = sasl_client_step(client->conn, serverin, serverinlen, &prompt_need,
                                 clientout, clientoutlen);
    
    if (result == SASL_OK) {
        printf("Client authentication completed successfully\n");
    } else if (result == SASL_CONTINUE) {
        printf("Client authentication continues\n");
    } else {
        printf("Client authentication step failed: %d\n", result);
    }
    
    return result;
}

/* Get client username */
const char* mini_client_get_username(mini_client_t *client) {
    if (!client || !client->conn) return NULL;
    
    const char *username = NULL;
    int result = sasl_getprop(client->conn, SASL_USERNAME, (const void**)&username);
    if (result != SASL_OK) return NULL;
    
    return username;
}

/* Cleanup mini client */
void mini_client_destroy(mini_client_t *client) {
    if (!client) return;
    
    if (client->conn) {
        sasl_dispose(&client->conn);
    }
    
    if (client->auth_data) {
        free(client->auth_data);
    }
    
    if (client->mechanism) {
        free((char*)client->mechanism);
    }
    
    free(client);
}

/* Test function: Basic XOAUTH2 client test */
int test_mini_client_xoauth2_basic() {
    mini_client_t *client = mini_client_create("XOAUTH2", "test@test.com", TEST_JWT_VALID_XOAUTH2);
    INTEGRATION_TEST_ASSERT_NOT_NULL(client, "Client should be created successfully");
    
    const char *clientout;
    unsigned clientoutlen;
    
    int result = mini_client_authenticate(client, &clientout, &clientoutlen);
    INTEGRATION_TEST_ASSERT_EQ(SASL_OK, result, "Client authentication should start successfully");
    INTEGRATION_TEST_ASSERT_NOT_NULL(clientout, "Client should provide auth data");
    INTEGRATION_TEST_ASSERT(clientoutlen > 0, "Client auth data should not be empty");
    
    printf("Client auth data length: %u\n", clientoutlen);
    
    mini_client_destroy(client);
    return 0;
}

/* Test function: Basic OAUTHBEARER client test */
int test_mini_client_oauthbearer_basic() {
    mini_client_t *client = mini_client_create("OAUTHBEARER", "test@test.com", TEST_JWT_VALID_XOAUTH2);
    INTEGRATION_TEST_ASSERT_NOT_NULL(client, "Client should be created successfully");
    
    const char *clientout;
    unsigned clientoutlen;
    
    int result = mini_client_authenticate(client, &clientout, &clientoutlen);
    INTEGRATION_TEST_ASSERT_EQ(SASL_OK, result, "Client authentication should start successfully");
    INTEGRATION_TEST_ASSERT_NOT_NULL(clientout, "Client should provide auth data");
    INTEGRATION_TEST_ASSERT(clientoutlen > 0, "Client auth data should not be empty");
    
    printf("Client auth data length: %u\n", clientoutlen);
    
    mini_client_destroy(client);
    return 0;
}

/* Test function: Invalid mechanism */
int test_mini_client_invalid_mechanism() {
    mini_client_t *client = mini_client_create("INVALID", "test@test.com", TEST_JWT_VALID_XOAUTH2);
    INTEGRATION_TEST_ASSERT(client == NULL, "Client should not be created with invalid mechanism");
    
    return 0;
}