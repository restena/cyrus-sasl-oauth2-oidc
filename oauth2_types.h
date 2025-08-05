/*
 * OAuth2/OIDC SASL Plugin - Type Definitions
 * Copyright (c) 2025 Stephane Benoit <stefb@wizzz.net>
 */

#ifndef OAUTH2_TYPES_H
#define OAUTH2_TYPES_H

#include <sasl/sasl.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations for liboauth2 types - use existing liboauth2 definitions */
/* Include necessary liboauth2 headers to get the real type definitions */

/* Forward declaration for plugin configuration (full definition in oauth2_plugin.h) */
struct oauth2_config;

/* Server-side context structure */
typedef struct oauth2_server_context {
    struct oauth2_config *config;   /* Plugin configuration */
    int state;                      /* Current state in authentication */
    char *username;                 /* Authenticated username */
    char *access_token;             /* Access token from client */
    void *oauth2_ctx;               /* Internal liboauth2 context */
} oauth2_server_context_t;

/* Client-side context structure */
typedef struct oauth2_client_context {
    struct oauth2_config *config;   /* Plugin configuration */
    int state;                      /* Current state in authentication */
    char *access_token;             /* Access token to send to server */
    char *username;                 /* Username for authentication */
    void *oauth2_ctx;               /* Internal liboauth2 context */
} oauth2_client_context_t;

#ifdef __cplusplus
}
#endif

#endif /* OAUTH2_TYPES_H */