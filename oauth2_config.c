/*
 * OAuth2/OIDC SASL Plugin - Configuration Management
 * Copyright (c) 2025 Stephane Benoit <stefb@wizzz.net>
 */

#include "oauth2_plugin.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>

/* For strdup function */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/* Utility function to parse space-separated string lists */
/*@null@*/ char **oauth2_parse_string_list(const char *input, int *count) {
    *count = 0;
    if (!input || strlen(input) == 0) {
        return NULL;
    }
    
    /* Count items first */
    char *temp = strdup(input);
    char *token = strtok(temp, " \t\n");
    int item_count = 0;
    while (token) {
        item_count++;
        token = strtok(NULL, " \t\n");
    }
    free(temp);
    
    if (item_count == 0) {
        return NULL;
    }
    
    /* Allocate array */
    char **list = malloc((item_count + 1) * sizeof(char*));
    if (!list) {
        return NULL;
    }
    
    /* Parse items */
    temp = strdup(input);
    token = strtok(temp, " \t\n");
    int i = 0;
    while ((token != NULL) && (i < item_count)) {
        list[i] = strdup(token);
        if (!list[i]) {
            /* Cleanup on error */
            for (int j = 0; j < i; j++) {
                free(list[j]);
            }
            free(list);
            free(temp);
            return NULL;
        }
        i++;
        token = strtok(NULL, " \t\n");
    }
    list[i] = NULL;
    free(temp);
    
    *count = item_count;
    return list;
}

void oauth2_free_string_list(char **list, int count) {
    if (!list) return;
    
    for (int i = 0; i < count; i++) {
        if (list[i]) {
            free(list[i]);
        }
    }
    free(list);
}

static const char *oauth2_config_get_string(const sasl_utils_t *utils, 
                                           const char *key, 
                                           const char *default_value) {
    const char *value;
    if (utils->getopt(utils->getopt_context, "oauth2", key, &value, NULL) == SASL_OK && value) {
        return value;  /* Return direct pointer - no strdup needed */
    }
    return default_value;
}

static int oauth2_config_get_int(const sasl_utils_t *utils, 
                                const char *key, 
                                int default_value) {
    const char *value;
    if (utils->getopt(utils->getopt_context, "oauth2", key, &value, NULL) == SASL_OK && value) {
        /* Secure integer parsing with validation */
        char *endptr;
        long parsed_value = strtol(value, &endptr, 10);
        
        /* Validate the conversion */
        if (endptr == value || *endptr != '\0') {
            /* Invalid number format */
            OAUTH2_LOG_WARN(utils, "Invalid integer value for %s: %s, using default %d", 
                          key, value, default_value);
            return default_value;
        }
        
        /* Check for integer overflow/underflow */
        if (parsed_value > INT_MAX || parsed_value < INT_MIN) {
            OAUTH2_LOG_WARN(utils, "Integer value out of range for %s: %ld, using default %d", 
                          key, parsed_value, default_value);
            return default_value;
        }
        
        return (int)parsed_value;
    }
    return default_value;
}

static int oauth2_config_get_bool(const sasl_utils_t *utils, 
                                 const char *key, 
                                 int default_value) {
    const char *value;
    if (utils->getopt(utils->getopt_context, "oauth2", key, &value, NULL) == SASL_OK && value) {
        return (strcasecmp(value, "yes") == 0 || 
                strcasecmp(value, "true") == 0 || 
                strcasecmp(value, "1") == 0) ? 1 : 0;
    }
    return default_value;
}

oauth2_config_t *oauth2_config_init(const sasl_utils_t *utils) {
    oauth2_config_t *config;
    
    config = utils->malloc(sizeof(oauth2_config_t));
    if (!config) {
        OAUTH2_LOG_ERR(utils, "Failed to allocate memory for configuration");
        return NULL;
    }
    
    memset(config, 0, sizeof(oauth2_config_t));
    
    /* Initialize liboauth2 logging context with default level (will be adjusted after config load) */
    config->oauth2_log = oauth2_init(OAUTH2_LOG_WARN, NULL);
    if (!config->oauth2_log) {
        OAUTH2_LOG_ERR(utils, "Failed to initialize liboauth2 logging context");
        utils->free(config);
        return NULL;
    }
    
    return config;
}

void oauth2_config_free(oauth2_config_t *config) {
    if (!config) return;
    
    /* Free string list configurations */
    oauth2_free_string_list(config->discovery_urls, config->discovery_urls_count);
    oauth2_free_string_list(config->issuers, config->issuers_count);
    oauth2_free_string_list(config->audiences, config->audiences_count);
    
    /* NOTE: Simple string configurations are pointers to SASL internal data - do NOT free them */
    /* config->client_id, client_secret, scope, user_claim point to getopt() results */
    
    /* Cleanup liboauth2 logging context */
    if (config->oauth2_log) {
        oauth2_shutdown(config->oauth2_log);
    }
    
    
    free(config);
}

int oauth2_config_load(oauth2_config_t *config, const sasl_utils_t *utils) {
    if (!config || !utils) {
        return SASL_BADPARAM;
    }
    
    /* Loading OAuth2 configuration */
    
    /* Load OIDC Discovery settings - support multiple URLs/issuers */
    const char *discovery_urls_str = oauth2_config_get_string(utils, OAUTH2_CONF_DISCOVERY_URLS, NULL);
    const char *discovery_url_str = oauth2_config_get_string(utils, OAUTH2_CONF_DISCOVERY_URL, NULL);
    const char *issuers_str = oauth2_config_get_string(utils, OAUTH2_CONF_ISSUERS, NULL);
    const char *issuer_str = oauth2_config_get_string(utils, OAUTH2_CONF_ISSUER, NULL);
    
    /* Log configuration input summary */
    OAUTH2_LOG_DEBUG(utils, "Reading OAuth2 configuration from SASL");
    
    /* Validate exclusive configuration for discovery URLs */
    if (discovery_urls_str && discovery_url_str) {
        OAUTH2_LOG_ERR(utils, "Cannot configure both %s and %s - use only one form", 
                      OAUTH2_CONF_DISCOVERY_URLS, OAUTH2_CONF_DISCOVERY_URL);
        return SASL_FAIL;
    }
    
    /* Parse discovery URLs (priority: plural form, then singular) */
    if (discovery_urls_str) {
        config->discovery_urls = oauth2_parse_string_list(discovery_urls_str, &config->discovery_urls_count);
    } else if (discovery_url_str) {
        config->discovery_urls = oauth2_parse_string_list(discovery_url_str, &config->discovery_urls_count);
    }
    
    /* Validate exclusive configuration for issuers */
    if (issuers_str && issuer_str) {
        OAUTH2_LOG_ERR(utils, "Cannot configure both %s and %s - use only one form", 
                      OAUTH2_CONF_ISSUERS, OAUTH2_CONF_ISSUER);
        return SASL_FAIL;
    }
    
    /* Parse issuers (priority: plural form, then singular) */
    if (issuers_str) {
        config->issuers = oauth2_parse_string_list(issuers_str, &config->issuers_count);
    } else if (issuer_str) {
        config->issuers = oauth2_parse_string_list(issuer_str, &config->issuers_count);
    }
    
    /* Ensure we have at least one discovery URL or issuer */
    if (!config->discovery_urls && !config->issuers) {
        OAUTH2_LOG_ERR(utils, "Either %s/%s or %s/%s must be configured", 
                      OAUTH2_CONF_DISCOVERY_URLS, OAUTH2_CONF_DISCOVERY_URL,
                      OAUTH2_CONF_ISSUERS, OAUTH2_CONF_ISSUER);
        return SASL_FAIL;
    }
    
    /* If only issuers provided, construct discovery URLs */
    if (!config->discovery_urls && config->issuers) {
        config->discovery_urls = malloc(config->issuers_count * sizeof(char*));
        if (!config->discovery_urls) {
            OAUTH2_LOG_ERR(utils, "Failed to allocate memory for discovery URLs");
            return SASL_NOMEM;
        }
        
        config->discovery_urls_count = config->issuers_count;
        for (int i = 0; i < config->issuers_count; i++) {
            /* Ensure issuer doesn't end with slash */
            char *clean_issuer = strdup(config->issuers[i]);
            size_t issuer_len = strlen(clean_issuer);
            if (issuer_len > 0 && clean_issuer[issuer_len - 1] == '/') {
                clean_issuer[issuer_len - 1] = '\0';
            }
            
            size_t len = strlen(clean_issuer) + strlen("/.well-known/openid-configuration") + 1;
            config->discovery_urls[i] = malloc(len);
            if (!config->discovery_urls[i]) {
                OAUTH2_LOG_ERR(utils, "Failed to allocate memory for discovery URL %d", i);
                /* Cleanup partial allocation */
                for (int j = 0; j < i; j++) {
                    free(config->discovery_urls[j]);
                }
                free(config->discovery_urls);
                free(clean_issuer);
                return SASL_NOMEM;
            }
            
            snprintf(config->discovery_urls[i], len, "%s/.well-known/openid-configuration", clean_issuer);
            free(clean_issuer);
        }
    }
    
    /* Load client credentials */
    config->client_id = (char*)oauth2_config_get_string(utils, OAUTH2_CONF_CLIENT_ID, NULL);
    config->client_secret = (char*)oauth2_config_get_string(utils, OAUTH2_CONF_CLIENT_SECRET, NULL);
    
    if (!config->client_id) {
        OAUTH2_LOG_ERR(utils, "%s must be configured", OAUTH2_CONF_CLIENT_ID);
        return SASL_FAIL;
    }
    
    /* Load token validation settings - support multiple audiences */
    const char *audiences_str = oauth2_config_get_string(utils, OAUTH2_CONF_AUDIENCES, NULL);
    const char *audience_str = oauth2_config_get_string(utils, OAUTH2_CONF_AUDIENCE, NULL);
    
    /* Log key configuration loaded */
    OAUTH2_LOG_DEBUG(utils, "Client ID configured: %s", config->client_id ? config->client_id : "N/A");
    
    /* Validate exclusive configuration for audiences */
    if (audiences_str && audience_str) {
        OAUTH2_LOG_ERR(utils, "Cannot configure both %s and %s - use only one form", 
                      OAUTH2_CONF_AUDIENCES, OAUTH2_CONF_AUDIENCE);
        return SASL_FAIL;
    }
    
    /* Parse audiences (priority: plural form, then singular) */
    if (audiences_str) {
        config->audiences = oauth2_parse_string_list(audiences_str, &config->audiences_count);
    } else if (audience_str) {
        config->audiences = oauth2_parse_string_list(audience_str, &config->audiences_count);
    }
    
    config->scope = (char*)oauth2_config_get_string(utils, OAUTH2_CONF_SCOPE, OAUTH2_DEFAULT_SCOPE);
    config->user_claim = (char*)oauth2_config_get_string(utils, OAUTH2_CONF_USER_CLAIM, OAUTH2_DEFAULT_USER_CLAIM);
    config->verify_signature = oauth2_config_get_bool(utils, OAUTH2_CONF_VERIFY_SIGNATURE, OAUTH2_DEFAULT_VERIFY_SIGNATURE);
    
    /* Load network settings */
    config->ssl_verify = oauth2_config_get_bool(utils, OAUTH2_CONF_SSL_VERIFY, OAUTH2_DEFAULT_SSL_VERIFY);
    config->timeout = oauth2_config_get_int(utils, OAUTH2_CONF_TIMEOUT, OAUTH2_DEFAULT_TIMEOUT);
    config->debug = oauth2_config_get_bool(utils, OAUTH2_CONF_DEBUG, OAUTH2_DEFAULT_DEBUG);
    
    /* Adjust liboauth2 log level based on debug setting */
    if (config->oauth2_log) {
        oauth2_log_level_t log_level = config->debug ? OAUTH2_LOG_TRACE1 : OAUTH2_LOG_WARN;
        /* Change the log level of the default stderr sink */
        oauth2_log_sink_level_set(&oauth2_log_sink_stderr, log_level);
    }
    
    /* Network settings configured */
    OAUTH2_LOG_DEBUG(utils, "Network: SSL verify=%s, timeout=%ds, debug=%s",
                     config->ssl_verify ? "yes" : "no", config->timeout,
                     config->debug ? "yes" : "no");
    
    /* Log configuration summary */
    OAUTH2_LOG_INFO(utils, "OAuth2 configuration loaded: %d providers, %d audiences", 
                   config->discovery_urls_count, 
                   config->audiences_count);
    
    /* Log essential configuration at DEBUG level */
    OAUTH2_LOG_DEBUG(utils, "User claim: %s, signature verification: %s", 
                     config->user_claim, 
                     config->verify_signature ? "enabled" : "disabled");
    
    return SASL_OK;
}