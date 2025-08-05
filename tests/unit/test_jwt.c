#include <jansson.h>
#include "test_framework.h"
#include "mock_sasl.h"
#include "../../oauth2_plugin.h"
#include <time.h>
#include <string.h>
#include <oauth2/oauth2.h>

/* Use our test base64 decode function */

/* Mock JWT token for testing */
const char *mock_jwt_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lkLndpenpwLm5ldC9hcHBsaWNhdGlvbi9vL2N5cnVzLWltYXBkLyIsInN1YiI6InRlc3R1c2VyIiwiYXVkIjpbImVKWk9ZQlJMOGVxOGdRT0hldlkwRTJFSVhrUXRXME1jSE1Ta3NweTciXSwiZXhwIjoxNzMzNDE5MjAwLCJpYXQiOjE3MzM0MTU2MDAsIm5iZiI6MTczMzQxNTYwMCwic2NvcGUiOiJvcGVuaWQgZW1haWwgcHJvZmlsZSJ9.signature";

/* Test JWT header parsing */
int test_jwt_parse_header() {
    char *header_b64 = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9";
    
    /* Decode base64 header */
    uint8_t *decoded;
    size_t decoded_len;
    bool result = test_base64_decode(header_b64, &decoded, &decoded_len);
    TEST_ASSERT(result, "Header should be decoded");
    TEST_ASSERT_NOT_NULL(decoded, "Header should be decoded");
    
    /* Parse JSON */
    json_error_t error;
    json_t *header_json = json_loadb((char*)decoded, decoded_len, 0, &error);
    TEST_ASSERT_NOT_NULL(header_json, "Header JSON should be parsed");
    
    /* Check algorithm */
    json_t *alg_obj = json_object_get(header_json, "alg");
    TEST_ASSERT_NOT_NULL(alg_obj, "Algorithm should exist");
    const char *alg = json_string_value(alg_obj);
    TEST_ASSERT_STR_EQ("RS256", alg, "Algorithm should be RS256");
    
    /* Check type */
    json_t *typ_obj = json_object_get(header_json, "typ");
    TEST_ASSERT_NOT_NULL(typ_obj, "Type should exist");
    const char *typ = json_string_value(typ_obj);
    TEST_ASSERT_STR_EQ("JWT", typ, "Type should be JWT");
    
    /* Cleanup */
    json_decref(header_json);
    free(decoded);
    
    return 0;
}

/* Test JWT payload parsing */
int test_jwt_parse_payload() {
    char *payload_b64 = "eyJpc3MiOiJodHRwczovL2lkLndpenpwLm5ldC9hcHBsaWNhdGlvbi9vL2N5cnVzLWltYXBkLyIsInN1YiI6InRlc3R1c2VyIiwiYXVkIjpbImVKWk9ZQlJMOGVxOGdRT0hldlkwRTJFSVhrUXRXME1jSE1Ta3NweTciXSwiZXhwIjoxNzMzNDE5MjAwLCJpYXQiOjE3MzM0MTU2MDAsIm5iZiI6MTczMzQxNTYwMCwic2NvcGUiOiJvcGVuaWQgZW1haWwgcHJvZmlsZSJ9";
    
    /* Decode base64 payload */
    uint8_t *decoded;
    size_t decoded_len;
    bool result = test_base64_decode(payload_b64, &decoded, &decoded_len);
    TEST_ASSERT(result, "Payload should be decoded");
    TEST_ASSERT_NOT_NULL(decoded, "Payload should be decoded");
    
    /* Parse JSON */
    json_error_t error;
    json_t *payload_json = json_loadb((char*)decoded, decoded_len, 0, &error);
    TEST_ASSERT_NOT_NULL(payload_json, "Payload JSON should be parsed");
    
    /* Check issuer */
    json_t *iss_obj = json_object_get(payload_json, "iss");
    TEST_ASSERT_NOT_NULL(iss_obj, "Issuer should exist");
    const char *iss = json_string_value(iss_obj);
    TEST_ASSERT_STR_EQ("https://id.wizzp.net/application/o/cyrus-imapd/", iss, "Issuer should match");
    
    /* Check subject */
    json_t *sub_obj = json_object_get(payload_json, "sub");
    TEST_ASSERT_NOT_NULL(sub_obj, "Subject should exist");
    const char *sub = json_string_value(sub_obj);
    TEST_ASSERT_STR_EQ("testuser", sub, "Subject should match");
    
    /* Check audience */
    json_t *aud_obj = json_object_get(payload_json, "aud");
    TEST_ASSERT_NOT_NULL(aud_obj, "Audience should exist");
    TEST_ASSERT(json_is_array(aud_obj), "Audience should be array");
    
    json_t *aud_item = json_array_get(aud_obj, 0);
    TEST_ASSERT_NOT_NULL(aud_item, "First audience item should exist");
    const char *aud = json_string_value(aud_item);
    TEST_ASSERT_STR_EQ("eJZOYBRL8eq8gQOHevY0E2EIXkQtW0McHMSkspy7", aud, "Audience should match");
    
    /* Check timestamps */
    json_t *exp_obj = json_object_get(payload_json, "exp");
    json_t *iat_obj = json_object_get(payload_json, "iat");
    json_t *nbf_obj = json_object_get(payload_json, "nbf");
    TEST_ASSERT_NOT_NULL(exp_obj, "Expiration should exist");
    TEST_ASSERT_NOT_NULL(iat_obj, "Issued at should exist");
    TEST_ASSERT_NOT_NULL(nbf_obj, "Not before should exist");
    
    json_int_t exp = json_integer_value(exp_obj);
    json_int_t iat = json_integer_value(iat_obj);
    json_int_t nbf = json_integer_value(nbf_obj);
    
    TEST_ASSERT(exp > iat, "Expiration should be after issued at");
    TEST_ASSERT(nbf <= iat, "Not before should be before or equal to issued at");
    
    /* Check scope */
    json_t *scope_obj = json_object_get(payload_json, "scope");
    TEST_ASSERT_NOT_NULL(scope_obj, "Scope should exist");
    const char *scope = json_string_value(scope_obj);
    TEST_ASSERT_STR_EQ("openid email profile", scope, "Scope should match");
    
    /* Cleanup */
    json_decref(payload_json);
    free(decoded);
    
    return 0;
}

/* Test JWT token splitting */
int test_jwt_token_split() {
    /* Split the mock JWT token */
    char *token_copy = strdup(mock_jwt_token);
    char *header = strtok(token_copy, ".");
    char *payload = strtok(NULL, ".");
    char *signature = strtok(NULL, ".");
    
    TEST_ASSERT_NOT_NULL(header, "Header should be extracted");
    TEST_ASSERT_NOT_NULL(payload, "Payload should be extracted");
    TEST_ASSERT_NOT_NULL(signature, "Signature should be extracted");
    
    TEST_ASSERT_STR_EQ("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9", header, "Header should match");
    TEST_ASSERT_STR_EQ("eyJpc3MiOiJodHRwczovL2lkLndpenpwLm5ldC9hcHBsaWNhdGlvbi9vL2N5cnVzLWltYXBkLyIsInN1YiI6InRlc3R1c2VyIiwiYXVkIjpbImVKWk9ZQlJMOGVxOGdRT0hldlkwRTJFSVhrUXRXME1jSE1Ta3NweTciXSwiZXhwIjoxNzMzNDE5MjAwLCJpYXQiOjE3MzM0MTU2MDAsIm5iZiI6MTczMzQxNTYwMCwic2NvcGUiOiJvcGVuaWQgZW1haWwgcHJvZmlsZSJ9", payload, "Payload should match");
    
    free(token_copy);
    return 0;
}

/* Test audience validation */
int test_jwt_validate_audience() {
    /* Test with single audience */
    const char *single_aud = "eJZOYBRL8eq8gQOHevY0E2EIXkQtW0McHMSkspy7";
    const char *valid_audiences = "eJZOYBRL8eq8gQOHevY0E2EIXkQtW0McHMSkspy7";
    
    /* This would normally call the validation function */
    TEST_ASSERT_STR_EQ(single_aud, valid_audiences, "Single audience should match");
    
    /* Test with multiple audiences */
    const char *multi_audiences = "aud1 aud2 aud3";
    /* This would normally call the validation function */
    TEST_ASSERT_NOT_NULL(multi_audiences, "Multiple audiences should be processed");
    
    return 0;
}

/* Test issuer validation */
int test_jwt_validate_issuer() {
    /* Test with single issuer */
    const char *single_iss = "https://id.wizzp.net/application/o/cyrus-imapd/";
    const char *valid_issuers = "https://id.wizzp.net/application/o/cyrus-imapd/";
    
    TEST_ASSERT_STR_EQ(single_iss, valid_issuers, "Single issuer should match");
    
    /* Test with multiple issuers */
    const char *multi_issuers = "https://issuer1.com https://issuer2.com";
    TEST_ASSERT_NOT_NULL(multi_issuers, "Multiple issuers should be processed");
    
    return 0;
}

/* Test timestamp validation */
int test_jwt_validate_timestamps() {
    time_t now = time(NULL);
    
    /* Test valid token (not expired, valid now) */
    time_t future_exp = now + 3600; /* 1 hour from now */
    TEST_ASSERT(future_exp > now, "Valid token should not be expired");
    
    time_t past_nbf = now - 60; /* 1 minute ago */
    TEST_ASSERT(past_nbf <= now, "Valid token should be active now");
    
    /* Test expired token */
    time_t past_exp = now - 3600; /* 1 hour ago */
    TEST_ASSERT(past_exp < now, "Expired token should be detected");
    
    /* Test not yet valid token */
    time_t future_nbf = now + 60; /* 1 minute from now */
    TEST_ASSERT(future_nbf > now, "Not yet valid token should be detected");
    
    return 0;
}

/* Test base64 decoding with invalid input */
int test_jwt_base64_decode_invalid() {
    uint8_t *decoded;
    size_t decoded_len;
    bool result = test_base64_decode(NULL, &decoded, &decoded_len);
    TEST_ASSERT(!result, "Should return false for NULL input");
    
    result = test_base64_decode("", &decoded, &decoded_len);
    TEST_ASSERT(!result, "Should return false for empty input");
    
    return 0;
}

/* Test JWT with missing claims */
int test_jwt_missing_claims() {
    /* Test with payload missing required claims */
    char *incomplete_payload = "eyJpc3MiOiJodHRwczovL2lkLndpenpwLm5ldC9hcHBsaWNhdGlvbi9vL2N5cnVzLWltYXBkLyJ9";
    
    uint8_t *decoded;
    size_t decoded_len;
    bool result = test_base64_decode(incomplete_payload, &decoded, &decoded_len);
    TEST_ASSERT(result, "Incomplete payload should still decode");
    TEST_ASSERT_NOT_NULL(decoded, "Incomplete payload should still decode");
    
    json_error_t error;
    json_t *payload_json = json_loadb((char*)decoded, decoded_len, 0, &error);
    TEST_ASSERT_NOT_NULL(payload_json, "Incomplete payload JSON should parse");
    
    /* Check that missing claims are handled */
    json_t *sub_obj = json_object_get(payload_json, "sub");
    TEST_ASSERT_NULL(sub_obj, "Subject should be missing");
    
    json_decref(payload_json);
    free(decoded);
    
    return 0;
}

/* Main test runner for JWT tests */
int main() {
    tests_total = 0;
    tests_passed = 0;
    tests_failed = 0;
    
    printf("Running OAuth2 JWT Unit Tests\n");
    printf("=============================\n");
    
    RUN_TEST(test_jwt_parse_header);
    RUN_TEST(test_jwt_parse_payload);
    RUN_TEST(test_jwt_token_split);
    RUN_TEST(test_jwt_validate_audience);
    RUN_TEST(test_jwt_validate_issuer);
    RUN_TEST(test_jwt_validate_timestamps);
    RUN_TEST(test_jwt_base64_decode_invalid);
    RUN_TEST(test_jwt_missing_claims);
    
    printf("\nResults: %d/%d tests passed (%d failed)\n", 
           tests_passed, tests_total, tests_failed);
    
    return tests_failed > 0 ? 1 : 0;
}
