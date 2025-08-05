#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* Forward declaration for SASL connection type */
struct sasl_conn;
typedef struct sasl_conn sasl_conn_t;

/* Global test counters */
extern int tests_total;
extern int tests_passed;
extern int tests_failed;

/* Enhanced test framework macros with proper tracking */
#define TEST_ASSERT(condition, message) \
    do { \
        tests_total++; \
        if (!(condition)) { \
            fprintf(stderr, "FAIL: %s - %s\n", __func__, message); \
            tests_failed++; \
            return -1; \
        } \
        tests_passed++; \
    } while(0)

#define TEST_ASSERT_EQ(expected, actual, message) \
    do { \
        tests_total++; \
        if ((expected) != (actual)) { \
            fprintf(stderr, "FAIL: %s - %s (expected: %d, actual: %d)\n", \
                    __func__, message, (int)(expected), (int)(actual)); \
            tests_failed++; \
            return -1; \
        } \
        tests_passed++; \
    } while(0)

#define TEST_ASSERT_STR_EQ(expected, actual, message) \
    do { \
        tests_total++; \
        if (strcmp((expected), (actual)) != 0) { \
            fprintf(stderr, "FAIL: %s - %s (expected: '%s', actual: '%s')\n", \
                    __func__, message, (expected), (actual)); \
            tests_failed++; \
            return -1; \
        } \
        tests_passed++; \
    } while(0)

#define TEST_ASSERT_NULL(ptr, message) \
    do { \
        tests_total++; \
        if ((ptr) != NULL) { \
            fprintf(stderr, "FAIL: %s - %s (expected NULL, got %p)\n", \
                    __func__, message, (ptr)); \
            tests_failed++; \
            return -1; \
        } \
        tests_passed++; \
    } while(0)

#define TEST_ASSERT_NOT_NULL(ptr, message) \
    do { \
        tests_total++; \
        if ((ptr) == NULL) { \
            fprintf(stderr, "FAIL: %s - %s (expected non-NULL, got NULL)\n", \
                    __func__, message); \
            tests_failed++; \
            return -1; \
        } \
        tests_passed++; \
    } while(0)

#define RUN_TEST(test_func) \
    do { \
        printf("Running %s... ", #test_func); \
        if (test_func() == 0) { \
            printf("PASS\n"); \
            tests_passed++; \
        } else { \
            printf("FAIL\n"); \
            tests_failed++; \
        } \
        tests_total++; \
    } while(0)

/* Test statistics */
extern int tests_total;
extern int tests_passed;
extern int tests_failed;

/* Mock SASL utilities for testing */
typedef struct mock_sasl_utils {
    int (*getopt)(void *context, const char *plugin_name, const char *option, 
                  const char **result, unsigned *len);
    void *(*malloc)(size_t size);
    void (*free)(void *ptr);
    void *getopt_context;
    void *conn;
    int (*log)(void *conn, int level, const char *fmt, ...);
} mock_sasl_utils_t;

/* Mock functions */
int mock_getopt(void *context, const char *plugin_name, const char *option, 
                const char **result, unsigned *len);
void *mock_malloc(size_t size);
void mock_free(void *ptr);
void mock_config_set(const char *plugin_name, const char *key, const char *value);
void mock_config_clear(void);
void mock_log(sasl_conn_t *conn, int level, const char *fmt, ...);

/* Simple base64 decode for testing purposes */
bool test_base64_decode(const char *src, uint8_t **dst, size_t *dst_len);

#endif /* TEST_FRAMEWORK_H */
