#include "test_framework.h"
#include "mock_sasl.h"
#include <stdlib.h>
#include <stdint.h>

/* Test statistics */
int tests_total = 0;
int tests_passed = 0;
int tests_failed = 0;

/* Simple base64 decode table */
static const int base64_decode_table[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
};

/* Simple base64 decode for testing purposes */
bool test_base64_decode(const char *src, uint8_t **dst, size_t *dst_len) {
    if (!src || !dst || !dst_len) {
        return false;
    }
    
    size_t src_len = strlen(src);
    if (src_len == 0) {
        return false;
    }
    
    /* Calculate output length */
    size_t padding = 0;
    if (src_len >= 2) {
        if (src[src_len - 1] == '=') padding++;
        if (src[src_len - 2] == '=') padding++;
    }
    
    size_t out_len = (src_len * 3) / 4 - padding;
    *dst = (uint8_t*)malloc(out_len + 1);
    if (!*dst) {
        return false;
    }
    
    size_t out_pos = 0;
    uint32_t buf = 0;
    int buf_len = 0;
    
    for (size_t i = 0; i < src_len; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '=') break;
        
        int val = base64_decode_table[c];
        if (val < 0) {
            free(*dst);
            *dst = NULL;
            return false;
        }
        
        buf = (buf << 6) | val;
        buf_len += 6;
        
        if (buf_len >= 8) {
            buf_len -= 8;
            (*dst)[out_pos++] = (buf >> buf_len) & 0xFF;
        }
    }
    
    (*dst)[out_pos] = '\0';
    *dst_len = out_pos;
    return true;
}
