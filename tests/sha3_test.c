#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha3.h"
#include "test_vectors.h"

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(expr, msg) do { \
    tests_run++; \
    if (expr) { \
        tests_passed++; \
        printf("[PASS] %s\n", msg); \
    } else { \
        tests_failed++; \
        printf("[FAIL] %s\n", msg); \
    } \
} while(0)

#define TEST_ASSERT_HASH(vec) do { \
    tests_run++; \
    sha3_context ctx; \
    sha3_init(&ctx, (vec)->bit_len); \
    sha3_update(&ctx, (const sha3_byte_t*)(vec)->input, (vec)->input_len); \
    sha3_byte_t hash[64]; \
    sha3_final(&ctx, hash); \
    \
    size_t expected_len = (vec)->bit_len / 8; \
    char hash_hex[256] = {0}; \
    for (size_t i = 0; i < expected_len; i++) { \
        sprintf(hash_hex + i*2, "%02x", hash[i]); \
    } \
    \
    if (memcmp(hash_hex, (vec)->expected_hex, expected_len * 2) == 0) { \
        tests_passed++; \
        printf("[PASS] SHA3-%lu \"%s\"\n", (unsigned long)(vec)->bit_len, (vec)->input); \
    } else { \
        tests_failed++; \
        printf("[FAIL] SHA3-%lu \"%s\"\n", (unsigned long)(vec)->bit_len, (vec)->input); \
        printf("  Expected: %s\n", (vec)->expected_hex); \
        printf("  Got:      %s\n", hash_hex); \
    } \
} while(0)

void test_short_vectors(void) {
    printf("\n=== Short Input Test Vectors ===\n");
    for (size_t i = 0; i < SHA3_SHORT_VECTORS_COUNT; i++) {
        TEST_ASSERT_HASH(&sha3_short_test_vectors[i]);
    }
}

void test_variable_length(void) {
    printf("\n=== Variable Length Test Vectors ===\n");
    for (size_t i = 0; i < SHA3_VARIABLE_VECTORS_COUNT; i++) {
        TEST_ASSERT_HASH(&sha3_variable_length_test_vectors[i]);
    }
}

void test_nist_vectors(void) {
    printf("\n=== NIST Test Vectors ===\n");
    for (size_t i = 0; i < SHA3_NIST_VECTORS_COUNT; i++) {
        TEST_ASSERT_HASH(&sha3_nist_test_vectors[i]);
    }
}

void test_api_init(void) {
    printf("\n=== API: Initialization ===\n");
    sha3_context ctx;
    
    sha3_init(&ctx, 256);
    TEST_ASSERT(ctx.hash_bit_len == 256, "Init SHA3-256 sets hash_bit_len");
    TEST_ASSERT(ctx.block_size == (1600 - 512) / 8, "Init SHA3-256 sets correct block_size");
    
    sha3_init(&ctx, 512);
    TEST_ASSERT(ctx.hash_bit_len == 512, "Init SHA3-512 sets hash_bit_len");
    TEST_ASSERT(ctx.block_size == (1600 - 1024) / 8, "Init SHA3-512 sets correct block_size");
    
    sha3_init(&ctx, 0);
    TEST_ASSERT(ctx.block_size == 0, "Init with invalid size sets block_size to 0");
}

void test_api_update(void) {
    printf("\n=== API: Update ===\n");
    sha3_context ctx;
    sha3_byte_t hash[64];
    
    sha3_init(&ctx, 256);
    sha3_update(&ctx, (const sha3_byte_t*)"a", 1);
    sha3_update(&ctx, (const sha3_byte_t*)"bc", 2);
    sha3_final(&ctx, hash);
    
    sha3_context ctx_single;
    sha3_init(&ctx_single, 256);
    sha3_update(&ctx_single, (const sha3_byte_t*)"abc", 3);
    sha3_final(&ctx_single, hash);
    
    TEST_ASSERT(ctx.count == 3, "Update accumulates count correctly");
    TEST_ASSERT(ctx.count == ctx_single.count, "Split updates match single update");
}

void test_api_final(void) {
    printf("\n=== API: Final ===\n");
    sha3_context ctx;
    sha3_byte_t hash[32];
    
    sha3_init(&ctx, 256);
    sha3_final(&ctx, hash);
    
    int has_nonzero = 0;
    for (int i = 0; i < 32; i++) {
        if (hash[i] != 0) has_nonzero = 1;
    }
    TEST_ASSERT(has_nonzero, "Final produces non-zero hash for empty input");
    
    const unsigned char expected_empty_sha3_256[] = {
        0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
        0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
        0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
        0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a
    };
    int match = 1;
    for (int i = 0; i < 32; i++) {
        if (hash[i] != expected_empty_sha3_256[i]) match = 0;
    }
    TEST_ASSERT(match, "Empty input produces correct SHA3-256 hash");
}

void test_multiblock(void) {
    printf("\n=== Multi-Block Message ===\n");
    const char *long_msg = "The quick brown fox jumps over the lazy dog";
    sha3_context ctx;
    sha3_byte_t hash[64];
    
    sha3_init(&ctx, 256);
    size_t chunk = 17;
    for (size_t i = 0; i < strlen(long_msg); i += chunk) {
        size_t len = (i + chunk < strlen(long_msg)) ? chunk : strlen(long_msg) - i;
        sha3_update(&ctx, (const sha3_byte_t*)long_msg + i, len);
    }
    sha3_final(&ctx, hash);
    
    sha3_context ctx_direct;
    sha3_init(&ctx_direct, 256);
    sha3_update(&ctx_direct, (const sha3_byte_t*)long_msg, strlen(long_msg));
    sha3_final(&ctx_direct, hash);
    
    TEST_ASSERT(ctx.count == ctx_direct.count, "Multi-block count matches direct");
}

int main(void) {
    printf("========================================\n");
    printf("       SHA-3 Test Suite\n");
    printf("========================================\n");
    
    test_api_init();
    test_api_update();
    test_api_final();
    test_multiblock();
    test_short_vectors();
    test_variable_length();
    test_nist_vectors();
    
    printf("\n========================================\n");
    printf("Results: %d/%d tests passed\n", tests_passed, tests_run);
    printf("========================================\n");
    
    return tests_failed > 0 ? 1 : 0;
}
