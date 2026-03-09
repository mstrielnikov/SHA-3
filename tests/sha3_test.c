#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha3.h"

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

static int hexcmp(const char *a, const char *b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (a[i] != b[i]) return 0;
    }
    return 1;
}

#define TEST_HASH(bit_len, func, input, expected) do { \
    tests_run++; \
    sha3_byte_t hash[64]; \
    size_t input_len = strlen(input); \
    func((const sha3_byte_t*)(input), input_len, hash); \
    char hash_hex[256] = {0}; \
    for (size_t i = 0; i < bit_len/8; i++) { \
        sprintf(hash_hex + i*2, "%02x", hash[i]); \
    } \
    if (hexcmp(hash_hex, expected, bit_len/8 * 2)) { \
        tests_passed++; \
        printf("[PASS] SHA3-%d \"%s\"\n", bit_len, input); \
    } else { \
        tests_failed++; \
        printf("[FAIL] SHA3-%d \"%s\"\n", bit_len, input); \
        printf("  Expected: %s\n", expected); \
        printf("  Got:      %s\n", hash_hex); \
    } \
} while(0)

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
    sha3_byte_t hash_single[64];
    
    sha3_init(&ctx, 256);
    sha3_update(&ctx, (const sha3_byte_t*)"a", 1);
    sha3_update(&ctx, (const sha3_byte_t*)"bc", 2);
    sha3_final(&ctx, hash);
    
    sha3_256((const sha3_byte_t*)"abc", 3, hash_single);
    
    int match = 1;
    for (int i = 0; i < 32; i++) {
        if (hash[i] != hash_single[i]) match = 0;
    }
    TEST_ASSERT(match, "Split updates match single sha3_256");
    
    TEST_ASSERT(ctx.count == 3, "Update accumulates count correctly");
}

void test_api_final(void) {
    printf("\n=== API: Final ===\n");
    sha3_context ctx;
    sha3_byte_t hash[32];
    
    sha3_init(&ctx, 256);
    sha3_final(&ctx, hash);
    
    sha3_byte_t expected[32];
    sha3_256((const sha3_byte_t*)"", 0, expected);
    
    int match = 1;
    for (int i = 0; i < 32; i++) {
        if (hash[i] != expected[i]) match = 0;
    }
    TEST_ASSERT(match, "Final matches sha3_256 for empty input");
}

void test_multiblock(void) {
    printf("\n=== Multi-Block Message ===\n");
    const char *long_msg = "The quick brown fox jumps over the lazy dog";
    sha3_context ctx;
    sha3_byte_t hash[32];
    sha3_byte_t hash_direct[32];
    
    sha3_init(&ctx, 256);
    size_t chunk = 17;
    size_t msg_len = strlen(long_msg);
    for (size_t i = 0; i < msg_len; i += chunk) {
        size_t len = (i + chunk < msg_len) ? chunk : msg_len - i;
        sha3_update(&ctx, (const sha3_byte_t*)long_msg + i, len);
    }
    sha3_final(&ctx, hash);
    
    sha3_256((const sha3_byte_t*)long_msg, msg_len, hash_direct);
    
    int match = 1;
    for (int i = 0; i < 32; i++) {
        if (hash[i] != hash_direct[i]) match = 0;
    }
    TEST_ASSERT(match, "Multi-block matches single sha3_256 call");
}

void test_short_vectors(void) {
    printf("\n=== Short Input Test Vectors ===\n");
    TEST_HASH(256, sha3_256, "",      "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    TEST_HASH(256, sha3_256, "a",     "80084bf2fba02475726feb2cab2d8215eab14bc6bdd8bfb2c8151257032ecd8b");
    TEST_HASH(256, sha3_256, "abc",   "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    TEST_HASH(256, sha3_256, "message", "7f4a23d90de90d100754f82d6c14073b7fb466f76fd1f61b187b9f39c3ffd895");
}

void test_variable_length(void) {
    printf("\n=== Variable Length Test Vectors ===\n");
    TEST_HASH(224, sha3_224, "abc", "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf");
    TEST_HASH(256, sha3_256, "abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    TEST_HASH(384, sha3_384, "abc", "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25");
    TEST_HASH(512, sha3_512, "abc", "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");
}

void test_nist_vectors(void) {
    printf("\n=== NIST Test Vectors ===\n");
    const char *nist_msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    
    TEST_HASH(224, sha3_224, "abc", "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf");
    TEST_HASH(256, sha3_256, "abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    TEST_HASH(384, sha3_384, "abc", "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25");
    TEST_HASH(512, sha3_512, "abc", "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");
    
    TEST_HASH(224, sha3_224, nist_msg, "8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33");
    TEST_HASH(256, sha3_256, nist_msg, "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376");
    TEST_HASH(384, sha3_384, nist_msg, "991c665755eb3a4b6bbdfb75c78a492e8c56a22c5c4d7e429bfdbc32b9d4ad5aa04a1f076e62fea19eef51acd0657c22");
    TEST_HASH(512, sha3_512, nist_msg, "04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636dee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e");
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
