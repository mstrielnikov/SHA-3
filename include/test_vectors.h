#ifndef TEST_VECTORS_H
#define TEST_VECTORS_H

#include "sha3.h"

#define SHA3_TEST_VECTORS(...) \
    /* { bit_len, input, expected_hex } */ \
    __VA_ARGS__

typedef struct {
    sha3_size_t bit_len;
    const char *input;
    size_t input_len;
    const char *expected_hex;
} sha3_test_vector_t;

#define SV(bit_len, input, expected) \
    { bit_len, input, sizeof(input) - 1, expected }

static const sha3_test_vector_t sha3_short_test_vectors[] = {
    SV(256, "",      "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
    SV(256, "a",     "80084bf2fba02475726feb2cab2d8215eab14bc6bdd8bfb2c8151257032ecd8b"),
    SV(256, "abc",   "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
    SV(256, "message", "7f4a23d90de90d100754f82d6c14073b7fb466f76fd1f61b187b9f39c3ffd895"),
};

static const sha3_test_vector_t sha3_variable_length_test_vectors[] = {
    SV(224, "abc", "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"),
    SV(256, "abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
    SV(384, "abc", "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"),
    SV(512, "abc", "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"),
};

static const sha3_test_vector_t sha3_nist_test_vectors[] = {
    SV(224, "abc", "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"),
    SV(256, "abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
    SV(384, "abc", "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"),
    SV(512, "abc", "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"),
    SV(224, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33"),
    SV(256, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376"),
    SV(384, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "991c665755eb3a4b6bbdfb75c78a492e8c56a22c5c4d7e429bfdbc32b9d4ad5aa04a1f076e62fea19eef51acd0657c22"),
    SV(512, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636dee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e"),
};

#define SHA3_SHORT_VECTORS_COUNT    (sizeof(sha3_short_test_vectors) / sizeof(sha3_test_vector_t))
#define SHA3_VARIABLE_VECTORS_COUNT (sizeof(sha3_variable_length_test_vectors) / sizeof(sha3_test_vector_t))
#define SHA3_NIST_VECTORS_COUNT     (sizeof(sha3_nist_test_vectors) / sizeof(sha3_test_vector_t))

#endif
