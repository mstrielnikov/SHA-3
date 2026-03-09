#include "keccak.h"

#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

static const sha3_uint64_t keccakf_rndc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static const int keccakf_rotc[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const int keccakf_piln[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

void keccakf(sha3_uint64_t st[25]) {
    int round, x, y;
    sha3_uint64_t t, bc[5];

    for (round = 0; round < 24; round++) {
        // Theta
        for (x = 0; x < 5; x++) {
            bc[x] = st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20];
        }

        for (x = 0; x < 5; x++) {
            t = bc[(x + 4) % 5] ^ ROTL64(bc[(x + 1) % 5], 1);
            for (y = 0; y < 25; y += 5) {
                st[y + x] ^= t;
            }
        }

        // Rho Pi
        t = st[1];
        for (x = 0; x < 24; x++) {
            y = keccakf_piln[x];
            bc[0] = st[y];
            st[y] = ROTL64(t, keccakf_rotc[x]);
            t = bc[0];
        }

        // Chi
        for (y = 0; y < 25; y += 5) {
            for (x = 0; x < 5; x++) {
                bc[x] = st[y + x];
            }
            for (x = 0; x < 5; x++) {
                st[y + x] ^= (~bc[(x + 1) % 5]) & bc[(x + 2) % 5];
            }
        }

        // Iota
        st[0] ^= keccakf_rndc[round];
    }
}

// Helper to absorb a full block (little-endian 64-bit words)
void keccak_absorb(sha3_context *ctx) {
    for (sha3_size_t j = 0; j < ctx->block_size; j += 8) {
        ctx->state[j / 8] ^= ((sha3_uint64_t)ctx->buffer[j + 0]) |
                             ((sha3_uint64_t)ctx->buffer[j + 1] << 8) |
                             ((sha3_uint64_t)ctx->buffer[j + 2] << 16) |
                             ((sha3_uint64_t)ctx->buffer[j + 3] << 24) |
                             ((sha3_uint64_t)ctx->buffer[j + 4] << 32) |
                             ((sha3_uint64_t)ctx->buffer[j + 5] << 40) |
                             ((sha3_uint64_t)ctx->buffer[j + 6] << 48) |
                             ((sha3_uint64_t)ctx->buffer[j + 7] << 56);
    }
}
