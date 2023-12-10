#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

typedef struct {
    uint64_t state[25];
    size_t   count;
    size_t   block_size;
    uint8_t  buffer[144];
} sha3_context;

static const uint64_t keccakf_rndc[24] = {
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

void sha3_init(sha3_context *ctx, size_t hash_bit_len);
void sha3_update(sha3_context *ctx, const uint8_t *data, size_t len);
void sha3_final(sha3_context *ctx, uint8_t *hash);

static void keccakf(uint64_t st[25]);

void sha3_init(sha3_context *ctx, size_t hash_bit_len) {
    memset(ctx, 0, sizeof(*ctx));

    if (hash_bit_len == 224 || hash_bit_len == 256 || hash_bit_len == 384 || hash_bit_len == 512) {
        ctx->block_size = 1600 - hash_bit_len * 2;
    } else {
        // Unsupported hash length
        return;
    }

    ctx->count = 0;
}

void sha3_update(sha3_context *ctx, const uint8_t *data, size_t len) {
    size_t i;
    size_t index = ctx->count % ctx->block_size;
    ctx->count += len;

    for (i = 0; i < len; i++) {
        ctx->buffer[index++] = data[i];
        if (index == ctx->block_size) {
            keccakf(ctx->state);
            index = 0;
        }
    }
}

void sha3_final(sha3_context *ctx, uint8_t *hash) {
    size_t index = ctx->count % ctx->block_size;
    ctx->buffer[index++] = 0x06; // SHA-3 padding rule
    memset(ctx->buffer + index, 0, ctx->block_size - index);
    ctx->buffer[ctx->block_size - 1] |= 0x80; // Set the last byte to 0x80

    keccakf(ctx->state);

    for (size_t i = 0; i < ctx->block_size / 8; i++) {
        hash[i * 8 + 0] = ctx->state[i] & 0xFF;
        hash[i * 8 + 1] = (ctx->state[i] >> 8) & 0xFF;
        hash[i * 8 + 2] = (ctx->state[i] >> 16) & 0xFF;
        hash[i * 8 + 3] = (ctx->state[i] >> 24) & 0xFF;
        hash[i * 8 + 4] = (ctx->state[i] >> 32) & 0xFF;
        hash[i * 8 + 5] = (ctx->state[i] >> 40) & 0xFF;
        hash[i * 8 + 6] = (ctx->state[i] >> 48) & 0xFF;
        hash[i * 8 + 7] = (ctx->state[i] >> 56) & 0xFF;
    }
}

static void keccakf(uint64_t st[25]) {
    int round, x, y;
    uint64_t t, bc[5];

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
