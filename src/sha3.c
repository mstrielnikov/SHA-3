#include "sha3.h"
#include "keccak.h"

static void *sha3_memset(void *s, int c, sha3_size_t n) {
    sha3_byte_t *p = s;
    while (n) {
        *p++ = (sha3_byte_t)c;
        n--;
    }
    return s;
}

void sha3_init(sha3_context *ctx, sha3_size_t hash_bit_len) {
    sha3_memset(ctx, 0, sizeof(*ctx));

    if (hash_bit_len == 224 || hash_bit_len == 256 ||
        hash_bit_len == 384 || hash_bit_len == 512) {
        ctx->block_size   = (1600 - hash_bit_len * 2) / 8;
        ctx->hash_bit_len = hash_bit_len;
    } else {
        ctx->block_size = 0;
        return;
    }
    ctx->count = 0;
}

void sha3_update(sha3_context *ctx, const sha3_byte_t *data, sha3_size_t len) {
    sha3_size_t i;
    sha3_size_t index = ctx->count % ctx->block_size;
    ctx->count += len;

    for (i = 0; i < len; i++) {
        ctx->buffer[index++] = data[i];
        if (index == ctx->block_size) {
            keccak_absorb(ctx);
            keccakf(ctx->state);
            index = 0;
        }
    }
}


void sha3_final(sha3_context *ctx, sha3_byte_t *hash) {
    if (ctx->block_size == 0) return;

    sha3_size_t index = ctx->count % ctx->block_size;
    
    if (index == ctx->block_size) {
        keccak_absorb(ctx);
        keccakf(ctx->state);
        index = 0;
    }
    
    ctx->buffer[index++] = 0x06;
    sha3_memset(ctx->buffer + index, 0, ctx->block_size - index);
    ctx->buffer[ctx->block_size - 1] |= 0x80;

    keccak_absorb(ctx);
    keccakf(ctx->state);

    sha3_size_t output_len = ctx->hash_bit_len / 8;
    for (sha3_size_t i = 0; i < output_len; i++) {
        sha3_size_t word = i / 8;
        sha3_size_t byte = i % 8;
        hash[i] = (sha3_byte_t)(ctx->state[word] >> (byte * 8));
    }
}

sha3_byte_t *sha3_hash(const sha3_byte_t *data, sha3_size_t len, sha3_size_t hash_bit_len, sha3_byte_t *hash) {
    sha3_context ctx;
    sha3_init(&ctx, hash_bit_len);
    if (ctx.block_size == 0) return NULL;
    sha3_update(&ctx, data, len);
    sha3_final(&ctx, hash);
    return hash;
}

