#ifndef SHA3_H
#define SHA3_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint64_t state[25];
    size_t    count;
    size_t    block_size;
    uint8_t   buffer[144];
} sha3_context;

void sha3_init(sha3_context *ctx, size_t hash_bit_len);
void sha3_update(sha3_context *ctx, const uint8_t *data, size_t len);
void sha3_final(sha3_context *ctx, uint8_t *hash);

#endif  // SHA3_H
