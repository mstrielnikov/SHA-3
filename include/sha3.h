#ifndef SHA3_H
#define SHA3_H

#define sha3_uint64_t unsigned long long int
#define sha3_size_t unsigned long int
#define sha3_byte_t unsigned char   

typedef struct {
    sha3_uint64_t state[25];
    sha3_size_t    count;
    sha3_size_t    block_size;
    sha3_size_t    hash_bit_len;
    sha3_byte_t   buffer[144];
} sha3_context;

void sha3_init(sha3_context *ctx, sha3_size_t hash_bit_len);
void sha3_update(sha3_context *ctx, const sha3_byte_t *data, sha3_size_t len);
void sha3_final(sha3_context *ctx, sha3_byte_t *hash);

sha3_byte_t *sha3_hash(const sha3_byte_t *data, sha3_size_t len, sha3_size_t hash_bit_len, sha3_byte_t *hash);

sha3_byte_t *sha3_224(const sha3_byte_t *data, sha3_size_t len, sha3_byte_t *hash);
sha3_byte_t *sha3_256(const sha3_byte_t *data, sha3_size_t len, sha3_byte_t *hash);
sha3_byte_t *sha3_384(const sha3_byte_t *data, sha3_size_t len, sha3_byte_t *hash);
sha3_byte_t *sha3_512(const sha3_byte_t *data, sha3_size_t len, sha3_byte_t *hash);

#endif  // SHA3_H
