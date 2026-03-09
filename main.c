// src/main.c
#include <stdio.h>
#include <stdint.h>
#include "sha3.h"

int main() {
    const char* input_string = "Hello, SHA-3!";

    sha3_context ctx;
    sha3_init(&ctx, 256);
    printf("block_size = %lu, hash_bit_len = %lu\n", (unsigned long)ctx.block_size, (unsigned long)ctx.hash_bit_len);
    sha3_update(&ctx, (const uint8_t*)input_string, 13);
    uint8_t hash[32];
    sha3_final(&ctx, hash);

    printf("Input String: %s\n", input_string);
    printf("SHA3-256 (context API): ");
    for (size_t i = 0; i < 32; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    uint8_t hash2[32];
    sha3_hash((const uint8_t*)input_string, 13, 256, hash2);
    printf("SHA3-256 (high-level):  ");
    for (size_t i = 0; i < 32; i++) {
        printf("%02x", hash2[i]);
    }
    printf("\n");

    return 0;
}
