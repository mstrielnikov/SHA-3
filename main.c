// src/main.c
#include <stdio.h>
#include <stdint.h>
#include "sha3.h"

int main() {
    const char* input = "Hello, SHA-3!";
    sha3_size_t len = 13;

    sha3_byte_t hash256[32];
    sha3_byte_t hash224[28];
    sha3_byte_t hash384[48];
    sha3_byte_t hash512[64];

    sha3_256((const sha3_byte_t*)input, len, hash256);
    sha3_224((const sha3_byte_t*)input, len, hash224);
    sha3_384((const sha3_byte_t*)input, len, hash384);
    sha3_512((const sha3_byte_t*)input, len, hash512);

    printf("Input: \"%s\"\n\n", input);

    printf("SHA3-224: ");
    for (size_t i = 0; i < 28; i++) printf("%02x", hash224[i]);
    printf("\n");

    printf("SHA3-256: ");
    for (size_t i = 0; i < 32; i++) printf("%02x", hash256[i]);
    printf("\n");

    printf("SHA3-384: ");
    for (size_t i = 0; i < 48; i++) printf("%02x", hash384[i]);
    printf("\n");

    printf("SHA3-512: ");
    for (size_t i = 0; i < 64; i++) printf("%02x", hash512[i]);
    printf("\n");

    return 0;
}
