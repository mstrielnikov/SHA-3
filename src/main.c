// src/main.c
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "sha3.h"

int main() {
    // Define the input string
    const char* input_string = "Hello, SHA-3!";

    // Initialize SHA-3 context for a 256-bit hash
    sha3_context ctx;
    sha3_init(&ctx, 256);

    // Update the context with the input string
    sha3_update(&ctx, (const uint8_t*)input_string, strlen(input_string));

    // Finalize the hash
    uint8_t hash[32];  // 256 bits = 32 bytes
    sha3_final(&ctx, hash);

    // Print the original string and its SHA-3 hash
    printf("Input String: %s\n", input_string);
    printf("SHA-3 Hash: ");
    for (size_t i = 0; i < sizeof(hash); i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    return 0;
}
