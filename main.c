// src/main.c
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "sha3.h"

int main() {
    const char* input_string = "Hello, SHA-3!";
    printf("Input String: %s\n", input_string);
    printf("SHA3-256 (context API): ");

    uint8_t hash[32];
    sha3_hash((const uint8_t*)input_string, strlen(input_string), 256, hash);
    
    printf("\n");

    return 0;
}
