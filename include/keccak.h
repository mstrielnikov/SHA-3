#ifndef KECCAK_H
#define KECCAK_H

#include "sha3.h"

void keccakf(sha3_uint64_t st[25]);
void keccak_absorb(sha3_context *ctx);

#endif  // KECCAK_H
