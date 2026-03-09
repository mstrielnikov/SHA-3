# SHA-3 Implementation in C

A portable, zero-dependency C implementation of the SHA-3 (Keccak) cryptographic hash function, compliant with FIPS 202 standard.

## Features

- **Zero external dependencies** - No libc dependency for core SHA-3 functions
- **Standards compliant** - Implements FIPS 202 SHA-3
- **Multiple hash sizes** - SHA3-224, SHA3-256, SHA3-384, SHA3-512
- **Simple API** - High-level one-shot functions and low-level context API
- **Well tested** - Full test suite with NIST test vectors

## Quick Start

```c
#include "sha3.h"

sha3_byte_t hash[32];
sha3_256((const sha3_byte_t*)"Hello, World!", 13, hash);
```

## Building

```bash
make        # Build example
make tests  # Build and run tests
make clean  # Clean build artifacts
```

## API Reference

### High-Level One-Shot Functions

```c
sha3_byte_t *sha3_224(const sha3_byte_t *data, sha3_size_t len, sha3_byte_t *hash);
sha3_byte_t *sha3_256(const sha3_byte_t *data, sha3_size_t len, sha3_byte_t *hash);
sha3_byte_t *sha3_384(const sha3_byte_t *data, sha3_size_t len, sha3_byte_t *hash);
sha3_byte_t *sha3_512(const sha3_byte_t *data, sha3_size_t len, sha3_byte_t *hash);
```

Single-call functions that hash data in one operation. Returns the hash buffer pointer.

### Generic Function

```c
sha3_byte_t *sha3_hash(const sha3_byte_t *data, sha3_size_t len, sha3_size_t hash_bit_len, sha3_byte_t *hash);
```

Hash data with arbitrary bit length (224, 256, 384, or 512).

### Low-Level Context API

```c
void sha3_init(sha3_context *ctx, sha3_size_t hash_bit_len);
void sha3_update(sha3_context *ctx, const sha3_byte_t *data, sha3_size_t len);
void sha3_final(sha3_context *ctx, sha3_byte_t *hash);
```

For streaming/incremental hashing of large data.

## Data Types

| Type | Description |
|------|-------------|
| `sha3_byte_t` | Unsigned char (8-bit) |
| `sha3_uint64_t` | Unsigned 64-bit integer |
| `sha3_size_t` | Unsigned size type |
| `sha3_context` | Opaque state structure |

## Hash Output Sizes

| Function | Output Size |
|----------|-------------|
| `sha3_224` | 28 bytes (224 bits) |
| `sha3_256` | 32 bytes (256 bits) |
| `sha3_384` | 48 bytes (384 bits) |
| `sha3_512` | 64 bytes (512 bits) |

## Example Usage

### One-shot hashing

```c
#include "sha3.h"
#include <stdio.h>

int main() {
    const char *msg = "Hello, SHA-3!";
    
    sha3_byte_t hash[32];
    sha3_256((const sha3_byte_t*)msg, 13, hash);
    
    printf("SHA3-256: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
    
    return 0;
}
```

### Incremental hashing

```c
sha3_context ctx;
sha3_init(&ctx, 256);

sha3_update(&ctx, (const sha3_byte_t*)"part1", 5);
sha3_update(&ctx, (const sha3_byte_t*)"part2", 5);

sha3_byte_t hash[32];
sha3_final(&ctx, hash);
```

## Project Structure

```
SHA-3/
├── include/
│   ├── sha3.h          # Public API header
│   └── keccak.h       # Internal Keccak header
├── src/
│   ├── sha3.c          # SHA-3 implementation
│   └── keccak.c        # Keccak-f[1600] permutation
├── tests/
│   └── sha3_test.c     # Test suite
├── main.c              # Example program
├── Makefile            # Build configuration
└── README.md           # This file
```

## Testing

The test suite includes:
- API initialization tests
- Multi-block message handling
- Short input test vectors
- Variable-length tests (224/256/384/512)
- NIST test vectors

Run tests with:
```bash
make tests
```

## License

MIT License

Copyright (c) 2024

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
