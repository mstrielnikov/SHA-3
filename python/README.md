# Python Bindings for SHA-3

Python C extension module that wraps the C SHA-3 implementation.

## Building

```bash
make python
```

## Usage

```python
import sha3_c

# One-shot hashing
hash_256 = sha3_c.sha3_256(b"Hello, World!")  # returns bytes
hash_224 = sha3_c.sha3_224(b"Hello, World!")
hash_384 = sha3_c.sha3_384(b"Hello, World!")
hash_512 = sha3_c.sha3_512(b"Hello, World!")

# Generic function with arbitrary bit length
hash_256 = sha3_c.sha3_hash(b"Hello, World!", 256)  # data, bit_len

# Get hex string
print(hash_256.hex())
```

## API

| Function | Description |
|----------|-------------|
| `sha3_c.sha3_224(data)` | SHA3-224 hash (returns 28 bytes) |
| `sha3_c.sha3_256(data)` | SHA3-256 hash (returns 32 bytes) |
| `sha3_c.sha3_384(data)` | SHA3-384 hash (returns 48 bytes) |
| `sha3_c.sha3_512(data)` | SHA3-512 hash (returns 64 bytes) |
| `sha3_c.sha3_hash(data, bit_len)` | Generic SHA-3 hash (224/256/384/512) |

All functions accept bytes or bytearray input and return bytes.
