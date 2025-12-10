# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a DuckDB extension that adds cryptographic hash functions, HMAC calculation, encryption/decryption, and cryptographically secure random byte generation using OpenSSL and BLAKE3.

## Architecture

The extension is implemented in C++ and uses OpenSSL's EVP API for cryptographic operations, with BLAKE3 provided by a vendored library:

**Source files** (`src/`):
- `crypto_extension.cpp`: Main extension entry point, registers all functions with DuckDB
- `crypto_hash.cpp`: Core hash, HMAC, and random byte implementations
- `crypto_enc.cpp`: Encryption/decryption using OpenSSL ciphers (AES-GCM, AES-CBC, etc.)
- `query_farm_telemetry.cpp`: Telemetry integration

**Implemented functions**:
- `crypto_hash(algorithm, value)` - Scalar function for hashing various data types
- `crypto_hmac(algorithm, key, message)` - Scalar function for HMAC computation
- `crypto_hash_agg(algorithm, value ORDER BY ...)` - Aggregate function for hashing multiple rows
- `crypto_random_bytes(length)` - Scalar function for generating random bytes
- `crypto_encrypt(cipher, key, plaintext)` - Encrypt data using OpenSSL ciphers
- `crypto_decrypt(cipher, key, ciphertext)` - Decrypt data using OpenSSL ciphers

### Build Integration

- Uses vcpkg for dependency management (OpenSSL, BLAKE3)
- Links against OpenSSL::SSL and OpenSSL::Crypto
- Build configuration in `extension_config.cmake`

## Common Commands

### Building

Debug build:
```sh
VCPKG_TOOLCHAIN_PATH=`pwd`/vcpkg/scripts/buildsystems/vcpkg.cmake GEN=ninja make debug
```

Release build:
```sh
VCPKG_TOOLCHAIN_PATH=`pwd`/vcpkg/scripts/buildsystems/vcpkg.cmake GEN=ninja make release
```

Build outputs:
- `./build/{debug,release}/duckdb` - DuckDB shell with extension pre-loaded
- `./build/{debug,release}/test/unittest` - Test runner
- `./build/{debug,release}/extension/crypto/crypto.duckdb_extension` - Loadable extension

### Testing

```sh
make test_debug
```

Runs SQL tests in `test/sql/*.test`.

### Running

```sh
./build/release/duckdb
```

## Supported Hash Algorithms

Defined in `src/crypto_hash.cpp:GetDigestMap()`:
- **blake3** - 32 bytes (vendored library, not OpenSSL)
- **blake2b-512** - 64 bytes
- **sha2-224, sha2-256, sha2-384, sha2-512** - SHA-2 family
- **sha3-224, sha3-256, sha3-384, sha3-512** - SHA-3 family
- **keccak224, keccak256, keccak384, keccak512** - mapped to SHA3 variants
- **md4, md5** - 16 bytes (deprecated)
- **sha1** - 20 bytes

## Key Implementation Details

### Algorithm Handling
- **BLAKE3**: Handled separately using vendored `blake3.h`, `LookupAlgorithm()` returns `nullptr`
- **OpenSSL algorithms**: Use EVP API via `GetDigestMap()` which returns lambda functions

### List Hashing
- Lists are hashed element-by-element in order
- VARCHAR/BLOB elements: `[8-byte length][content]` to prevent length extension attacks
- Fixed-length types: raw binary data only
- Helper functions: `HashListElementBlake3()` and `HashListElementEVP()`

### Aggregate Function
- `crypto_hash_agg()` uses `HashAggregateState` to maintain state across rows
- Requires ORDER BY clause - enforced in `Combine()` by throwing on parallel aggregation
- Produces identical output to `crypto_hash()` on an equivalent ordered list

### Encryption/Decryption
- Uses OpenSSL's EVP cipher API with AEAD support (GCM mode)
- Ciphertext format: `[IV][encrypted data][auth tag]`
- `EvpCipherContext` and `CipherText` classes in `crypto_enc.cpp` handle the OpenSSL operations

### Error Handling
- `InvalidInputException`: Invalid algorithm names, unsupported types, NULL list elements
- `InternalException`: OpenSSL operation failures

## Development Workflow

### Adding a New Hash Algorithm

1. Add to `GetDigestMap()` in `src/crypto_hash.cpp`
2. Map to appropriate `EVP_*()` function
3. Add test vectors to `test/sql/crypto.test`
4. Update README.md

### Adding a New Supported Data Type

1. Update `CryptoScalarHashFun()` in `src/crypto_extension.cpp` to handle the new type
2. For aggregate support, add `RegisterHashAggType<>()` call in `LoadInternal()`
3. Add test cases in `test/sql/crypto.test`
4. Update README.md

## Testing

SQL-based tests:
- `test/sql/crypto.test` - Main test suite for hash, HMAC, aggregate, and random bytes
- `test/sql/crypto_enc.test` - Encryption/decryption tests

## CI/CD

Uses DuckDB extension template CI system:
- Build configuration: `extension_config.cmake`
- CI tools: `extension-ci-tools/` (git submodule)
- Makefile includes: `extension-ci-tools/makefiles/duckdb_extension.Makefile`
