# C-FAST

A C implementation of the FAST (Format-preserving, Additive, Symmetric Translation) cipher.

## Overview

FAST is a format-preserving encryption scheme designed for arbitrary radix values and word lengths. This implementation provides a complete cryptographic library for performing format-preserving encryption while maintaining the structure and format of input data.

## Features

- Format-preserving encryption for arbitrary radix (4-256)
- Configurable word lengths and security parameters
- S-box pool generation using AES-based PRNG
- Multi-layer SPN (Substitution-Permutation Network) structure
- Comprehensive test suite with edge case handling
- Tweak support for domain separation
- HMAC-SHA256 based PRF for key derivation

## Requirements

- GCC or compatible C compiler
- OpenSSL 3.x
- Make build system

On macOS with Homebrew:

```bash
brew install openssl@3
```

## Building

Build the library and test suite:

```bash
make
```

Run tests:

```bash
make test             # Run basic test suite
make test_edge_cases  # Build edge case tests (run with ./test_edge_cases)
make diffusion        # Run diffusion tests
make benchmark        # Run performance benchmarks
```

Clean build artifacts:

```bash
make clean
```

## Usage

### Basic Example

```c
#include "fast.h"

// Initialize parameters
fast_params_t params;
calculate_recommended_params(&params, 10, 16);  // radix=10, word_length=16

// Create context with key
uint8_t key[16] = { /* 128-bit key */ };
fast_context_t *ctx;
fast_init(&ctx, &params, key);

// Encrypt data
uint8_t plaintext[16] = { /* input data */ };
uint8_t ciphertext[16];
uint8_t tweak[8] = { 0, 1, 2, 3, 4, 5, 6, 7 };
fast_encrypt(ctx, tweak, sizeof(tweak), plaintext, ciphertext, 16);

// Decrypt data
uint8_t decrypted[16];
fast_decrypt(ctx, tweak, sizeof(tweak), ciphertext, decrypted, 16);

// Cleanup
fast_cleanup(ctx);
```

### Configuration Parameters

- `radix`: Base of the numeral system (4-256)
- `word_length`: Length of plaintext/ciphertext words
- `sbox_count`: Number of S-boxes in the pool (default: 256)
- `num_layers`: Number of SPN layers for security
- `branch_dist1`, `branch_dist2`: Branch distances for diffusion
- `security_level`: Target classical security in bits (default 128)

## References

- [FAST Paper](https://eprint.iacr.org/2021/1171.pdf)
- [The Next Generation of Performant Data Protection: a New FPE Algorithm](https://insights.comforte.com/the-next-generation-of-performant-data-protection-a-new-fpe-algorithm)
- [Format-Preserving Encryption](https://en.wikipedia.org/wiki/Format-preserving_encryption)
