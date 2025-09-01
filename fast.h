#ifndef FAST_H
#define FAST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Public constants
#define FAST_MAX_RADIX      256
#define FAST_SBOX_POOL_SIZE 256
#define FAST_AES_BLOCK_SIZE 16
#define FAST_AES_KEY_SIZE   16

// Public parameter structure
typedef struct {
    uint32_t radix; // a: radix (must be >= 4)
    uint32_t word_length; // ℓ: length of plaintext/ciphertext words
    uint32_t sbox_count; // m: number of S-boxes in pool (typically 256)
    uint32_t num_layers; // n: number of SPN layers
    uint32_t branch_dist1; // w: branch distance for first part
    uint32_t branch_dist2; // w': branch distance for second part
} fast_params_t;

// Opaque context structure for public API
typedef struct fast_context fast_context_t;

// Public API functions

// Initialize FAST context with given parameters
int fast_init(fast_context_t **ctx, const fast_params_t *params, const uint8_t *key);

// Clean up FAST context
void fast_cleanup(fast_context_t *ctx);

// Main encryption function
int fast_encrypt(fast_context_t *ctx, const uint8_t *plaintext, uint8_t *ciphertext, size_t length);

// Main decryption function
int fast_decrypt(fast_context_t *ctx, const uint8_t *ciphertext, uint8_t *plaintext, size_t length);

// Utility function to calculate recommended parameters
int calculate_recommended_params(fast_params_t *params, uint32_t radix, uint32_t word_length);

#endif // FAST_H