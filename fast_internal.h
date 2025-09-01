#ifndef FAST_INTERNAL_H
#define FAST_INTERNAL_H

#include "fast.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Internal data structures

typedef struct {
    uint8_t *perm; // Permutation array of size radix
    uint32_t radix; // Size of the permutation
} sbox_t;

typedef struct {
    sbox_t  *sboxes; // Array of S-boxes
    uint32_t count; // Number of S-boxes
    uint32_t radix; // Radix for all S-boxes
} sbox_pool_t;

typedef struct {
    uint8_t key[FAST_AES_KEY_SIZE];
    uint8_t counter[FAST_AES_BLOCK_SIZE];
    uint8_t buffer[FAST_AES_BLOCK_SIZE];
    size_t  buffer_pos;
} prng_state_t;

// Internal context structure
typedef struct {
    fast_params_t params;
    sbox_pool_t  *sbox_pool;
    uint8_t       key[FAST_AES_KEY_SIZE];
    prng_state_t  prng;
} fast_context_internal_t;

// S-box functions
void generate_sbox(sbox_t *sbox, uint32_t radix, prng_state_t *prng);
int  generate_sbox_pool(sbox_pool_t *pool, uint32_t count, uint32_t radix, prng_state_t *prng);
void free_sbox_pool(sbox_pool_t *pool);
void apply_sbox(const sbox_t *sbox, uint8_t *data);
void apply_inverse_sbox(const sbox_t *sbox, uint8_t *data);

// Layer functions
void fast_es_layer(const fast_params_t *params, const sbox_pool_t *pool, uint8_t *data,
                   size_t length, uint32_t layer_idx);
void fast_ds_layer(const fast_params_t *params, const sbox_pool_t *pool, uint8_t *data,
                   size_t length, uint32_t layer_idx);
void fast_es_layer_correct(const fast_params_t *params, const sbox_pool_t *pool, uint8_t *data,
                           size_t length, uint32_t layer_idx);
void fast_ds_layer_correct(const fast_params_t *params, const sbox_pool_t *pool, uint8_t *data,
                           size_t length, uint32_t layer_idx);

// Component encryption/decryption
void fast_cenc(const fast_params_t *params, const sbox_pool_t *pool, const uint8_t *input,
               uint8_t *output, size_t length);
void fast_cdec(const fast_params_t *params, const sbox_pool_t *pool, const uint8_t *input,
               uint8_t *output, size_t length);

// PRNG functions
int      prng_init(prng_state_t *prng, const uint8_t *key, const uint8_t *nonce);
void     prng_get_bytes(prng_state_t *prng, uint8_t *output, size_t length);
uint32_t prng_get_uint32(prng_state_t *prng, uint32_t max);
void     prng_cleanup(prng_state_t *prng);

// PRF functions
int prf_derive_key(const uint8_t *master_key, const uint8_t *input, size_t input_len,
                   uint8_t *output, size_t output_len);

#endif // FAST_INTERNAL_H