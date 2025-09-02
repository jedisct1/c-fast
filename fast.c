#include "fast.h"
#include "fast_internal.h"
#include <math.h>
#include <stdlib.h>
#include <string.h>

// Define the full context structure
struct fast_context {
    fast_params_t params;
    sbox_pool_t  *sbox_pool;
    uint8_t       key[FAST_AES_KEY_SIZE];
    prng_state_t  prng;
};

int
calculate_recommended_params(fast_params_t *params, uint32_t radix, uint32_t word_length)
{
    if (!params || radix < 4 || word_length < 2) {
        return -1;
    }

    params->radix       = radix;
    params->word_length = word_length;
    params->sbox_count  = FAST_SBOX_POOL_SIZE;

    // Set branch distances according to FAST paper formulas
    // w = min(floor(sqrt(ℓ)), ℓ - 2)
    uint32_t sqrt_ell    = (uint32_t) floor(sqrt(word_length));
    params->branch_dist1 = (sqrt_ell < word_length - 2) ? sqrt_ell : (word_length - 2);

    // w' = max(1, w - 1)
    params->branch_dist2 = (params->branch_dist1 > 1) ? (params->branch_dist1 - 1) : 1;

    // Set number of layers according to FAST paper for 128-bit security
    // Formula: n = ℓ × 2 × max(s/√(ℓ log2 m), s√ℓ/ln(a-1), s√ℓ/log2(a-1))
    uint32_t s = 128; // Security parameter
    uint32_t m = FAST_SBOX_POOL_SIZE;

    double term1 = s / sqrt(word_length * log2(m));
    double term2 = s * sqrt(word_length) / log(radix - 1);
    double term3 = s * sqrt(word_length) / log2(radix - 1);

    double max_term = term1;
    if (term2 > max_term)
        max_term = term2;
    if (term3 > max_term)
        max_term = term3;

    params->num_layers = (uint32_t) ceil(word_length * 2 * max_term);

    // Ensure n is a multiple of ℓ as required by the paper
    uint32_t rounds    = (params->num_layers + word_length - 1) / word_length;
    params->num_layers = rounds * word_length;

    if (params->branch_dist1 >= word_length) {
        params->branch_dist1 = word_length - 1;
    }
    if (params->branch_dist2 >= word_length) {
        params->branch_dist2 = word_length - 1;
    }

    return 0;
}

int
fast_init(fast_context_t **ctx, const fast_params_t *params, const uint8_t *key)
{
    if (!ctx || !params || !key) {
        return -1;
    }

    *ctx = malloc(sizeof(fast_context_t));
    if (!*ctx) {
        return -1;
    }

    if (params->radix < 4 || params->radix > FAST_MAX_RADIX) {
        return -1;
    }

    if (params->word_length < 2) {
        return -1;
    }

    memcpy(&(*ctx)->params, params, sizeof(fast_params_t));
    memcpy((*ctx)->key, key, FAST_AES_KEY_SIZE);

    uint8_t sbox_seed[FAST_AES_KEY_SIZE];
    uint8_t sbox_label[] = "SBOX_GENERATION";
    if (prf_derive_key(key, sbox_label, sizeof(sbox_label) - 1, sbox_seed, FAST_AES_KEY_SIZE) !=
        0) {
        return -1;
    }

    uint8_t nonce[FAST_AES_BLOCK_SIZE] = { 0 };
    if (prng_init(&(*ctx)->prng, sbox_seed, nonce) != 0) {
        free(*ctx);
        *ctx = NULL;
        return -1;
    }

    (*ctx)->sbox_pool = malloc(sizeof(sbox_pool_t));
    if (!(*ctx)->sbox_pool) {
        prng_cleanup(&(*ctx)->prng);
        free(*ctx);
        *ctx = NULL;
        return -1;
    }

    if (generate_sbox_pool((*ctx)->sbox_pool, params->sbox_count, params->radix, &(*ctx)->prng) !=
        0) {
        free((*ctx)->sbox_pool);
        prng_cleanup(&(*ctx)->prng);
        free(*ctx);
        *ctx = NULL;
        return -1;
    }

    memset(sbox_seed, 0, FAST_AES_KEY_SIZE);

    return 0;
}

void
fast_cleanup(fast_context_t *ctx)
{
    if (!ctx) {
        return;
    }

    if (ctx->sbox_pool) {
        free_sbox_pool(ctx->sbox_pool);
        free(ctx->sbox_pool);
        ctx->sbox_pool = NULL;
    }

    prng_cleanup(&ctx->prng);
    memset(ctx->key, 0, FAST_AES_KEY_SIZE);
    memset(&ctx->params, 0, sizeof(fast_params_t));
    free(ctx);
}

int
fast_encrypt(fast_context_t *ctx, const uint8_t *plaintext, uint8_t *ciphertext, size_t length)
{
    if (!ctx || !plaintext || !ciphertext) {
        return -1;
    }

    if (length != ctx->params.word_length) {
        return -1;
    }

    uint8_t *working = malloc(length);
    if (!working) {
        return -1;
    }

    for (size_t i = 0; i < length; i++) {
        if (plaintext[i] >= ctx->params.radix) {
            free(working);
            return -1;
        }
        working[i] = plaintext[i];
    }

    fast_cenc(&ctx->params, ctx->sbox_pool, working, ciphertext, length);

    free(working);
    return 0;
}

int
fast_decrypt(fast_context_t *ctx, const uint8_t *ciphertext, uint8_t *plaintext, size_t length)
{
    if (!ctx || !ciphertext || !plaintext) {
        return -1;
    }

    if (length != ctx->params.word_length) {
        return -1;
    }

    uint8_t *working = malloc(length);
    if (!working) {
        return -1;
    }

    for (size_t i = 0; i < length; i++) {
        if (ciphertext[i] >= ctx->params.radix) {
            free(working);
            return -1;
        }
        working[i] = ciphertext[i];
    }

    fast_cdec(&ctx->params, ctx->sbox_pool, working, plaintext, length);

    free(working);
    return 0;
}