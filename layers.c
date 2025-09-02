#include "fast_internal.h"
#include <stdlib.h>
#include <string.h>

static inline uint8_t
mod_add(uint32_t a, uint32_t b, uint32_t radix)
{
    return (uint8_t) ((a + b) % radix);
}

static inline uint8_t
mod_sub(uint32_t a, uint32_t b, uint32_t radix)
{
    return (uint8_t) ((a + radix - (b % radix)) % radix);
}

void
fast_es_layer(const fast_params_t *params, const sbox_pool_t *pool, uint8_t *data, size_t length,
              uint32_t sbox_index)
{
    if (!params || !pool || !data || length != params->word_length) {
        return;
    }

    uint32_t w     = params->branch_dist1;
    uint32_t wp    = params->branch_dist2;
    uint32_t ell   = params->word_length;
    uint32_t radix = params->radix;

    if (!pool->sboxes || sbox_index >= pool->count) {
        return;
    }
    const sbox_t *sbox = &pool->sboxes[sbox_index];

    uint8_t sum1 = mod_add(data[0], data[ell - wp], radix);
    apply_sbox(sbox, &sum1);

    uint8_t new_last;
    if (w > 0) {
        uint8_t intermediate = mod_sub(sum1, data[w], radix);
        apply_sbox(sbox, &intermediate);
        new_last = intermediate;
    } else {
        uint8_t double_image = sum1;
        apply_sbox(sbox, &double_image);
        new_last = double_image;
    }

    memmove(data, data + 1, (ell - 1) * sizeof(uint8_t));
    data[ell - 1] = new_last;
}

void
fast_ds_layer(const fast_params_t *params, const sbox_pool_t *pool, uint8_t *data, size_t length,
              uint32_t sbox_index)
{
    if (!params || !pool || !data || length != params->word_length) {
        return;
    }

    uint32_t w     = params->branch_dist1;
    uint32_t wp    = params->branch_dist2;
    uint32_t ell   = params->word_length;
    uint32_t radix = params->radix;

    if (!pool->sboxes || sbox_index >= pool->count) {
        return;
    }
    const sbox_t *sbox = &pool->sboxes[sbox_index];

    uint8_t x_last = data[ell - 1];
    apply_inverse_sbox(sbox, &x_last);

    uint8_t intermediate;
    if (w > 0) {
        intermediate = mod_add(x_last, data[w - 1], radix);
        apply_inverse_sbox(sbox, &intermediate);
    } else {
        apply_inverse_sbox(sbox, &x_last);
        intermediate = x_last;
    }

    uint8_t new_first = mod_sub(intermediate, data[ell - wp - 1], radix);

    memmove(data + 1, data, (ell - 1) * sizeof(uint8_t));
    data[0] = new_first;
}
