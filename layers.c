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

static inline uint8_t
add_mod256(uint8_t a, uint8_t b)
{
    return (uint8_t) (a + b);
}

static inline uint8_t
sub_mod256(uint8_t a, uint8_t b)
{
    return (uint8_t) (a - b);
}

static inline void
fast_es_layer_radix256(uint8_t *data, uint32_t ell, uint32_t w, uint32_t wp, const sbox_t *sbox)
{
    if (!sbox->perm) {
        return;
    }

    const uint8_t *perm = sbox->perm;

    uint8_t sum1 = perm[add_mod256(data[0], data[ell - wp])];

    uint8_t new_last;
    if (w > 0) {
        uint8_t intermediate = perm[sub_mod256(sum1, data[w])];
        new_last             = intermediate;
    } else {
        uint8_t double_image = perm[sum1];
        new_last             = double_image;
    }

    memmove(data, data + 1, (ell - 1) * sizeof(uint8_t));
    data[ell - 1] = new_last;
}

static inline void
fast_ds_layer_radix256(uint8_t *data, uint32_t ell, uint32_t w, uint32_t wp, const sbox_t *sbox)
{
    if (!sbox->inv) {
        return;
    }

    const uint8_t *inv = sbox->inv;

    uint8_t x_last = inv[data[ell - 1]];

    uint8_t intermediate;
    if (w > 0) {
        uint8_t wrapped = add_mod256(x_last, data[w - 1]);
        intermediate    = inv[wrapped];
    } else {
        intermediate = inv[inv[x_last]];
    }

    uint8_t new_first = sub_mod256(intermediate, data[ell - wp - 1]);

    memmove(data + 1, data, (ell - 1) * sizeof(uint8_t));
    data[0] = new_first;
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

    if (radix == 256 && sbox->radix == 256) {
        fast_es_layer_radix256(data, ell, w, wp, sbox);
        return;
    }

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

    if (radix == 256 && sbox->radix == 256) {
        fast_ds_layer_radix256(data, ell, w, wp, sbox);
        return;
    }

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
