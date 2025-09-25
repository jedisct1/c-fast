#include "fast_internal.h"
#include <stdlib.h>
#include <string.h>

static int
allocate_sbox_arrays(sbox_t *sbox, uint32_t radix)
{
    sbox->perm = malloc(radix * sizeof(uint8_t));
    if (!sbox->perm) {
        return -1;
    }

    sbox->inv = malloc(radix * sizeof(uint8_t));
    if (!sbox->inv) {
        free(sbox->perm);
        sbox->perm = NULL;
        return -1;
    }

    sbox->radix = radix;
    return 0;
}

int
generate_sbox(sbox_t *sbox, uint32_t radix, prng_state_t *prng)
{
    if (!sbox || radix == 0 || radix > FAST_MAX_RADIX || !prng) {
        return -1;
    }

    if (allocate_sbox_arrays(sbox, radix) != 0) {
        return -1;
    }

    for (uint32_t i = 0; i < radix; i++) {
        sbox->perm[i] = (uint8_t) i;
    }

    for (uint32_t i = radix; i > 1; i--) {
        uint32_t j        = prng_uniform(prng, i);
        uint8_t  temp     = sbox->perm[i - 1];
        sbox->perm[i - 1] = sbox->perm[j];
        sbox->perm[j]     = temp;
    }

    for (uint32_t i = 0; i < radix; i++) {
        sbox->inv[sbox->perm[i]] = (uint8_t) i;
    }

    return 0;
}

int
generate_sbox_pool(sbox_pool_t *pool, uint32_t count, uint32_t radix, prng_state_t *prng)
{
    if (!pool || count == 0 || radix < 4 || radix > FAST_MAX_RADIX || !prng) {
        return -1;
    }

    pool->sboxes = calloc(count, sizeof(sbox_t));
    if (!pool->sboxes) {
        return -1;
    }

    pool->count = count;
    pool->radix = radix;

    for (uint32_t i = 0; i < count; i++) {
        if (generate_sbox(&pool->sboxes[i], radix, prng) != 0) {
            for (uint32_t j = 0; j < i; j++) {
                free(pool->sboxes[j].perm);
                free(pool->sboxes[j].inv);
            }
            free(pool->sboxes);
            pool->sboxes = NULL;
            return -1;
        }
    }

    return 0;
}

void
free_sbox_pool(sbox_pool_t *pool)
{
    if (!pool || !pool->sboxes) {
        return;
    }

    for (uint32_t i = 0; i < pool->count; i++) {
        if (pool->sboxes[i].perm) {
            free(pool->sboxes[i].perm);
        }
        if (pool->sboxes[i].inv) {
            free(pool->sboxes[i].inv);
        }
    }

    free(pool->sboxes);
    pool->sboxes = NULL;
    pool->count  = 0;
}

void
apply_sbox(const sbox_t *sbox, uint8_t *data)
{
    if (!sbox || !sbox->perm || !data) {
        return;
    }

    uint32_t value = *data;
    if (value < sbox->radix) {
        *data = sbox->perm[value];
    }
}

void
apply_inverse_sbox(const sbox_t *sbox, uint8_t *data)
{
    if (!sbox || !sbox->inv || !data) {
        return;
    }

    uint32_t value = *data;
    if (value < sbox->radix) {
        *data = sbox->inv[value];
    }
}
