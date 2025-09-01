#include "fast_internal.h"
#include <stdlib.h>
#include <string.h>

void
generate_sbox(sbox_t *sbox, uint32_t radix, prng_state_t *prng)
{
    if (!sbox || radix == 0 || radix > FAST_MAX_RADIX || !prng) {
        return;
    }

    sbox->perm = malloc(radix * sizeof(uint8_t));
    if (!sbox->perm) {
        return;
    }

    sbox->radix = radix;

    for (uint32_t i = 0; i < radix; i++) {
        sbox->perm[i] = i;
    }

    for (uint32_t i = radix - 1; i > 0; i--) {
        uint32_t j    = prng_get_uint32(prng, i + 1);
        uint8_t  temp = sbox->perm[i];
        sbox->perm[i] = sbox->perm[j];
        sbox->perm[j] = temp;
    }
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
        generate_sbox(&pool->sboxes[i], radix, prng);
        if (!pool->sboxes[i].perm) {
            for (uint32_t j = 0; j < i; j++) {
                free(pool->sboxes[j].perm);
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

    if (*data < sbox->radix) {
        *data = sbox->perm[*data];
    }
}

void
apply_inverse_sbox(const sbox_t *sbox, uint8_t *data)
{
    if (!sbox || !sbox->perm || !data) {
        return;
    }

    if (*data < sbox->radix) {
        for (uint32_t i = 0; i < sbox->radix; i++) {
            if (sbox->perm[i] == *data) {
                *data = i;
                break;
            }
        }
    }
}