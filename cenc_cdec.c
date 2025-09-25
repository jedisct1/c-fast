#include "fast_internal.h"
#include <string.h>

void
fast_cenc(const fast_params_t *params, const sbox_pool_t *pool, const uint32_t *seq,
          const uint8_t *input, uint8_t *output, size_t length)
{
    if (!params || !pool || !input || !output || length != params->word_length) {
        return;
    }

    if (input != output) {
        memcpy(output, input, length);
    }

    for (uint32_t i = 0; i < params->num_layers; i++) {
        uint32_t sbox_index = seq ? seq[i] : (i % pool->count);
        fast_es_layer(params, pool, output, length, sbox_index);
    }
}

void
fast_cdec(const fast_params_t *params, const sbox_pool_t *pool, const uint32_t *seq,
          const uint8_t *input, uint8_t *output, size_t length)
{
    if (!params || !pool || !input || !output || length != params->word_length) {
        return;
    }

    if (input != output) {
        memcpy(output, input, length);
    }

    for (int i = params->num_layers - 1; i >= 0; i--) {
        uint32_t sbox_index = seq ? seq[i] : ((uint32_t) i % pool->count);
        fast_ds_layer(params, pool, output, length, sbox_index);
    }
}
