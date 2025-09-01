#include "fast_internal.h"
#include <string.h>

void
fast_cenc(const fast_params_t *params, const sbox_pool_t *pool, const uint8_t *input,
          uint8_t *output, size_t length)
{
    if (!params || !pool || !input || !output || length != params->word_length) {
        return;
    }

    memcpy(output, input, length);

    for (uint32_t i = 0; i < params->num_layers; i++) {
        fast_es_layer(params, pool, output, length, i);
    }
}

void
fast_cdec(const fast_params_t *params, const sbox_pool_t *pool, const uint8_t *input,
          uint8_t *output, size_t length)
{
    if (!params || !pool || !input || !output || length != params->word_length) {
        return;
    }

    memcpy(output, input, length);

    for (int i = params->num_layers - 1; i >= 0; i--) {
        fast_ds_layer(params, pool, output, length, (uint32_t) i);
    }
}