#include "fast_internal.h"
#include <stdlib.h>
#include <string.h>

void
fast_es_layer(const fast_params_t *params, const sbox_pool_t *pool, uint8_t *data, size_t length,
              uint32_t layer_idx)
{
    if (!params || !pool || !data || length != params->word_length) {
        return;
    }

    uint32_t w     = params->branch_dist1;
    uint32_t wp    = params->branch_dist2;
    uint32_t ell   = params->word_length;
    uint32_t radix = params->radix;

    // Get the S-box for this layer
    uint32_t      sbox_idx = layer_idx % pool->count;
    const sbox_t *sbox     = &pool->sboxes[sbox_idx];

    // Save original data
    uint8_t *temp = malloc(length * sizeof(uint8_t));
    if (!temp) {
        return;
    }
    memcpy(temp, data, length);

    // Apply ES transformation: (x₁, ..., xₗ₋₁, Sᵢ(Sᵢ(x₀ + xₗ₋w') - xw))

    // Calculate the new last element
    uint8_t x0             = temp[0];
    uint8_t x_ell_minus_wp = temp[ell - wp];

    // First addition: x₀ + xₗ₋w'
    uint8_t sum1 = (x0 + x_ell_minus_wp) % radix;

    // Apply first S-box: Sᵢ(x₀ + xₗ₋w')
    apply_sbox(sbox, &sum1);

    uint8_t new_last;
    if (w > 0) {
        // Subtract xw: Sᵢ(x₀ + xₗ₋w') - xw
        uint8_t xw           = temp[w];
        uint8_t intermediate = (sum1 + radix - xw) % radix;

        // Apply second S-box: Sᵢ(Sᵢ(x₀ + xₗ₋w') - xw)
        apply_sbox(sbox, &intermediate);
        new_last = intermediate;
    } else {
        // w = 0 case: apply S-box twice: Sᵢ(Sᵢ(x₀ + xₗ₋w'))
        apply_sbox(sbox, &sum1); // Second application
        new_last = sum1;
    }

    // Perform the circular shift: (x₁, ..., xₗ₋₁, new_value)
    for (uint32_t i = 0; i < ell - 1; i++) {
        data[i] = temp[i + 1];
    }
    data[ell - 1] = new_last;

    free(temp);
}

void
fast_ds_layer(const fast_params_t *params, const sbox_pool_t *pool, uint8_t *data, size_t length,
              uint32_t layer_idx)
{
    if (!params || !pool || !data || length != params->word_length) {
        return;
    }

    uint32_t w     = params->branch_dist1;
    uint32_t wp    = params->branch_dist2;
    uint32_t ell   = params->word_length;
    uint32_t radix = params->radix;

    // Get the S-box for this layer
    uint32_t      sbox_idx = layer_idx % pool->count;
    const sbox_t *sbox     = &pool->sboxes[sbox_idx];

    // Save original data
    uint8_t *temp = malloc(length * sizeof(uint8_t));
    if (!temp) {
        return;
    }
    memcpy(temp, data, length);

    // Apply DS transformation: (S⁻¹ᵢ(S⁻¹ᵢ(xₗ₋₁) + xw₋₁) - xₗ₋w'₋₁, x₀, ..., xₗ₋₂)

    // Start with the last element
    uint8_t x_last = temp[ell - 1];

    // Apply inverse S-box once: S⁻¹ᵢ(xₗ₋₁)
    apply_inverse_sbox(sbox, &x_last);

    uint8_t intermediate;
    if (w > 0) {
        // Add xw₋₁: S⁻¹ᵢ(xₗ₋₁) + xw₋₁
        uint8_t xw_minus_1 = temp[w - 1];
        intermediate       = (x_last + xw_minus_1) % radix;

        // Apply inverse S-box again: S⁻¹ᵢ(S⁻¹ᵢ(xₗ₋₁) + xw₋₁)
        apply_inverse_sbox(sbox, &intermediate);
    } else {
        // w = 0 case: apply inverse S-box twice: S⁻¹ᵢ(S⁻¹ᵢ(xₗ₋₁))
        intermediate = x_last;
        apply_inverse_sbox(sbox, &intermediate); // Second application
    }

    // Subtract xₗ₋w'₋₁
    uint8_t x_ell_minus_wp_minus_1 = temp[ell - wp - 1];
    uint8_t new_first              = (intermediate + radix - x_ell_minus_wp_minus_1) % radix;

    // Perform the circular shift: (new_value, x₀, ..., xₗ₋₂)
    data[0] = new_first;
    for (uint32_t i = 1; i < ell; i++) {
        data[i] = temp[i - 1];
    }

    free(temp);
}