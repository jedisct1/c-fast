#include "fast_internal.h"
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <string.h>

int
prf_derive_key(const uint8_t *master_key, const uint8_t *input, size_t input_len, uint8_t *output,
               size_t output_len)
{
    if (!master_key || !input || !output || output_len == 0) {
        return -1;
    }

    size_t   bytes_generated = 0;
    uint32_t counter         = 0;

    // Create the MAC context once
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
    if (!mac) {
        return -1;
    }

    while (bytes_generated < output_len) {
        size_t  cmac_len = FAST_AES_BLOCK_SIZE;
        uint8_t cmac_output[FAST_AES_BLOCK_SIZE];

        // Prepare input: counter || input
        size_t   total_input_len = 4 + input_len;
        uint8_t *cmac_input      = malloc(total_input_len);
        if (!cmac_input) {
            EVP_MAC_free(mac);
            return -1;
        }

        // Big-endian counter
        cmac_input[0] = (counter >> 24) & 0xFF;
        cmac_input[1] = (counter >> 16) & 0xFF;
        cmac_input[2] = (counter >> 8) & 0xFF;
        cmac_input[3] = counter & 0xFF;
        memcpy(cmac_input + 4, input, input_len);

        // Create MAC context
        EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
        if (!ctx) {
            free(cmac_input);
            EVP_MAC_free(mac);
            return -1;
        }

        // Set up parameters for CMAC with AES-128-CBC
        OSSL_PARAM params[] = { OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER,
                                                                 "AES-128-CBC", 0),
                                OSSL_PARAM_construct_end() };

        // Initialize with key
        if (EVP_MAC_init(ctx, master_key, FAST_AES_KEY_SIZE, params) != 1) {
            EVP_MAC_CTX_free(ctx);
            free(cmac_input);
            EVP_MAC_free(mac);
            return -1;
        }

        // Update with data
        if (EVP_MAC_update(ctx, cmac_input, total_input_len) != 1) {
            EVP_MAC_CTX_free(ctx);
            free(cmac_input);
            EVP_MAC_free(mac);
            return -1;
        }

        // Finalize and get output
        if (EVP_MAC_final(ctx, cmac_output, &cmac_len, sizeof(cmac_output)) != 1) {
            EVP_MAC_CTX_free(ctx);
            free(cmac_input);
            EVP_MAC_free(mac);
            return -1;
        }

        EVP_MAC_CTX_free(ctx);
        free(cmac_input);

        // Copy output
        size_t to_copy =
            (output_len - bytes_generated < cmac_len) ? (output_len - bytes_generated) : cmac_len;
        memcpy(output + bytes_generated, cmac_output, to_copy);
        bytes_generated += to_copy;
        counter++;
    }

    EVP_MAC_free(mac);
    return 0;
}
