#include "fast.h"
#include <string.h>
#include <openssl/evp.h>
#include <openssl/cmac.h>

int prf_derive_key(const uint8_t *master_key, const uint8_t *input, size_t input_len,
                   uint8_t *output, size_t output_len) {
    if (!master_key || !input || !output || output_len == 0) {
        return -1;
    }
    
    size_t bytes_generated = 0;
    uint32_t counter = 0;
    
    while (bytes_generated < output_len) {
        size_t cmac_len = FAST_AES_BLOCK_SIZE;
        uint8_t cmac_output[FAST_AES_BLOCK_SIZE];
        
        size_t total_input_len = 4 + input_len;
        uint8_t *cmac_input = malloc(total_input_len);
        if (!cmac_input) {
            return -1;
        }
        
        cmac_input[0] = (counter >> 24) & 0xFF;
        cmac_input[1] = (counter >> 16) & 0xFF;
        cmac_input[2] = (counter >> 8) & 0xFF;
        cmac_input[3] = counter & 0xFF;
        memcpy(cmac_input + 4, input, input_len);
        
        CMAC_CTX *ctx = CMAC_CTX_new();
        if (!ctx) {
            free(cmac_input);
            return -1;
        }
        
        if (CMAC_Init(ctx, master_key, FAST_AES_KEY_SIZE, EVP_aes_128_cbc(), NULL) != 1) {
            CMAC_CTX_free(ctx);
            free(cmac_input);
            return -1;
        }
        
        if (CMAC_Update(ctx, cmac_input, total_input_len) != 1) {
            CMAC_CTX_free(ctx);
            free(cmac_input);
            return -1;
        }
        
        if (CMAC_Final(ctx, cmac_output, &cmac_len) != 1) {
            CMAC_CTX_free(ctx);
            free(cmac_input);
            return -1;
        }
        
        CMAC_CTX_free(ctx);
        free(cmac_input);
        
        size_t to_copy = (output_len - bytes_generated < cmac_len) ?
                        (output_len - bytes_generated) : cmac_len;
        memcpy(output + bytes_generated, cmac_output, to_copy);
        bytes_generated += to_copy;
        counter++;
    }
    
    return 0;
}