#include "fast.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

void print_array(const char *label, const uint8_t *data, size_t length) {
    printf("%s: ", label);
    for (size_t i = 0; i < length; i++) {
        printf("%3u ", data[i]);
    }
    printf("\n");
}

void test_single_layer() {
    printf("\n=== Testing Single Layer ES/DS ===\n");
    
    uint8_t key[FAST_AES_KEY_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    uint8_t nonce[FAST_AES_BLOCK_SIZE] = {0};
    
    prng_state_t prng;
    assert(prng_init(&prng, key, nonce) == 0);
    
    sbox_pool_t pool;
    assert(generate_sbox_pool(&pool, 256, 10, &prng) == 0);
    
    fast_params_t params = {
        .radix = 10,
        .word_length = 8,
        .sbox_count = 256,
        .num_layers = 1,
        .branch_dist1 = 3,
        .branch_dist2 = 3
    };
    
    uint8_t original[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t data[8];
    uint8_t recovered[8];
    
    memcpy(data, original, 8);
    print_array("Original  ", original, 8);
    
    // Apply ES layer
    fast_es_layer(&params, &pool, data, 8, 0);
    print_array("After ES  ", data, 8);
    
    memcpy(recovered, data, 8);
    
    // Apply DS layer
    fast_ds_layer(&params, &pool, recovered, 8, 0);
    print_array("After DS  ", recovered, 8);
    
    if (memcmp(original, recovered, 8) == 0) {
        printf("✓ Single layer correctly inverted\n");
    } else {
        printf("✗ Single layer inversion failed\n");
    }
    
    free_sbox_pool(&pool);
    prng_cleanup(&prng);
}

void test_multiple_layers() {
    printf("\n=== Testing Multiple Layers ===\n");
    
    uint8_t key[FAST_AES_KEY_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    
    fast_params_t params = {
        .radix = 10,
        .word_length = 8,
        .sbox_count = 256,
        .num_layers = 3,
        .branch_dist1 = 3,
        .branch_dist2 = 3
    };
    
    fast_context_t ctx;
    assert(fast_init(&ctx, &params, key) == 0);
    
    uint8_t plaintext[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t ciphertext[8];
    uint8_t recovered[8];
    
    print_array("Plaintext ", plaintext, 8);
    
    // Manually apply CEnc
    memcpy(ciphertext, plaintext, 8);
    for (uint32_t i = 0; i < params.num_layers; i++) {
        printf("  Layer %u: ", i);
        fast_es_layer(&params, ctx.sbox_pool, ciphertext, 8, i);
        print_array("", ciphertext, 8);
    }
    
    print_array("Ciphertext", ciphertext, 8);
    
    // Manually apply CDec
    memcpy(recovered, ciphertext, 8);
    for (int i = params.num_layers - 1; i >= 0; i--) {
        printf("  Layer %d: ", i);
        fast_ds_layer(&params, ctx.sbox_pool, recovered, 8, (uint32_t)i);
        print_array("", recovered, 8);
    }
    
    print_array("Recovered ", recovered, 8);
    
    if (memcmp(plaintext, recovered, 8) == 0) {
        printf("✓ Multiple layers correctly inverted\n");
    } else {
        printf("✗ Multiple layers inversion failed\n");
    }
    
    fast_cleanup(&ctx);
}

int main() {
    printf("FAST Debug Test Suite\n");
    printf("=====================\n");
    
    test_single_layer();
    test_multiple_layers();
    
    return 0;
}