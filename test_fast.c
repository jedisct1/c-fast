#include "fast.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

void print_array(const char *label, const uint8_t *data, size_t length) {
    printf("%s: ", label);
    for (size_t i = 0; i < length; i++) {
        printf("%3u ", data[i]);
    }
    printf("\n");
}

void test_sbox_generation() {
    printf("\n=== Testing S-box Generation ===\n");
    
    uint8_t key[FAST_AES_KEY_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    uint8_t nonce[FAST_AES_BLOCK_SIZE] = {0};
    
    prng_state_t prng;
    assert(prng_init(&prng, key, nonce) == 0);
    
    sbox_t sbox;
    generate_sbox(&sbox, 10, &prng);
    
    printf("Generated S-box (radix 10): ");
    for (uint32_t i = 0; i < 10; i++) {
        printf("%u ", sbox.perm[i]);
    }
    printf("\n");
    
    uint8_t seen[10] = {0};
    for (uint32_t i = 0; i < 10; i++) {
        assert(sbox.perm[i] < 10);
        assert(seen[sbox.perm[i]] == 0);
        seen[sbox.perm[i]] = 1;
    }
    
    printf("S-box validation passed: all values are unique and in range\n");
    
    free(sbox.perm);
    prng_cleanup(&prng);
}

void test_encrypt_decrypt() {
    printf("\n=== Testing Encryption and Decryption ===\n");
    
    uint8_t key[FAST_AES_KEY_SIZE] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    fast_params_t params;
    uint32_t radix = 10;
    uint32_t word_length = 16;
    
    assert(calculate_recommended_params(&params, radix, word_length) == 0);
    
    printf("Parameters:\n");
    printf("  Radix: %u\n", params.radix);
    printf("  Word length: %u\n", params.word_length);
    printf("  Number of layers: %u\n", params.num_layers);
    printf("  Branch distance w: %u\n", params.branch_dist1);
    printf("  Branch distance w': %u\n", params.branch_dist2);
    printf("  S-box pool size: %u\n", params.sbox_count);
    
    fast_context_t ctx;
    assert(fast_init(&ctx, &params, key) == 0);
    
    uint8_t plaintext[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6};
    uint8_t ciphertext[16];
    uint8_t recovered[16];
    
    print_array("Plaintext ", plaintext, word_length);
    
    assert(fast_encrypt(&ctx, plaintext, ciphertext, word_length) == 0);
    print_array("Ciphertext", ciphertext, word_length);
    
    assert(fast_decrypt(&ctx, ciphertext, recovered, word_length) == 0);
    print_array("Recovered ", recovered, word_length);
    
    assert(memcmp(plaintext, recovered, word_length) == 0);
    printf("✓ Decryption correctly recovered the plaintext\n");
    
    fast_cleanup(&ctx);
}

void test_different_inputs() {
    printf("\n=== Testing Different Inputs ===\n");
    
    uint8_t key[FAST_AES_KEY_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    
    fast_params_t params;
    assert(calculate_recommended_params(&params, 16, 8) == 0);
    
    fast_context_t ctx;
    assert(fast_init(&ctx, &params, key) == 0);
    
    uint8_t test_cases[][8] = {
        {0, 0, 0, 0, 0, 0, 0, 0},
        {15, 15, 15, 15, 15, 15, 15, 15},
        {0, 1, 2, 3, 4, 5, 6, 7},
        {7, 6, 5, 4, 3, 2, 1, 0},
        {10, 11, 12, 13, 14, 15, 0, 1}
    };
    
    for (int i = 0; i < 5; i++) {
        uint8_t ciphertext[8];
        uint8_t recovered[8];
        
        printf("\nTest case %d:\n", i + 1);
        print_array("  Input    ", test_cases[i], 8);
        
        assert(fast_encrypt(&ctx, test_cases[i], ciphertext, 8) == 0);
        print_array("  Encrypted", ciphertext, 8);
        
        assert(fast_decrypt(&ctx, ciphertext, recovered, 8) == 0);
        print_array("  Decrypted", recovered, 8);
        
        assert(memcmp(test_cases[i], recovered, 8) == 0);
        printf("  ✓ Passed\n");
    }
    
    fast_cleanup(&ctx);
}

void test_prng_determinism() {
    printf("\n=== Testing PRNG Determinism ===\n");
    
    uint8_t key[FAST_AES_KEY_SIZE] = {
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00
    };
    uint8_t nonce[FAST_AES_BLOCK_SIZE] = {0};
    
    prng_state_t prng1, prng2;
    assert(prng_init(&prng1, key, nonce) == 0);
    assert(prng_init(&prng2, key, nonce) == 0);
    
    uint8_t bytes1[32], bytes2[32];
    prng_get_bytes(&prng1, bytes1, 32);
    prng_get_bytes(&prng2, bytes2, 32);
    
    assert(memcmp(bytes1, bytes2, 32) == 0);
    printf("✓ PRNG produces deterministic output with same key/nonce\n");
    
    uint32_t rand1[10], rand2[10];
    for (int i = 0; i < 10; i++) {
        rand1[i] = prng_get_uint32(&prng1, 100);
        rand2[i] = prng_get_uint32(&prng2, 100);
        assert(rand1[i] == rand2[i]);
        assert(rand1[i] < 100);
    }
    printf("✓ PRNG uint32 generation is deterministic and bounded\n");
    
    prng_cleanup(&prng1);
    prng_cleanup(&prng2);
}

int main() {
    printf("FAST Implementation Test Suite\n");
    printf("==============================\n");
    
    test_sbox_generation();
    test_prng_determinism();
    test_encrypt_decrypt();
    test_different_inputs();
    
    printf("\n==============================\n");
    printf("All tests passed successfully!\n");
    
    return 0;
}