#include "fast.h"
#include "fast_internal.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t EDGE_TWEAK[]   = { 0x10, 0x20, 0x30, 0x40 };
static const size_t  EDGE_TWEAK_LEN = sizeof(EDGE_TWEAK);

void
test_w_zero_case()
{
    printf("\n=== Testing w=0 Edge Case ===\n");

    uint8_t key[FAST_AES_KEY_SIZE] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                                       0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 };

    fast_params_t params;
    params.radix        = 10;
    params.word_length  = 4; // Small to force w=0
    params.branch_dist1 = 0; // Force w=0
    params.branch_dist2 = 2; // w' = 2
    params.num_layers   = 8;
    params.sbox_count   = 256;

    fast_context_t *ctx;
    assert(fast_init(&ctx, &params, key) == 0);

    uint8_t plaintext[4] = { 1, 2, 3, 4 };
    uint8_t ciphertext[4];
    uint8_t recovered[4];

    printf("Testing with w=0, w'=2:\n");
    printf("  Plaintext:  %u %u %u %u\n", plaintext[0], plaintext[1], plaintext[2], plaintext[3]);

    assert(fast_encrypt(ctx, EDGE_TWEAK, EDGE_TWEAK_LEN, plaintext, ciphertext, 4) == 0);
    printf("  Ciphertext: %u %u %u %u\n", ciphertext[0], ciphertext[1], ciphertext[2],
           ciphertext[3]);

    assert(fast_decrypt(ctx, EDGE_TWEAK, EDGE_TWEAK_LEN, ciphertext, recovered, 4) == 0);
    printf("  Recovered:  %u %u %u %u\n", recovered[0], recovered[1], recovered[2], recovered[3]);

    if (memcmp(plaintext, recovered, 4) == 0) {
        printf("✓ w=0 case: Encryption/Decryption successful\n");
    } else {
        printf("✗ w=0 case: Decryption failed to recover plaintext\n");
        exit(1);
    }

    fast_cleanup(ctx);
}

void
test_minimum_parameters()
{
    printf("\n=== Testing Minimum Valid Parameters ===\n");

    uint8_t key[FAST_AES_KEY_SIZE] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

    fast_params_t params;
    params.radix        = 4; // Minimum radix
    params.word_length  = 2; // Minimum word length
    params.branch_dist1 = 0;
    params.branch_dist2 = 1;
    params.num_layers   = 4;
    params.sbox_count   = 256;

    fast_context_t *ctx;
    assert(fast_init(&ctx, &params, key) == 0);

    uint8_t plaintext[2] = { 0, 3 }; // Values within radix 4
    uint8_t ciphertext[2];
    uint8_t recovered[2];

    printf("Testing with minimum parameters (radix=4, length=2):\n");
    printf("  Plaintext:  %u %u\n", plaintext[0], plaintext[1]);

    assert(fast_encrypt(ctx, EDGE_TWEAK, EDGE_TWEAK_LEN, plaintext, ciphertext, 2) == 0);
    printf("  Ciphertext: %u %u\n", ciphertext[0], ciphertext[1]);

    assert(fast_decrypt(ctx, EDGE_TWEAK, EDGE_TWEAK_LEN, ciphertext, recovered, 2) == 0);
    printf("  Recovered:  %u %u\n", recovered[0], recovered[1]);

    if (memcmp(plaintext, recovered, 2) == 0) {
        printf("✓ Minimum parameters: Encryption/Decryption successful\n");
    } else {
        printf("✗ Minimum parameters: Decryption failed\n");
        exit(1);
    }

    fast_cleanup(ctx);
}

void
test_large_radix()
{
    printf("\n=== Testing Large Radix (256) ===\n");

    uint8_t key[FAST_AES_KEY_SIZE];
    for (int i = 0; i < FAST_AES_KEY_SIZE; i++) {
        key[i] = i;
    }

    fast_params_t params;
    params.radix        = 256; // Maximum radix
    params.word_length  = 8;
    params.branch_dist1 = 2;
    params.branch_dist2 = 3;
    params.num_layers   = 16;
    params.sbox_count   = 256;

    fast_context_t *ctx;
    assert(fast_init(&ctx, &params, key) == 0);

    uint8_t plaintext[8] = { 0, 1, 127, 128, 254, 255, 100, 200 };
    uint8_t ciphertext[8];
    uint8_t recovered[8];

    printf("Testing with radix=256:\n");
    printf("  Plaintext:  ");
    for (int i = 0; i < 8; i++)
        printf("%3u ", plaintext[i]);
    printf("\n");

    assert(fast_encrypt(ctx, EDGE_TWEAK, EDGE_TWEAK_LEN, plaintext, ciphertext, 8) == 0);
    printf("  Ciphertext: ");
    for (int i = 0; i < 8; i++)
        printf("%3u ", ciphertext[i]);
    printf("\n");

    assert(fast_decrypt(ctx, EDGE_TWEAK, EDGE_TWEAK_LEN, ciphertext, recovered, 8) == 0);
    printf("  Recovered:  ");
    for (int i = 0; i < 8; i++)
        printf("%3u ", recovered[i]);
    printf("\n");

    if (memcmp(plaintext, recovered, 8) == 0) {
        printf("✓ Large radix: Encryption/Decryption successful\n");
    } else {
        printf("✗ Large radix: Decryption failed\n");
        exit(1);
    }

    fast_cleanup(ctx);
}

void
test_determinism()
{
    printf("\n=== Testing Determinism ===\n");

    uint8_t key[FAST_AES_KEY_SIZE] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
                                       0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00 };

    fast_params_t params;
    calculate_recommended_params(&params, 10, 6);

    fast_context_t *ctx1, *ctx2;
    assert(fast_init(&ctx1, &params, key) == 0);
    assert(fast_init(&ctx2, &params, key) == 0);

    uint8_t plaintext[6] = { 9, 8, 7, 6, 5, 4 };
    uint8_t ciphertext1[6], ciphertext2[6];

    assert(fast_encrypt(ctx1, EDGE_TWEAK, EDGE_TWEAK_LEN, plaintext, ciphertext1, 6) == 0);
    assert(fast_encrypt(ctx2, EDGE_TWEAK, EDGE_TWEAK_LEN, plaintext, ciphertext2, 6) == 0);

    if (memcmp(ciphertext1, ciphertext2, 6) == 0) {
        printf("✓ Determinism: Same key produces same ciphertext\n");
    } else {
        printf("✗ Determinism: Different ciphertexts from same key!\n");
        exit(1);
    }

    uint8_t alt_tweak[] = { 0x90, 0x81, 0x72, 0x63 };
    assert(sizeof(alt_tweak) == EDGE_TWEAK_LEN);
    assert(fast_encrypt(ctx1, alt_tweak, EDGE_TWEAK_LEN, plaintext, ciphertext1, 6) == 0);
    if (memcmp(ciphertext1, ciphertext2, 6) != 0) {
        printf("✓ Different tweaks: Ciphertexts differ as expected\n");
    } else {
        printf("✗ Different tweaks: Ciphertexts unexpectedly match\n");
        exit(1);
    }

    fast_cleanup(ctx1);
    fast_cleanup(ctx2);
}

int
main()
{
    printf("FAST Edge Case Test Suite\n");
    printf("==========================\n");

    test_w_zero_case();
    test_minimum_parameters();
    test_large_radix();
    test_determinism();

    printf("\n==========================\n");
    printf("All edge case tests passed!\n");

    return 0;
}
