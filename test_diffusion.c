#include "fast.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#define DEFAULT_TWEAK_LEN 8
static const uint8_t DEFAULT_TWEAK[DEFAULT_TWEAK_LEN] = { 0xA0, 0xA1, 0xA2, 0xA3,
                                                          0xA4, 0xA5, 0xA6, 0xA7 };

#define MAX_WORD_LENGTH 128

typedef struct {
    double avg_bit_flip_ratio;
    double min_bit_flip_ratio;
    double max_bit_flip_ratio;
    double std_deviation;
    int total_tests;
    int passed_tests;
} diffusion_stats_t;

static int
count_different_bytes(const uint8_t *a, const uint8_t *b, size_t length)
{
    int count = 0;
    for (size_t i = 0; i < length; i++) {
        if (a[i] != b[i]) {
            count++;
        }
    }
    return count;
}

static int
hamming_weight(uint8_t byte)
{
    int weight = 0;
    while (byte) {
        weight += byte & 1;
        byte >>= 1;
    }
    return weight;
}

static int
hamming_distance(const uint8_t *a, const uint8_t *b, size_t length)
{
    int distance = 0;
    for (size_t i = 0; i < length; i++) {
        distance += hamming_weight(a[i] ^ b[i]);
    }
    return distance;
}

static void
test_single_bit_flip(fast_context_t *ctx, size_t word_length, diffusion_stats_t *stats)
{
    uint8_t plaintext1[MAX_WORD_LENGTH];
    uint8_t plaintext2[MAX_WORD_LENGTH];
    uint8_t ciphertext1[MAX_WORD_LENGTH];
    uint8_t ciphertext2[MAX_WORD_LENGTH];
    
    double sum_ratio = 0.0;
    double sum_squared = 0.0;
    double min_ratio = 1.0;
    double max_ratio = 0.0;
    int test_count = 0;
    int passed = 0;
    
    // Test flipping each bit position
    for (size_t byte_idx = 0; byte_idx < word_length; byte_idx++) {
        for (int bit_idx = 0; bit_idx < 8; bit_idx++) {
            // Initialize with random values
            for (size_t i = 0; i < word_length; i++) {
                plaintext1[i] = (uint8_t)((i * 7 + byte_idx * 3) % 10);
                plaintext2[i] = plaintext1[i];
            }
            
            // Flip single bit
            plaintext2[byte_idx] ^= (1 << bit_idx);
            
            // Ensure the value stays within radix bounds (0-9 for radix 10)
            if (plaintext2[byte_idx] >= 10) {
                plaintext2[byte_idx] = plaintext1[byte_idx] ^ (1 << ((bit_idx + 1) % 4));
                if (plaintext2[byte_idx] >= 10) {
                    plaintext2[byte_idx] = (plaintext1[byte_idx] + 1) % 10;
                }
            }
            
            // Encrypt both
            assert(fast_encrypt(ctx, DEFAULT_TWEAK, DEFAULT_TWEAK_LEN, plaintext1,
                                ciphertext1, word_length) == 0);
            assert(fast_encrypt(ctx, DEFAULT_TWEAK, DEFAULT_TWEAK_LEN, plaintext2,
                                ciphertext2, word_length) == 0);
            
            // Measure diffusion
            int different_bytes = count_different_bytes(ciphertext1, ciphertext2, word_length);
            double ratio = (double)different_bytes / word_length;
            
            sum_ratio += ratio;
            sum_squared += ratio * ratio;
            if (ratio < min_ratio) min_ratio = ratio;
            if (ratio > max_ratio) max_ratio = ratio;
            
            // Good diffusion should affect at least 40% of output bytes
            if (ratio >= 0.4) {
                passed++;
            }
            
            test_count++;
        }
    }
    
    stats->avg_bit_flip_ratio = sum_ratio / test_count;
    stats->min_bit_flip_ratio = min_ratio;
    stats->max_bit_flip_ratio = max_ratio;
    
    double variance = (sum_squared / test_count) - (stats->avg_bit_flip_ratio * stats->avg_bit_flip_ratio);
    stats->std_deviation = sqrt(variance);
    
    stats->total_tests = test_count;
    stats->passed_tests = passed;
}

static void
test_avalanche_effect(fast_context_t *ctx, size_t word_length)
{
    printf("\n=== Testing Avalanche Effect (word_length=%zu) ===\n", word_length);
    
    uint8_t plaintext[MAX_WORD_LENGTH];
    uint8_t modified[MAX_WORD_LENGTH];
    uint8_t ciphertext1[MAX_WORD_LENGTH];
    uint8_t ciphertext2[MAX_WORD_LENGTH];
    
    // Initialize plaintext
    for (size_t i = 0; i < word_length; i++) {
        plaintext[i] = (uint8_t)(i % 10);
        modified[i] = plaintext[i];
    }
    
    // Test 1: Single byte change
    modified[0] = (plaintext[0] + 1) % 10;
    
    assert(fast_encrypt(ctx, DEFAULT_TWEAK, DEFAULT_TWEAK_LEN, plaintext, ciphertext1,
                        word_length) == 0);
    assert(fast_encrypt(ctx, DEFAULT_TWEAK, DEFAULT_TWEAK_LEN, modified, ciphertext2,
                        word_length) == 0);
    
    int diff_bytes = count_different_bytes(ciphertext1, ciphertext2, word_length);
    double diff_ratio = (double)diff_bytes / word_length;
    
    printf("Single byte change:\n");
    printf("  Changed bytes in output: %d/%zu (%.1f%%)\n", 
           diff_bytes, word_length, diff_ratio * 100);
    
    if (diff_ratio >= 0.4) {
        printf("  ✓ Good avalanche effect (>= 40%% changed)\n");
    } else {
        printf("  ✗ Poor avalanche effect (< 40%% changed)\n");
    }
    
    // Test 2: Multiple byte changes
    for (size_t i = 0; i < word_length; i++) {
        modified[i] = (plaintext[i] + 1) % 10;
    }
    
    assert(fast_encrypt(ctx, DEFAULT_TWEAK, DEFAULT_TWEAK_LEN, modified, ciphertext2,
                        word_length) == 0);
    
    diff_bytes = count_different_bytes(ciphertext1, ciphertext2, word_length);
    diff_ratio = (double)diff_bytes / word_length;
    
    printf("\nAll bytes changed by 1:\n");
    printf("  Changed bytes in output: %d/%zu (%.1f%%)\n", 
           diff_bytes, word_length, diff_ratio * 100);
    
    if (diff_ratio >= 0.9) {
        printf("  ✓ Excellent avalanche effect (>= 90%% changed)\n");
    } else if (diff_ratio >= 0.5) {
        printf("  ✓ Good avalanche effect (>= 50%% changed)\n");
    } else {
        printf("  ✗ Poor avalanche effect (< 50%% changed)\n");
    }
}

static void
test_key_sensitivity(size_t word_length)
{
    printf("\n=== Testing Key Sensitivity (word_length=%zu) ===\n", word_length);
    
    uint8_t key1[FAST_AES_KEY_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    uint8_t key2[FAST_AES_KEY_SIZE];
    memcpy(key2, key1, FAST_AES_KEY_SIZE);
    key2[0] ^= 0x01;  // Flip one bit in the key
    
    fast_params_t params;
    assert(calculate_recommended_params(&params, 10, word_length) == 0);
    
    fast_context_t *ctx1, *ctx2;
    assert(fast_init(&ctx1, &params, key1) == 0);
    assert(fast_init(&ctx2, &params, key2) == 0);
    
    uint8_t plaintext[MAX_WORD_LENGTH];
    uint8_t ciphertext1[MAX_WORD_LENGTH];
    uint8_t ciphertext2[MAX_WORD_LENGTH];
    
    // Initialize plaintext
    for (size_t i = 0; i < word_length; i++) {
        plaintext[i] = (uint8_t)(i % 10);
    }
    
    assert(fast_encrypt(ctx1, DEFAULT_TWEAK, DEFAULT_TWEAK_LEN, plaintext, ciphertext1,
                        word_length) == 0);
    assert(fast_encrypt(ctx2, DEFAULT_TWEAK, DEFAULT_TWEAK_LEN, plaintext, ciphertext2,
                        word_length) == 0);
    
    int diff_bytes = count_different_bytes(ciphertext1, ciphertext2, word_length);
    double diff_ratio = (double)diff_bytes / word_length;
    
    printf("Same plaintext, 1-bit key difference:\n");
    printf("  Changed bytes in output: %d/%zu (%.1f%%)\n", 
           diff_bytes, word_length, diff_ratio * 100);
    
    if (diff_ratio >= 0.9) {
        printf("  ✓ Excellent key sensitivity (>= 90%% different)\n");
    } else if (diff_ratio >= 0.7) {
        printf("  ✓ Good key sensitivity (>= 70%% different)\n");
    } else {
        printf("  ✗ Poor key sensitivity (< 70%% different)\n");
    }
    
    fast_cleanup(ctx1);
    fast_cleanup(ctx2);
}

static void
test_statistical_diffusion(fast_context_t *ctx, size_t word_length, int num_samples)
{
    printf("\n=== Statistical Diffusion Analysis (word_length=%zu, samples=%d) ===\n", 
           word_length, num_samples);
    
    uint8_t plaintext1[MAX_WORD_LENGTH];
    uint8_t plaintext2[MAX_WORD_LENGTH];
    uint8_t ciphertext1[MAX_WORD_LENGTH];
    uint8_t ciphertext2[MAX_WORD_LENGTH];
    
    int histogram[11] = {0};  // 0-10 for 0%, 10%, ..., 100%
    double total_ratio = 0.0;
    
    for (int sample = 0; sample < num_samples; sample++) {
        // Generate random plaintexts
        for (size_t i = 0; i < word_length; i++) {
            plaintext1[i] = (uint8_t)(rand() % 10);
            plaintext2[i] = (uint8_t)(rand() % 10);
        }
        
        assert(fast_encrypt(ctx, DEFAULT_TWEAK, DEFAULT_TWEAK_LEN, plaintext1, ciphertext1,
                            word_length) == 0);
        assert(fast_encrypt(ctx, DEFAULT_TWEAK, DEFAULT_TWEAK_LEN, plaintext2, ciphertext2,
                            word_length) == 0);
        
        int diff_bytes = count_different_bytes(ciphertext1, ciphertext2, word_length);
        double ratio = (double)diff_bytes / word_length;
        total_ratio += ratio;
        
        int bucket = (int)(ratio * 10);
        if (bucket > 10) bucket = 10;
        histogram[bucket]++;
    }
    
    printf("\nDistribution of output differences:\n");
    printf("Difference | Count | Percentage\n");
    printf("-----------|-------|------------\n");
    for (int i = 0; i <= 10; i++) {
        double percentage = (double)histogram[i] / num_samples * 100;
        printf("%3d%%-%-3d%% | %5d | %6.2f%%", i*10, (i+1)*10-1, histogram[i], percentage);
        
        // Visual bar
        printf(" ");
        int bar_length = (int)(percentage / 2);
        for (int j = 0; j < bar_length; j++) {
            printf("█");
        }
        printf("\n");
    }
    
    double avg_ratio = total_ratio / num_samples;
    printf("\nAverage difference ratio: %.2f%%\n", avg_ratio * 100);
    
    if (avg_ratio >= 0.8) {
        printf("✓ Excellent statistical diffusion (>= 80%% average)\n");
    } else if (avg_ratio >= 0.6) {
        printf("✓ Good statistical diffusion (>= 60%% average)\n");
    } else {
        printf("✗ Poor statistical diffusion (< 60%% average)\n");
    }
}

static void
test_progressive_diffusion(fast_context_t *ctx, size_t word_length)
{
    printf("\n=== Progressive Diffusion Test (word_length=%zu) ===\n", word_length);
    printf("Testing how diffusion increases with number of changed input bytes:\n\n");
    
    uint8_t plaintext1[MAX_WORD_LENGTH];
    uint8_t plaintext2[MAX_WORD_LENGTH];
    uint8_t ciphertext1[MAX_WORD_LENGTH];
    uint8_t ciphertext2[MAX_WORD_LENGTH];
    
    // Initialize plaintext
    for (size_t i = 0; i < word_length; i++) {
        plaintext1[i] = (uint8_t)(i % 10);
    }
    
    assert(fast_encrypt(ctx, DEFAULT_TWEAK, DEFAULT_TWEAK_LEN, plaintext1, ciphertext1,
                        word_length) == 0);
    
    printf("Input Changes | Output Changes | Ratio\n");
    printf("--------------|----------------|--------\n");
    
    for (size_t changes = 1; changes <= word_length && changes <= 10; changes++) {
        memcpy(plaintext2, plaintext1, word_length);
        
        // Change first 'changes' bytes
        for (size_t i = 0; i < changes; i++) {
            plaintext2[i] = (plaintext1[i] + 1) % 10;
        }
        
        assert(fast_encrypt(ctx, DEFAULT_TWEAK, DEFAULT_TWEAK_LEN, plaintext2, ciphertext2,
                            word_length) == 0);
        
        int diff_bytes = count_different_bytes(ciphertext1, ciphertext2, word_length);
        double ratio = (double)diff_bytes / word_length;
        
        printf("%13zu | %14d | %5.1f%%\n", changes, diff_bytes, ratio * 100);
    }
}

int
main(int argc, char *argv[])
{
    printf("FAST Diffusion Property Test Suite\n");
    printf("===================================\n");
    
    // Default parameters
    uint32_t radix = 10;
    size_t word_lengths[] = {8, 16, 32, 64};
    size_t num_word_lengths = sizeof(word_lengths) / sizeof(word_lengths[0]);
    
    // Parse command line arguments
    if (argc > 1) {
        radix = atoi(argv[1]);
        if (radix < 4 || radix > 256) {
            fprintf(stderr, "Invalid radix: %u (must be 4-256)\n", radix);
            return 1;
        }
        printf("Using radix: %u\n", radix);
    }
    
    uint8_t key[FAST_AES_KEY_SIZE] = {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
                                       0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};
    
    for (size_t wl_idx = 0; wl_idx < num_word_lengths; wl_idx++) {
        size_t word_length = word_lengths[wl_idx];
        
        printf("\n╔══════════════════════════════════════════════════════════════╗\n");
        printf("║     Testing word_length = %3zu, radix = %3u                   ║\n", word_length, radix);
        printf("╚══════════════════════════════════════════════════════════════╝\n");
        
        fast_params_t params;
        if (calculate_recommended_params(&params, radix, word_length) != 0) {
            printf("Failed to calculate parameters for radix=%u, word_length=%zu\n", 
                   radix, word_length);
            continue;
        }
        
        printf("Parameters: layers=%u, w=%u, w'=%u, sboxes=%u\n",
               params.num_layers, params.branch_dist1, params.branch_dist2, params.sbox_count);
        
        fast_context_t *ctx;
        if (fast_init(&ctx, &params, key) != 0) {
            printf("Failed to initialize context\n");
            continue;
        }
        
        // Run diffusion tests
        test_avalanche_effect(ctx, word_length);
        test_key_sensitivity(word_length);
        
        // Single bit flip analysis
        printf("\n=== Single Bit Flip Analysis ===\n");
        diffusion_stats_t stats;
        test_single_bit_flip(ctx, word_length, &stats);
        printf("Average diffusion ratio: %.2f%%\n", stats.avg_bit_flip_ratio * 100);
        printf("Min diffusion ratio: %.2f%%\n", stats.min_bit_flip_ratio * 100);
        printf("Max diffusion ratio: %.2f%%\n", stats.max_bit_flip_ratio * 100);
        printf("Standard deviation: %.4f\n", stats.std_deviation);
        printf("Tests passed (>40%% threshold): %d/%d (%.1f%%)\n", 
               stats.passed_tests, stats.total_tests, 
               (double)stats.passed_tests / stats.total_tests * 100);
        
        // Statistical analysis
        test_statistical_diffusion(ctx, word_length, 1000);
        
        // Progressive diffusion
        test_progressive_diffusion(ctx, word_length);
        
        fast_cleanup(ctx);
    }
    
    printf("\n===================================\n");
    printf("Diffusion analysis completed!\n");
    
    return 0;
}
