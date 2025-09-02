#include "fast.h"
#include "fast_internal.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BENCH_TWEAK_LEN 8
static const uint8_t BENCH_TWEAK[BENCH_TWEAK_LEN] = { 0xBA, 0xDC, 0x0F, 0xFE,
                                                      0xED, 0x1A, 0x71, 0x0E };

#define BENCHMARK_ITERATIONS 10000
#define WARMUP_ITERATIONS 1000

typedef struct {
    double encrypt_time;
    double decrypt_time;
    double throughput_mbps_enc;
    double throughput_mbps_dec;
    size_t data_size;
} benchmark_result_t;

static double 
get_time_seconds() 
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void
run_benchmark(fast_context_t *ctx, size_t data_size, int iterations, benchmark_result_t *result, uint32_t radix)
{
    uint8_t *plaintext = malloc(data_size);
    uint8_t *ciphertext = malloc(data_size);
    uint8_t *recovered = malloc(data_size);
    
    if (!plaintext || !ciphertext || !recovered) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    
    // Initialize with random-looking data within radix bounds
    for (size_t i = 0; i < data_size; i++) {
        plaintext[i] = (uint8_t)(i % radix);
    }
    
    // Warmup
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        fast_encrypt(ctx, BENCH_TWEAK, BENCH_TWEAK_LEN, plaintext, ciphertext, data_size);
        fast_decrypt(ctx, BENCH_TWEAK, BENCH_TWEAK_LEN, ciphertext, recovered, data_size);
    }
    
    // Benchmark encryption
    double start = get_time_seconds();
    for (int i = 0; i < iterations; i++) {
        fast_encrypt(ctx, BENCH_TWEAK, BENCH_TWEAK_LEN, plaintext, ciphertext, data_size);
    }
    double end = get_time_seconds();
    result->encrypt_time = (end - start) / iterations;
    
    // Benchmark decryption
    start = get_time_seconds();
    for (int i = 0; i < iterations; i++) {
        fast_decrypt(ctx, BENCH_TWEAK, BENCH_TWEAK_LEN, ciphertext, recovered, data_size);
    }
    end = get_time_seconds();
    result->decrypt_time = (end - start) / iterations;
    
    // Calculate throughput in MB/s
    double bytes_per_second_enc = data_size / result->encrypt_time;
    double bytes_per_second_dec = data_size / result->decrypt_time;
    result->throughput_mbps_enc = bytes_per_second_enc / (1024 * 1024);
    result->throughput_mbps_dec = bytes_per_second_dec / (1024 * 1024);
    result->data_size = data_size;
    
    // Verify correctness
    assert(memcmp(plaintext, recovered, data_size) == 0);
    
    free(plaintext);
    free(ciphertext);
    free(recovered);
}

static void
benchmark_different_parameters()
{
    printf("\n=== Benchmarking Different Parameters ===\n");
    printf("%-10s %-10s %-10s %-15s %-15s %-15s %-15s\n", 
           "Radix", "WordLen", "Layers", "Encrypt(µs)", "Decrypt(µs)", "Enc MB/s", "Dec MB/s");
    printf("---------------------------------------------------------------------------------------------------------\n");
    
    uint8_t key[FAST_AES_KEY_SIZE] = {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
                                       0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};
    
    struct {
        uint32_t radix;
        uint32_t word_length;
    } test_configs[] = {
        {4, 16},
        {8, 16},
        {10, 16},
        {16, 16},
        {32, 16},
        {64, 16},
        {10, 8},
        {10, 32},
        {10, 64},
        {10, 128},
    };
    
    for (size_t i = 0; i < sizeof(test_configs) / sizeof(test_configs[0]); i++) {
        fast_params_t params;
        if (calculate_recommended_params(&params, test_configs[i].radix, test_configs[i].word_length) != 0) {
            printf("%-10u %-10u Failed to calculate parameters\n", 
                   test_configs[i].radix, test_configs[i].word_length);
            continue;
        }
        
        fast_context_t *ctx;
        if (fast_init(&ctx, &params, key) != 0) {
            printf("%-10u %-10u Failed to initialize context\n", 
                   test_configs[i].radix, test_configs[i].word_length);
            continue;
        }
        
        benchmark_result_t result;
        run_benchmark(ctx, test_configs[i].word_length, BENCHMARK_ITERATIONS, &result, params.radix);
        
        printf("%-10u %-10u %-10u %-15.2f %-15.2f %-15.2f %-15.2f\n",
               params.radix,
               params.word_length,
               params.num_layers,
               result.encrypt_time * 1e6,
               result.decrypt_time * 1e6,
               result.throughput_mbps_enc,
               result.throughput_mbps_dec);
        
        fast_cleanup(ctx);
    }
}

static void
benchmark_data_sizes()
{
    printf("\n=== Benchmarking Different Data Sizes (radix=10) ===\n");
    printf("%-15s %-15s %-15s %-15s %-15s\n", 
           "Data Size", "Encrypt(µs)", "Decrypt(µs)", "Enc MB/s", "Dec MB/s");
    printf("---------------------------------------------------------------------------------\n");
    
    uint8_t key[FAST_AES_KEY_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                       0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    
    size_t data_sizes[] = {8, 16, 32, 64, 128, 256, 512, 1024};
    
    for (size_t i = 0; i < sizeof(data_sizes) / sizeof(data_sizes[0]); i++) {
        fast_params_t params;
        if (calculate_recommended_params(&params, 10, data_sizes[i]) != 0) {
            printf("%-15zu Failed to calculate parameters\n", data_sizes[i]);
            continue;
        }
        
        fast_context_t *ctx;
        if (fast_init(&ctx, &params, key) != 0) {
            printf("%-15zu Failed to initialize context\n", data_sizes[i]);
            continue;
        }
        
        benchmark_result_t result;
        int iterations = BENCHMARK_ITERATIONS / (data_sizes[i] / 16 + 1);
        run_benchmark(ctx, data_sizes[i], iterations, &result, params.radix);
        
        printf("%-15zu %-15.2f %-15.2f %-15.2f %-15.2f\n",
               data_sizes[i],
               result.encrypt_time * 1e6,
               result.decrypt_time * 1e6,
               result.throughput_mbps_enc,
               result.throughput_mbps_dec);
        
        fast_cleanup(ctx);
    }
}

static void
benchmark_operations_per_second()
{
    printf("\n=== Operations Per Second ===\n");
    
    uint8_t key[FAST_AES_KEY_SIZE] = {0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
                                       0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00};
    
    fast_params_t params;
    assert(calculate_recommended_params(&params, 10, 16) == 0);
    
    fast_context_t *ctx;
    assert(fast_init(&ctx, &params, key) == 0);
    
    uint8_t plaintext[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6};
    uint8_t ciphertext[16];
    uint8_t recovered[16];
    
    // Measure operations over 1 second
    double start = get_time_seconds();
    double end = start + 1.0;
    int encrypt_ops = 0;
    
    while (get_time_seconds() < end) {
        fast_encrypt(ctx, BENCH_TWEAK, BENCH_TWEAK_LEN, plaintext, ciphertext, 16);
        encrypt_ops++;
    }
    
    start = get_time_seconds();
    end = start + 1.0;
    int decrypt_ops = 0;
    
    while (get_time_seconds() < end) {
        fast_decrypt(ctx, BENCH_TWEAK, BENCH_TWEAK_LEN, ciphertext, recovered, 16);
        decrypt_ops++;
    }
    
    printf("Encryption operations per second: %d\n", encrypt_ops);
    printf("Decryption operations per second: %d\n", decrypt_ops);
    printf("Average encryption time: %.2f µs\n", 1e6 / encrypt_ops);
    printf("Average decryption time: %.2f µs\n", 1e6 / decrypt_ops);
    
    fast_cleanup(ctx);
}

int
main()
{
    printf("FAST Cryptographic Benchmark Suite\n");
    printf("===================================\n");
    printf("Iterations per benchmark: %d\n", BENCHMARK_ITERATIONS);
    printf("Warmup iterations: %d\n", WARMUP_ITERATIONS);
    
    benchmark_different_parameters();
    benchmark_data_sizes();
    benchmark_operations_per_second();
    
    printf("\n===================================\n");
    printf("Benchmark completed successfully!\n");
    
    return 0;
}
