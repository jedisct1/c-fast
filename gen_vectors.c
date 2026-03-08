#include "fast.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t KEY[FAST_AES_KEY_SIZE] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

typedef struct { const uint8_t *data; size_t len; } tweak_t;

static void
print_array(const uint8_t *data, size_t len)
{
    printf("[");
    for (size_t i = 0; i < len; i++) {
        if (i > 0) printf(",");
        printf("%u", data[i]);
    }
    printf("]");
}

static int
emit_vector(fast_context_t *ctx, const fast_params_t *p,
            const uint8_t *pt, size_t pt_len,
            const tweak_t *tw, int *first)
{
    uint8_t ct[1024];
    uint8_t rt[1024];

    if (fast_encrypt(ctx, tw->data, tw->len, pt, ct, pt_len) != 0) {
        fprintf(stderr, "encrypt failed r=%u l=%u\n", p->radix, p->word_length);
        return -1;
    }
    if (fast_decrypt(ctx, tw->data, tw->len, ct, rt, pt_len) != 0) {
        fprintf(stderr, "decrypt failed r=%u l=%u\n", p->radix, p->word_length);
        return -1;
    }
    if (memcmp(pt, rt, pt_len) != 0) {
        fprintf(stderr, "roundtrip FAILED r=%u l=%u twk=%zu\n",
                p->radix, p->word_length, tw->len);
        return -1;
    }

    if (!*first) printf(",\n");
    *first = 0;

    printf("  {\"radix\":%u,\"wordLength\":%u,\"sboxCount\":%u,"
           "\"numLayers\":%u,\"branchDist1\":%u,\"branchDist2\":%u,"
           "\"securityLevel\":%u,",
           p->radix, p->word_length, p->sbox_count,
           p->num_layers, p->branch_dist1, p->branch_dist2,
           p->security_level);
    printf("\"key\":");
    print_array(KEY, sizeof(KEY));
    printf(",\"tweak\":");
    print_array(tw->data ? tw->data : (const uint8_t *)"", tw->len);
    printf(",\"plaintext\":");
    print_array(pt, pt_len);
    printf(",\"ciphertext\":");
    print_array(ct, pt_len);
    printf("}");
    return 0;
}

int
main(void)
{
    struct { uint32_t radix; uint32_t wl; } cases[] = {
        {4,2},{4,4},{4,8},{4,16},
        {10,2},{10,3},{10,4},{10,8},{10,10},{10,16},{10,19},{10,32},
        {16,2},{16,4},{16,8},{16,16},
        {36,4},{36,8},
        {62,4},{62,8},
        {256,2},{256,4},{256,8},{256,16},{256,32},
    };
    int ncases = sizeof(cases) / sizeof(cases[0]);

    uint8_t tweak8[]    = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77};
    uint8_t tweakShort[] = {0xAA,0xBB};
    tweak_t tweaks[] = {
        {tweak8, sizeof(tweak8)},
        {NULL, 0},
        {tweakShort, sizeof(tweakShort)},
    };
    int ntweaks = sizeof(tweaks) / sizeof(tweaks[0]);

    int first = 1;
    int errors = 0;

    printf("[\n");

    for (int ci = 0; ci < ncases; ci++) {
        fast_params_t params;
        if (calculate_recommended_params(&params, cases[ci].radix, cases[ci].wl) != 0) {
            fprintf(stderr, "params failed r=%u l=%u\n", cases[ci].radix, cases[ci].wl);
            errors++;
            continue;
        }

        fast_context_t *ctx = NULL;
        if (fast_init(&ctx, &params, KEY) != 0) {
            fprintf(stderr, "init failed r=%u l=%u\n", cases[ci].radix, cases[ci].wl);
            errors++;
            continue;
        }

        for (int ti = 0; ti < ntweaks; ti++) {
            uint32_t wl = cases[ci].wl;
            uint32_t radix = cases[ci].radix;

            // Sequential plaintext
            uint8_t pt_seq[1024];
            for (uint32_t i = 0; i < wl; i++) pt_seq[i] = i % radix;
            if (emit_vector(ctx, &params, pt_seq, wl, &tweaks[ti], &first) != 0) errors++;

            // All-zero plaintext
            uint8_t pt_zero[1024] = {0};
            if (emit_vector(ctx, &params, pt_zero, wl, &tweaks[ti], &first) != 0) errors++;

            // Max-symbol plaintext
            uint8_t pt_max[1024];
            memset(pt_max, radix - 1, wl);
            if (emit_vector(ctx, &params, pt_max, wl, &tweaks[ti], &first) != 0) errors++;
        }

        fast_cleanup(ctx);
    }

    printf("\n]\n");

    fprintf(stderr, "Generated vectors with %d errors\n", errors);
    return errors > 0 ? 1 : 0;
}
