#include "fast.h"
#include "fast_internal.h"
#include <math.h>
#include <stdlib.h>
#include <string.h>

// Define the full context structure
struct fast_context {
    fast_params_t params;
    sbox_pool_t  *sbox_pool;
    uint8_t       master_key[FAST_MASTER_KEY_SIZE];
    uint32_t     *seq_buffer;
    size_t        seq_length;
    uint8_t      *cached_tweak;
    size_t        cached_tweak_len;
    bool          has_cached_seq;
};

typedef struct {
    const uint8_t *data;
    size_t         len;
} prf_part_t;

static const uint8_t LABEL_INSTANCE1[] = "instance1";
static const uint8_t LABEL_INSTANCE2[] = "instance2";
static const uint8_t LABEL_FPE_POOL[]  = "FPE Pool";
static const uint8_t LABEL_FPE_SEQ[]   = "FPE SEQ";
static const uint8_t LABEL_TWEAK[]     = "tweak";

static const uint32_t k_round_l_values[] = { 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 16, 32, 50, 64, 100 };
static const uint32_t k_round_radices[]  = { 4,  5,  6,  7,   8,   9,   10,   11,   12,    13,
                                             14, 15, 16, 100, 128, 256, 1000, 1024, 10000, 65536 };

static const uint16_t k_round_table[][15] = {
    { 165, 135, 117, 105, 96, 89, 83, 78, 74, 68, 59, 52, 52, 53, 57 }, // a = 4
    { 131, 107, 93, 83, 76, 70, 66, 62, 59, 54, 48, 46, 47, 48, 53 }, // a = 5
    { 113, 92, 80, 72, 65, 61, 57, 54, 51, 46, 44, 43, 44, 46, 52 }, // a = 6
    { 102, 83, 72, 64, 59, 55, 51, 48, 46, 43, 41, 41, 43, 45, 50 }, // a = 7
    { 94, 76, 66, 59, 54, 50, 47, 44, 42, 41, 39, 39, 42, 44, 50 }, // a = 8
    { 88, 72, 62, 56, 51, 47, 44, 42, 40, 39, 38, 38, 41, 43, 49 }, // a = 9
    { 83, 68, 59, 53, 48, 45, 42, 39, 39, 38, 37, 37, 40, 43, 49 }, // a = 10
    { 79, 65, 56, 50, 46, 43, 40, 38, 38, 37, 36, 37, 40, 42, 48 }, // a = 11
    { 76, 62, 54, 48, 44, 41, 38, 37, 37, 36, 35, 36, 39, 42, 48 }, // a = 12
    { 73, 60, 52, 47, 43, 39, 37, 36, 36, 35, 34, 36, 39, 41, 48 }, // a = 13
    { 71, 58, 50, 45, 41, 38, 36, 36, 35, 34, 34, 35, 39, 41, 47 }, // a = 14
    { 69, 57, 49, 44, 40, 37, 36, 35, 34, 34, 33, 35, 38, 41, 47 }, // a = 15
    { 67, 55, 48, 43, 39, 36, 35, 34, 34, 33, 33, 35, 38, 41, 47 }, // a = 16
    { 40, 33, 28, 27, 26, 26, 25, 25, 25, 26, 26, 30, 34, 37, 44 }, // a = 100
    { 38, 31, 27, 26, 25, 25, 25, 25, 25, 25, 26, 30, 34, 37, 44 }, // a = 128
    { 33, 27, 25, 24, 23, 23, 23, 23, 23, 24, 25, 29, 33, 37, 44 }, // a = 256
    { 32, 22, 21, 21, 21, 21, 21, 21, 21, 22, 23, 28, 32, 36, 43 }, // a = 1000
    { 32, 22, 21, 21, 21, 21, 21, 21, 21, 22, 23, 28, 32, 36, 43 }, // a = 1024
    { 32, 22, 18, 18, 18, 18, 19, 19, 19, 20, 21, 27, 32, 35, 42 }, // a = 10000
    { 32, 22, 17, 17, 17, 17, 17, 18, 18, 19, 21, 26, 31, 35, 42 } // a = 65536
};

static void
write_u32_be(uint32_t value, uint8_t out[4])
{
    out[0] = (uint8_t) ((value >> 24) & 0xFF);
    out[1] = (uint8_t) ((value >> 16) & 0xFF);
    out[2] = (uint8_t) ((value >> 8) & 0xFF);
    out[3] = (uint8_t) (value & 0xFF);
}

static double
interpolate(double x, double x0, double x1, double y0, double y1)
{
    if (x1 == x0) {
        return y0;
    }
    double t = (x - x0) / (x1 - x0);
    if (t <= 0.0)
        return y0;
    if (t >= 1.0)
        return y1;
    return y0 + t * (y1 - y0);
}

static double
rounds_for_row(size_t row_index, double ell)
{
    const size_t    l_count = sizeof(k_round_l_values) / sizeof(k_round_l_values[0]);
    const uint16_t *row     = k_round_table[row_index];

    if (ell <= k_round_l_values[0]) {
        return (double) row[0];
    }
    if (ell >= k_round_l_values[l_count - 1]) {
        double last      = (double) row[l_count - 1];
        double ratio     = sqrt(ell / (double) k_round_l_values[l_count - 1]);
        double projected = last * ratio;
        return projected < last ? last : projected;
    }

    for (size_t i = 1; i < l_count; i++) {
        double l_prev = (double) k_round_l_values[i - 1];
        double l_curr = (double) k_round_l_values[i];
        if (ell <= l_curr) {
            double r_prev = (double) row[i - 1];
            double r_curr = (double) row[i];
            return interpolate(ell, l_prev, l_curr, r_prev, r_curr);
        }
    }

    return (double) row[l_count - 1];
}

static double
lookup_recommended_rounds(uint32_t radix, double ell)
{
    const size_t radix_count = sizeof(k_round_radices) / sizeof(k_round_radices[0]);

    if (radix <= k_round_radices[0]) {
        return rounds_for_row(0, ell);
    }
    if (radix >= k_round_radices[radix_count - 1]) {
        return rounds_for_row(radix_count - 1, ell);
    }

    for (size_t i = 1; i < radix_count; i++) {
        uint32_t r_prev = k_round_radices[i - 1];
        uint32_t r_curr = k_round_radices[i];
        if (radix <= r_curr) {
            double rounds_prev = rounds_for_row(i - 1, ell);
            double rounds_curr = rounds_for_row(i, ell);
            double log_prev    = log((double) r_prev);
            double log_curr    = log((double) r_curr);
            double log_radix   = log((double) radix);
            return interpolate(log_radix, log_prev, log_curr, rounds_prev, rounds_curr);
        }
    }

    return rounds_for_row(radix_count - 1, ell);
}

static int
encode_parts(uint8_t **out, size_t *out_len, const prf_part_t *parts, size_t part_count)
{
    if (!out || !out_len || (!parts && part_count > 0)) {
        return -1;
    }

    size_t total = sizeof(uint32_t);
    for (size_t i = 0; i < part_count; i++) {
        total += sizeof(uint32_t) + parts[i].len;
        if (parts[i].len > 0 && !parts[i].data) {
            return -1;
        }
    }

    uint8_t *buffer = malloc(total);
    if (!buffer) {
        return -1;
    }

    uint8_t *cursor = buffer;
    write_u32_be((uint32_t) part_count, cursor);
    cursor += sizeof(uint32_t);

    for (size_t i = 0; i < part_count; i++) {
        write_u32_be((uint32_t) parts[i].len, cursor);
        cursor += sizeof(uint32_t);
        if (parts[i].len > 0) {
            memcpy(cursor, parts[i].data, parts[i].len);
            cursor += parts[i].len;
        }
    }

    *out     = buffer;
    *out_len = total;
    return 0;
}

static int
build_setup1_input(const fast_params_t *params, uint8_t **out, size_t *out_len)
{
    uint8_t a_be[4];
    uint8_t m_be[4];
    write_u32_be(params->radix, a_be);
    write_u32_be(params->sbox_count, m_be);

    prf_part_t parts[] = { { LABEL_INSTANCE1, sizeof(LABEL_INSTANCE1) },
                           { a_be, sizeof(a_be) },
                           { m_be, sizeof(m_be) },
                           { LABEL_FPE_POOL, sizeof(LABEL_FPE_POOL) } };

    return encode_parts(out, out_len, parts, sizeof(parts) / sizeof(parts[0]));
}

static int
build_setup2_input(const fast_params_t *params, const uint8_t *tweak, size_t tweak_len,
                   uint8_t **out, size_t *out_len)
{
    uint8_t a_be[4];
    uint8_t m_be[4];
    uint8_t ell_be[4];
    uint8_t n_be[4];
    uint8_t w_be[4];
    uint8_t wp_be[4];

    write_u32_be(params->radix, a_be);
    write_u32_be(params->sbox_count, m_be);
    write_u32_be(params->word_length, ell_be);
    write_u32_be(params->num_layers, n_be);
    write_u32_be(params->branch_dist1, w_be);
    write_u32_be(params->branch_dist2, wp_be);

    prf_part_t parts[] = { { LABEL_INSTANCE1, sizeof(LABEL_INSTANCE1) },
                           { a_be, sizeof(a_be) },
                           { m_be, sizeof(m_be) },
                           { LABEL_INSTANCE2, sizeof(LABEL_INSTANCE2) },
                           { ell_be, sizeof(ell_be) },
                           { n_be, sizeof(n_be) },
                           { w_be, sizeof(w_be) },
                           { wp_be, sizeof(wp_be) },
                           { LABEL_FPE_SEQ, sizeof(LABEL_FPE_SEQ) },
                           { LABEL_TWEAK, sizeof(LABEL_TWEAK) },
                           { tweak, tweak_len } };

    return encode_parts(out, out_len, parts, sizeof(parts) / sizeof(parts[0]));
}

static int
ensure_sequence(fast_context_t *ctx, const uint8_t *tweak, size_t tweak_len)
{
    if (!ctx) {
        return -1;
    }

    if (ctx->has_cached_seq && ctx->cached_tweak_len == tweak_len) {
        if (tweak_len == 0 ||
            (ctx->cached_tweak && tweak && memcmp(ctx->cached_tweak, tweak, tweak_len) == 0)) {
            return 0;
        }
    }

    uint8_t *input     = NULL;
    size_t   input_len = 0;
    uint8_t  kseq_material[FAST_DERIVED_KEY_SIZE];
    int      status = -1;

    if (build_setup2_input(&ctx->params, tweak, tweak_len, &input, &input_len) != 0) {
        return -1;
    }

    if (prf_derive_key(ctx->master_key, input, input_len, kseq_material, sizeof(kseq_material)) !=
        0) {
        goto cleanup;
    }

    if (fast_generate_sequence(ctx->seq_buffer, ctx->params.num_layers, ctx->params.sbox_count,
                               kseq_material, sizeof(kseq_material)) != 0) {
        goto cleanup;
    }

    uint8_t *new_cache = NULL;
    if (tweak_len > 0) {
        new_cache = malloc(tweak_len);
        if (!new_cache) {
            goto cleanup;
        }
        memcpy(new_cache, tweak, tweak_len);
    }

    free(ctx->cached_tweak);
    ctx->cached_tweak     = new_cache;
    ctx->cached_tweak_len = tweak_len;
    ctx->has_cached_seq   = true;

    status = 0;

cleanup:
    if (input) {
        free(input);
    }
    memset(kseq_material, 0, sizeof(kseq_material));
    if (status != 0 && tweak_len > 0) {
        // new_cache freed by free(ctx->cached_tweak) only on success
        if (ctx->cached_tweak != new_cache) {
            free(new_cache);
        }
    }
    return status;
}

int
calculate_recommended_params(fast_params_t *params, uint32_t radix, uint32_t word_length)
{
    if (!params || radix < 4 || word_length < 2) {
        return -1;
    }

    params->radix          = radix;
    params->word_length    = word_length;
    params->sbox_count     = FAST_SBOX_POOL_SIZE;
    params->security_level = params->security_level ? params->security_level : 128;

    // Branch distances per specification
    uint32_t w_candidate = (uint32_t) ceil(sqrt((double) word_length));
    if (word_length <= 2) {
        params->branch_dist1 = 0;
    } else {
        uint32_t upper       = (word_length > 2) ? (word_length - 2) : 0;
        params->branch_dist1 = (w_candidate < upper) ? w_candidate : upper;
    }
    params->branch_dist2 = (params->branch_dist1 > 1) ? (params->branch_dist1 - 1) : 1;

    double rounds = lookup_recommended_rounds(params->radix, (double) params->word_length);
    if (rounds < 1.0) {
        rounds = 1.0;
    }

    uint32_t rounds_u  = (uint32_t) ceil(rounds);
    params->num_layers = rounds_u * params->word_length;

    return 0;
}

int
fast_init(fast_context_t **ctx, const fast_params_t *params, const uint8_t *key)
{
    if (!ctx || !params || !key) {
        return -1;
    }

    if (params->radix < 4 || params->radix > FAST_MAX_RADIX) {
        return -1;
    }

    if (params->word_length < 2 || params->num_layers == 0 ||
        params->num_layers % params->word_length != 0) {
        return -1;
    }

    if (params->sbox_count == 0) {
        return -1;
    }

    if (params->branch_dist1 > params->word_length - 2) {
        return -1;
    }

    if (params->branch_dist2 == 0 || params->branch_dist2 > params->word_length - 1 ||
        params->branch_dist2 > params->word_length - params->branch_dist1 - 1) {
        return -1;
    }

    fast_context_t *tmp = calloc(1, sizeof(fast_context_t));
    if (!tmp) {
        return -1;
    }

    tmp->params = *params;
    if (tmp->params.security_level == 0) {
        tmp->params.security_level = 128;
    }

    tmp->seq_length = tmp->params.num_layers;
    tmp->seq_buffer = malloc(tmp->seq_length * sizeof(uint32_t));
    if (!tmp->seq_buffer) {
        free(tmp);
        return -1;
    }

    memcpy(tmp->master_key, key, FAST_MASTER_KEY_SIZE);

    uint8_t *setup1_input = NULL;
    size_t   setup1_len   = 0;
    uint8_t  pool_key_material[FAST_DERIVED_KEY_SIZE];

    if (build_setup1_input(&tmp->params, &setup1_input, &setup1_len) != 0) {
        free(tmp->seq_buffer);
        free(tmp);
        return -1;
    }

    if (prf_derive_key(tmp->master_key, setup1_input, setup1_len, pool_key_material,
                       sizeof(pool_key_material)) != 0) {
        free(setup1_input);
        free(tmp->seq_buffer);
        memset(tmp->master_key, 0, sizeof(tmp->master_key));
        free(tmp);
        memset(pool_key_material, 0, sizeof(pool_key_material));
        return -1;
    }

    free(setup1_input);

    tmp->sbox_pool = malloc(sizeof(sbox_pool_t));
    if (!tmp->sbox_pool) {
        memset(pool_key_material, 0, sizeof(pool_key_material));
        free(tmp->seq_buffer);
        memset(tmp->master_key, 0, sizeof(tmp->master_key));
        free(tmp);
        return -1;
    }

    if (fast_generate_sbox_pool(tmp->sbox_pool, tmp->params.sbox_count, tmp->params.radix,
                                pool_key_material, sizeof(pool_key_material)) != 0) {
        memset(pool_key_material, 0, sizeof(pool_key_material));
        free(tmp->sbox_pool);
        free(tmp->seq_buffer);
        memset(tmp->master_key, 0, sizeof(tmp->master_key));
        free(tmp);
        return -1;
    }

    memset(pool_key_material, 0, sizeof(pool_key_material));

    tmp->cached_tweak     = NULL;
    tmp->cached_tweak_len = 0;
    tmp->has_cached_seq   = false;

    *ctx = tmp;
    return 0;
}

void
fast_cleanup(fast_context_t *ctx)
{
    if (!ctx) {
        return;
    }

    if (ctx->sbox_pool) {
        free_sbox_pool(ctx->sbox_pool);
        free(ctx->sbox_pool);
        ctx->sbox_pool = NULL;
    }

    if (ctx->seq_buffer) {
        free(ctx->seq_buffer);
        ctx->seq_buffer = NULL;
    }

    if (ctx->cached_tweak) {
        free(ctx->cached_tweak);
        ctx->cached_tweak = NULL;
    }

    memset(ctx->master_key, 0, sizeof(ctx->master_key));
    memset(&ctx->params, 0, sizeof(fast_params_t));
    free(ctx);
}

int
fast_encrypt(fast_context_t *ctx, const uint8_t *tweak, size_t tweak_len, const uint8_t *plaintext,
             uint8_t *ciphertext, size_t length)
{
    if (!ctx || !plaintext || !ciphertext) {
        return -1;
    }

    if (length != ctx->params.word_length) {
        return -1;
    }

    if (tweak_len > 0 && !tweak) {
        return -1;
    }

    if (ensure_sequence(ctx, tweak, tweak_len) != 0) {
        return -1;
    }

    for (size_t i = 0; i < length; i++) {
        if (plaintext[i] >= ctx->params.radix) {
            return -1;
        }
    }

    fast_cenc(&ctx->params, ctx->sbox_pool, ctx->seq_buffer, plaintext, ciphertext, length);
    return 0;
}

int
fast_decrypt(fast_context_t *ctx, const uint8_t *tweak, size_t tweak_len, const uint8_t *ciphertext,
             uint8_t *plaintext, size_t length)
{
    if (!ctx || !ciphertext || !plaintext) {
        return -1;
    }

    if (length != ctx->params.word_length) {
        return -1;
    }

    if (tweak_len > 0 && !tweak) {
        return -1;
    }

    if (ensure_sequence(ctx, tweak, tweak_len) != 0) {
        return -1;
    }

    for (size_t i = 0; i < length; i++) {
        if (ciphertext[i] >= ctx->params.radix) {
            return -1;
        }
    }

    fast_cdec(&ctx->params, ctx->sbox_pool, ctx->seq_buffer, ciphertext, plaintext, length);
    return 0;
}
