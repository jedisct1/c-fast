#include "fast_internal.h"
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <string.h>

static void
increment_counter(uint8_t *counter)
{
    for (int i = FAST_AES_BLOCK_SIZE - 1; i >= 0; i--) {
        if (++counter[i] != 0) {
            break;
        }
    }
}

int
prng_init(prng_state_t *prng, const uint8_t *key, const uint8_t *nonce)
{
    if (!prng || !key || !nonce) {
        return -1;
    }

    memcpy(prng->key, key, FAST_AES_KEY_SIZE);
    memset(prng->counter, 0, FAST_AES_BLOCK_SIZE);

    if (nonce) {
        memcpy(prng->counter, nonce, FAST_AES_BLOCK_SIZE);
    }

    memset(prng->buffer, 0, FAST_AES_BLOCK_SIZE);
    prng->buffer_pos = FAST_AES_BLOCK_SIZE;

    return 0;
}

static void
aes_encrypt_block(const uint8_t *key, const uint8_t *input, uint8_t *output)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return;

    int len;
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_EncryptUpdate(ctx, output, &len, input, FAST_AES_BLOCK_SIZE);

    EVP_CIPHER_CTX_free(ctx);
}

void
prng_get_bytes(prng_state_t *prng, uint8_t *output, size_t length)
{
    if (!prng || !output || length == 0) {
        return;
    }

    size_t bytes_copied = 0;

    while (bytes_copied < length) {
        if (prng->buffer_pos >= FAST_AES_BLOCK_SIZE) {
            increment_counter(prng->counter);
            aes_encrypt_block(prng->key, prng->counter, prng->buffer);
            prng->buffer_pos = 0;
        }

        size_t available = FAST_AES_BLOCK_SIZE - prng->buffer_pos;
        size_t to_copy = (length - bytes_copied < available) ? (length - bytes_copied) : available;

        memcpy(output + bytes_copied, prng->buffer + prng->buffer_pos, to_copy);
        prng->buffer_pos += to_copy;
        bytes_copied += to_copy;
    }
}

uint32_t
prng_next_u32(prng_state_t *prng)
{
    if (!prng) {
        return 0;
    }

    uint8_t bytes[4];
    prng_get_bytes(prng, bytes, sizeof(bytes));
    return ((uint32_t) bytes[0] << 24) | ((uint32_t) bytes[1] << 16) |
           ((uint32_t) bytes[2] << 8) | ((uint32_t) bytes[3]);
}

uint32_t
prng_uniform(prng_state_t *prng, uint32_t bound)
{
    if (!prng || bound == 0) {
        return 0;
    }

    const uint64_t bound64    = (uint64_t) bound;
    const uint32_t threshold  = (uint32_t) ((0u - bound) % bound);
    uint32_t       r, low;
    uint64_t       product;

    do {
        r        = prng_next_u32(prng);
        product  = (uint64_t) r * bound64;
        low      = (uint32_t) product;
    } while (low < threshold);

    return (uint32_t) (product >> 32);
}

void
prng_cleanup(prng_state_t *prng)
{
    if (!prng) {
        return;
    }

    memset(prng->key, 0, FAST_AES_KEY_SIZE);
    memset(prng->counter, 0, FAST_AES_BLOCK_SIZE);
    memset(prng->buffer, 0, FAST_AES_BLOCK_SIZE);
    prng->buffer_pos = 0;
}

static void
split_key_material(const uint8_t *key_material, uint8_t *key_out,
                   uint8_t *iv_out, bool zeroize_iv_suffix)
{
    memcpy(key_out, key_material, FAST_AES_KEY_SIZE);
    memcpy(iv_out, key_material + FAST_AES_KEY_SIZE, FAST_AES_BLOCK_SIZE);
    if (zeroize_iv_suffix) {
        iv_out[FAST_AES_BLOCK_SIZE - 1] = 0;
        iv_out[FAST_AES_BLOCK_SIZE - 2] = 0;
    }
}

int
fast_generate_sequence(uint32_t *seq, uint32_t seq_length, uint32_t pool_size,
                       const uint8_t *key_material, size_t key_len)
{
    if (!seq || seq_length == 0 || pool_size == 0 || !key_material ||
        key_len < FAST_DERIVED_KEY_SIZE) {
        return -1;
    }

    uint8_t key[FAST_AES_KEY_SIZE];
    uint8_t iv[FAST_AES_BLOCK_SIZE];
    split_key_material(key_material, key, iv, true);

    prng_state_t prng;
    if (prng_init(&prng, key, iv) != 0) {
        memset(key, 0, sizeof(key));
        memset(iv, 0, sizeof(iv));
        return -1;
    }

    for (uint32_t i = 0; i < seq_length; i++) {
        seq[i] = prng_uniform(&prng, pool_size);
    }

    prng_cleanup(&prng);
    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));
    return 0;
}

int
fast_generate_sbox_pool(sbox_pool_t *pool, uint32_t count, uint32_t radix,
                        const uint8_t *key_material, size_t key_len)
{
    if (!pool || !key_material || key_len < FAST_DERIVED_KEY_SIZE) {
        return -1;
    }

    uint8_t key[FAST_AES_KEY_SIZE];
    uint8_t iv[FAST_AES_BLOCK_SIZE];
    split_key_material(key_material, key, iv, false);

    prng_state_t prng;
    if (prng_init(&prng, key, iv) != 0) {
        memset(key, 0, sizeof(key));
        memset(iv, 0, sizeof(iv));
        return -1;
    }

    int ret = generate_sbox_pool(pool, count, radix, &prng);
    prng_cleanup(&prng);
    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));
    return ret;
}
