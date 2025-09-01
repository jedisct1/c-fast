#include "fast.h"
#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

static void increment_counter(uint8_t *counter) {
    for (int i = FAST_AES_BLOCK_SIZE - 1; i >= 0; i--) {
        if (++counter[i] != 0) {
            break;
        }
    }
}

int prng_init(prng_state_t *prng, const uint8_t *key, const uint8_t *nonce) {
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

static void aes_encrypt_block(const uint8_t *key, const uint8_t *input, uint8_t *output) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return;
    
    int len;
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_EncryptUpdate(ctx, output, &len, input, FAST_AES_BLOCK_SIZE);
    
    EVP_CIPHER_CTX_free(ctx);
}

void prng_get_bytes(prng_state_t *prng, uint8_t *output, size_t length) {
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
        size_t to_copy = (length - bytes_copied < available) ? 
                        (length - bytes_copied) : available;
        
        memcpy(output + bytes_copied, prng->buffer + prng->buffer_pos, to_copy);
        prng->buffer_pos += to_copy;
        bytes_copied += to_copy;
    }
}

uint32_t prng_get_uint32(prng_state_t *prng, uint32_t max) {
    if (!prng || max == 0) {
        return 0;
    }
    
    if (max == 1) {
        return 0;
    }
    
    uint32_t mask = 0xFFFFFFFF;
    uint32_t top = max - 1;
    while (top < (mask >> 1)) {
        mask >>= 1;
    }
    
    uint32_t result;
    do {
        uint8_t bytes[4];
        prng_get_bytes(prng, bytes, 4);
        result = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
        result &= mask;
    } while (result >= max);
    
    return result;
}

void prng_cleanup(prng_state_t *prng) {
    if (!prng) {
        return;
    }
    
    memset(prng->key, 0, FAST_AES_KEY_SIZE);
    memset(prng->counter, 0, FAST_AES_BLOCK_SIZE);
    memset(prng->buffer, 0, FAST_AES_BLOCK_SIZE);
    prng->buffer_pos = 0;
}