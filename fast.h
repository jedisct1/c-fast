#ifndef FAST_H
#define FAST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Public constants
#define FAST_MAX_RADIX      256
#define FAST_SBOX_POOL_SIZE 256
#define FAST_AES_BLOCK_SIZE 16
#define FAST_AES_KEY_SIZE   16

// Public parameter structure
typedef struct {
    uint32_t radix; // a: radix (must be >= 4)
    uint32_t word_length; // ℓ: length of plaintext/ciphertext words
    uint32_t sbox_count; // m: number of S-boxes in pool (typically 256)
    uint32_t num_layers; // n: number of SPN layers
    uint32_t branch_dist1; // w: branch distance for first part
    uint32_t branch_dist2; // w': branch distance for second part
    uint32_t security_level; // s: targeted security in bits (default 128)
} fast_params_t;

// Opaque context structure for public API
typedef struct fast_context fast_context_t;

// Public API functions

/**
 * Initialize a FAST cipher context with specified parameters
 *
 * Creates and initializes a FAST cipher context for format-preserving encryption
 * with the given parameters and master key. The context must be freed using
 * fast_cleanup() when no longer needed.
 *
 * @param ctx    Pointer to context pointer (will be allocated)
 * @param params Cipher parameters including radix, word length, and security settings
 * @param key    Master key of FAST_AES_KEY_SIZE (16) bytes
 * @return       0 on success, -1 on error (invalid parameters or allocation failure)
 */
int fast_init(fast_context_t **ctx, const fast_params_t *params, const uint8_t *key);

/**
 * Clean up and free a FAST cipher context
 *
 * Releases all resources associated with the context including S-box pools,
 * cached tweaks, and internal buffers. The context pointer becomes invalid
 * after this call.
 *
 * @param ctx Context to clean up (can be NULL)
 */
void fast_cleanup(fast_context_t *ctx);

/**
 * Encrypt data using the FAST cipher
 *
 * Performs format-preserving encryption on the input plaintext using the
 * initialized context and optional tweak. The plaintext and ciphertext
 * must be arrays of bytes in the range [0, radix-1].
 *
 * @param ctx        Initialized FAST context
 * @param tweak      Optional domain separation tweak (can be NULL)
 * @param tweak_len  Length of tweak in bytes (0 if tweak is NULL)
 * @param plaintext  Input plaintext array (values must be < radix)
 * @param ciphertext Output ciphertext array (must have same length as plaintext)
 * @param length     Length of plaintext/ciphertext arrays in bytes
 * @return          0 on success, -1 on error (invalid parameters or values)
 */
int fast_encrypt(fast_context_t *ctx, const uint8_t *tweak, size_t tweak_len,
                 const uint8_t *plaintext, uint8_t *ciphertext, size_t length);

/**
 * Decrypt data using the FAST cipher
 *
 * Performs format-preserving decryption on the input ciphertext using the
 * initialized context and optional tweak. The ciphertext and plaintext
 * must be arrays of bytes in the range [0, radix-1].
 *
 * @param ctx        Initialized FAST context
 * @param tweak      Optional domain separation tweak (must match encryption tweak)
 * @param tweak_len  Length of tweak in bytes (0 if tweak is NULL)
 * @param ciphertext Input ciphertext array (values must be < radix)
 * @param plaintext  Output plaintext array (must have same length as ciphertext)
 * @param length     Length of ciphertext/plaintext arrays in bytes
 * @return          0 on success, -1 on error (invalid parameters or values)
 */
int fast_decrypt(fast_context_t *ctx, const uint8_t *tweak, size_t tweak_len,
                 const uint8_t *ciphertext, uint8_t *plaintext, size_t length);

/**
 * Calculate recommended parameters for FAST cipher
 *
 * Determines optimal security parameters (number of layers, branch distances)
 * based on the specified radix and word length. Uses pre-computed lookup
 * tables with logarithmic interpolation for radix values not in the table.
 *
 * @param params      Output parameter structure to fill
 * @param radix       Desired radix (base) for the cipher, must be in [4, 256]
 * @param word_length Length of words to encrypt/decrypt
 * @return           0 on success, -1 on error (invalid radix or word length)
 */
int calculate_recommended_params(fast_params_t *params, uint32_t radix, uint32_t word_length);

#endif // FAST_H
