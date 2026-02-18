/****************************************************************************
 *
 *   Copyright (c) 2024 PX4 Development Team. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name PX4 nor the names of its contributors may be
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 ****************************************************************************/

/**
 * @file stm32h7_crypto.h
 *
 * STM32H7 Hardware Cryptographic Accelerators
 * 
 * Provides hardware-accelerated crypto operations:
 * - SHA256 hashing (via HASH peripheral)
 * - AES encryption/decryption
 * - RNG usage for nonces
 * - Performance optimizations
 */
#ifndef STM32H7_CRYPTO_H
#define STM32H7_CRYPTO_H

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

/* ==================== SHA256 Hardware Acceleration ==================== */

/**
 * @brief Hardware SHA256 context
 */
typedef struct {
	uint32_t state_initialized;
	/* Hardware-specific context (opaque) */
	uint8_t hw_context[256];
} stm32h7_sha256_context_t;

/**
 * @brief Initialize STM32H7 HASH peripheral for SHA256
 * 
 * @return 0 on success, -1 on failure
 */
int stm32h7_hash_init(void);

/**
 * @brief Deinitialize HASH peripheral
 */
void stm32h7_hash_deinit(void);

/**
 * @brief Hardware-accelerated SHA256 calculation
 * 
 * This function uses the STM32H7 HASH peripheral to calculate
 * SHA256 hash significantly faster than software implementation.
 * 
 * Performance: ~10-50x faster than software for large data
 * 
 * @param data Input data to hash
 * @param data_len Length of input data in bytes
 * @param hash Output hash (32 bytes for SHA256)
 * 
 * @return 0 on success, -1 on error
 */
int stm32h7_sha256(const uint8_t *data, uint32_t data_len, uint8_t *hash);

/**
 * @brief Streaming SHA256 hash initialization
 * 
 * For large data processed in chunks
 */
int stm32h7_sha256_start(stm32h7_sha256_context_t *ctx);

/**
 * @brief Update streaming hash
 */
int stm32h7_sha256_update(stm32h7_sha256_context_t *ctx, 
                           const uint8_t *data, 
                           uint32_t data_len);

/**
 * @brief Finalize streaming hash
 */
int stm32h7_sha256_finish(stm32h7_sha256_context_t *ctx, uint8_t *hash);

/* ==================== AES Hardware Acceleration ==================== */

/**
 * @brief AES modes
 */
typedef enum {
	STM32H7_AES_ECB = 0,   /* Electronic Code Book */
	STM32H7_AES_CBC = 1,   /* Cipher Block Chaining */
	STM32H7_AES_CTR = 2,   /* Counter mode */
	STM32H7_AES_GCM = 3,   /* Galois/Counter Mode */
} stm32h7_aes_mode_t;

/**
 * @brief AES key sizes
 */
typedef enum {
	STM32H7_AES_128 = 0,
	STM32H7_AES_192 = 1,
	STM32H7_AES_256 = 2,
} stm32h7_aes_key_size_t;

/**
 * @brief Initialize STM32H7 AES peripheral
 * 
 * @return 0 on success, -1 on failure
 */
int stm32h7_aes_init(void);

/**
 * @brief Deinitialize AES peripheral
 */
void stm32h7_aes_deinit(void);

/**
 * @brief Hardware-accelerated AES encryption
 * 
 * @param mode AES mode
 * @param key_size Key size
 * @param key Encryption key
 * @param iv Initialization vector (for CBC/CTR modes)
 * @param plaintext Input data
 * @param plaintext_len Length of plaintext
 * @param ciphertext Output encrypted data
 * 
 * @return Number of encrypted bytes, or -1 on error
 */
int stm32h7_aes_encrypt(stm32h7_aes_mode_t mode,
                        stm32h7_aes_key_size_t key_size,
                        const uint8_t *key,
                        const uint8_t *iv,
                        const uint8_t *plaintext,
                        uint32_t plaintext_len,
                        uint8_t *ciphertext);

/**
 * @brief Hardware-accelerated AES decryption
 * 
 * @param mode AES mode
 * @param key_size Key size
 * @param key Decryption key
 * @param iv Initialization vector (for CBC/CTR modes)
 * @param ciphertext Input encrypted data
 * @param ciphertext_len Length of ciphertext
 * @param plaintext Output decrypted data
 * 
 * @return Number of decrypted bytes, or -1 on error
 */
int stm32h7_aes_decrypt(stm32h7_aes_mode_t mode,
                        stm32h7_aes_key_size_t key_size,
                        const uint8_t *key,
                        const uint8_t *iv,
                        const uint8_t *ciphertext,
                        uint32_t ciphertext_len,
                        uint8_t *plaintext);

/* ==================== Random Number Generation ==================== */

/**
 * @brief Initialize STM32H7 RNG peripheral
 * 
 * @return 0 on success, -1 on failure
 */
int stm32h7_rng_init(void);

/**
 * @brief Deinitialize RNG peripheral
 */
void stm32h7_rng_deinit(void);

/**
 * @brief Generate random bytes using hardware RNG
 * 
 * Uses the STM32H7 built-in RNG (True Random Number Generator)
 * for cryptographically secure random values.
 * 
 * @param buffer Output buffer
 * @param length Number of random bytes to generate
 * 
 * @return 0 on success, -1 on error
 */
int stm32h7_rng_generate(uint8_t *buffer, uint32_t length);

/* ==================== Initialization and Status ==================== */

/**
 * @brief Initialize all hardware crypto modules
 * 
 * Should be called once during system initialization.
 * 
 * @return 0 if all modules initialized successfully
 *         -1 if any module failed to initialize
 */
int stm32h7_crypto_init(void);

/**
 * @brief Deinitialize all hardware crypto modules
 */
void stm32h7_crypto_deinit(void);

/**
 * @brief Check if hardware crypto is available
 * 
 * @return true if crypto hardware is ready, false otherwise
 */
bool stm32h7_crypto_is_available(void);

/**
 * @brief Get crypto hardware capabilities
 * 
 * @return Bitmask of available features:
 *         Bit 0: SHA256 support
 *         Bit 1: AES support
 *         Bit 2: RNG support
 */
uint32_t stm32h7_crypto_get_capabilities(void);

/* ==================== Performance Benchmarks ==================== */

/**
 * @brief Performance metrics for crypto operations
 */
typedef struct {
	uint32_t sha256_1kb_ms;      /* Time to hash 1KB in milliseconds */
	uint32_t sha256_1mb_ms;      /* Time to hash 1MB */
	uint32_t aes_encrypt_1kb_ms; /* Time to encrypt 1KB */
	uint32_t aes_decrypt_1kb_ms; /* Time to decrypt 1KB */
	uint32_t rng_bytes_per_sec;  /* RNG throughput */
} stm32h7_crypto_perf_t;

/**
 * @brief Get crypto performance characteristics
 * 
 * @param perf Pointer to performance structure
 * 
 * @return 0 if benchmark data available
 */
int stm32h7_crypto_get_performance(stm32h7_crypto_perf_t *perf);

#endif /* STM32H7_CRYPTO_H */
