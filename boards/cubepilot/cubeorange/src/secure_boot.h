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
 * @file secure_boot.h
 *
 * Secure Boot Implementation for CubeOrange (STM32H7)
 * 
 * Features:
 * - Firmware signature verification using RSA-3072 or ECDSA
 * - Secure storage of public keys in OTP/Flash
 * - Bootloader integrity checking
 * - IEC 62443-4-1 compliant security mechanisms
 */
#ifndef SECURE_BOOT_H
#define SECURE_BOOT_H

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

/* Secure Boot Configuration */
#define SECURE_BOOT_ENABLED              1
#define SECURE_BOOT_SIGNATURE_TYPE       SECURE_BOOT_SIG_ECDSA  /* or SECURE_BOOT_SIG_RSA */
#define SECURE_BOOT_KEY_SIZE             256                     /* bits for ECDSA P-256 */

/* Signature Types */
#define SECURE_BOOT_SIG_RSA              0
#define SECURE_BOOT_SIG_ECDSA            1

/* Hash Algorithm */
#define SECURE_BOOT_HASH_SIZE            32  /* SHA256 */
#define SECURE_BOOT_HASH_ALGO            "SHA256"

/* Firmware version encoding: [major:16][minor:8][patch:8] */
#define SECURE_BOOT_FW_VERSION_ENCODE(major, minor, patch) \
	((((uint32_t)(major) & 0xFFFFU) << 16) | (((uint32_t)(minor) & 0xFFU) << 8) | ((uint32_t)(patch) & 0xFFU))

/* Anti-rollback policy for signed firmware metadata version */
#define SECURE_BOOT_MIN_FW_VERSION_MAJOR 1000U
#define SECURE_BOOT_MIN_FW_VERSION_MINOR 0U
#define SECURE_BOOT_MIN_FW_VERSION_PATCH 0U
#define SECURE_BOOT_MIN_FW_VERSION SECURE_BOOT_FW_VERSION_ENCODE(SECURE_BOOT_MIN_FW_VERSION_MAJOR, \
		SECURE_BOOT_MIN_FW_VERSION_MINOR, \
		SECURE_BOOT_MIN_FW_VERSION_PATCH)

/* ECDSA P-256 Signature */
#define ECDSA_P256_SIGNATURE_SIZE        64  /* 2 x 32 bytes for R and S */
#define ECDSA_P256_PUBLIC_KEY_SIZE       64  /* 2 x 32 bytes for X and Y coordinates */

/* RSA-3072 Signature */
#define RSA3072_SIGNATURE_SIZE           384 /* 3072 bits / 8 */
#define RSA3072_PUBLIC_KEY_SIZE          384

/* Firmware Metadata Structure */
typedef struct {
	uint32_t magic;                          /* Magic number: 0x53424F4F (SBOOT) */
	uint16_t version;                        /* Metadata version */
	uint16_t flags;                          /* Security flags */
	uint32_t firmware_size;                  /* Size of firmware without signature */
	uint32_t firmware_crc32;                 /* CRC32 of firmware for quick check */
	uint8_t  hash[SECURE_BOOT_HASH_SIZE];   /* SHA256 hash of firmware */
	uint8_t  signature[ECDSA_P256_SIGNATURE_SIZE]; /* Signature (ECDSA P-256) */
	uint8_t  signing_key_index;              /* Index of signing key used */
	uint8_t  reserved[7];                    /* Reserved for future use */
} firmware_metadata_t;

/* Return codes */
typedef enum {
	SECURE_BOOT_OK                   = 0x00,
	SECURE_BOOT_ERR_INVALID_MAGIC    = 0x01,
	SECURE_BOOT_ERR_INVALID_VERSION  = 0x02,
	SECURE_BOOT_ERR_INVALID_CRC      = 0x03,
	SECURE_BOOT_ERR_HASH_MISMATCH    = 0x04,
	SECURE_BOOT_ERR_SIGNATURE_INVALID = 0x05,
	SECURE_BOOT_ERR_KEY_NOT_FOUND    = 0x06,
	SECURE_BOOT_ERR_MEMORY           = 0x07,
	SECURE_BOOT_ERR_HARDWARE         = 0x08,
	SECURE_BOOT_ERR_TIMEOUT          = 0x09,
	SECURE_BOOT_ERR_ROLLBACK         = 0x0A,
	SECURE_BOOT_ERR_UNKNOWN          = 0xFF
} secure_boot_result_t;

/* Public Key Storage */
typedef struct {
	uint8_t index;                           /* Key index (0-4) */
	uint8_t key_type;                        /* ECDSA or RSA */
	uint32_t timestamp;                      /* When key was added (Unix timestamp) */
	uint8_t  public_key[ECDSA_P256_PUBLIC_KEY_SIZE]; /* ECDSA P-256 public key */
	uint16_t crc16;                          /* CRC16 for key integrity */
} secure_boot_public_key_t;

/* Secure Boot Status */
typedef struct {
	bool secure_boot_enabled;
	bool firmware_validated;
	secure_boot_result_t last_error;
	uint32_t total_verifications;
	uint32_t failed_verifications;
	uint32_t last_verification_time_ms;
} secure_boot_status_t;

/* ==================== Public API ==================== */

/**
 * @brief Initialize secure boot subsystem
 * 
 * @return SECURE_BOOT_OK on success, error code otherwise
 */
secure_boot_result_t secure_boot_init(void);

/**
 * @brief Verify firmware integrity and signature
 * 
 * @param firmware_address Start address of firmware in flash
 * @param firmware_size    Size of firmware to verify
 * @param metadata         Pointer to firmware metadata structure
 * 
 * @return SECURE_BOOT_OK if verification passes, error code otherwise
 */
secure_boot_result_t secure_boot_verify_firmware(uintptr_t firmware_address,
                                                  uint32_t firmware_size,
                                                  const firmware_metadata_t *metadata);

/**
 * @brief Calculate SHA256 hash of firmware
 * 
 * @param firmware_address Start address of firmware
 * @param firmware_size    Size of firmware to hash
 * @param hash             Output buffer (must be SECURE_BOOT_HASH_SIZE bytes)
 * 
 * @return SECURE_BOOT_OK on success
 */
secure_boot_result_t secure_boot_calculate_hash(uintptr_t firmware_address,
                                                 uint32_t firmware_size,
                                                 uint8_t *hash);

/**
 * @brief Verify ECDSA P-256 signature
 * 
 * @param hash             SHA256 hash of data
 * @param signature        ECDSA signature (R || S)
 * @param public_key       ECDSA public key (X || Y)
 * 
 * @return SECURE_BOOT_OK if signature is valid
 */
secure_boot_result_t secure_boot_verify_signature(const uint8_t *hash,
                                                   const uint8_t *signature,
                                                   const uint8_t *public_key);

/**
 * @brief Load public key from secure storage
 * 
 * @param key_index Index of key to load (0-4)
 * @param key       Output buffer for public key
 * 
 * @return SECURE_BOOT_OK on success
 */
secure_boot_result_t secure_boot_load_public_key(uint8_t key_index,
                                                  secure_boot_public_key_t *key);

/**
 * @brief Store public key in secure storage
 * 
 * @param key_index Index where to store (0-4)
 * @param key       Public key to store
 * 
 * @return SECURE_BOOT_OK on success
 */
secure_boot_result_t secure_boot_store_public_key(uint8_t key_index,
                                                   const secure_boot_public_key_t *key);

/**
 * @brief Get secure boot status
 * 
 * @param status Pointer to status structure
 * 
 * @return SECURE_BOOT_OK on success
 */
secure_boot_result_t secure_boot_get_status(secure_boot_status_t *status);

/**
 * @brief Reset secure boot statistics
 * 
 * @return SECURE_BOOT_OK on success
 */
secure_boot_result_t secure_boot_reset_stats(void);

/**
 * @brief Enable/disable secure boot lockdown (irreversible)
 * 
 * @return SECURE_BOOT_OK on success
 */
secure_boot_result_t secure_boot_lockdown(void);

/**
 * @brief Verify bootloader integrity
 * 
 * @return SECURE_BOOT_OK if bootloader is valid
 */
secure_boot_result_t secure_boot_verify_bootloader(void);

/**
 * @brief Get the secure boot error string
 * 
 * @param error Error code
 * @return String describing the error
 */
const char* secure_boot_strerror(secure_boot_result_t error);

#endif /* SECURE_BOOT_H */
