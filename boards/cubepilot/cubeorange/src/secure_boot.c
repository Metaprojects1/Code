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
 * @file secure_boot.c
 *
 * Secure Boot Implementation for CubeOrange
 * Implements firmware signature verification and integrity checking
 */

#include "secure_boot.h"
#include "stm32h7_crypto.h"
#include <string.h>

#ifdef PX4_CRYPTO
#include <tomcrypt.h>
extern void libtomcrypt_init(void);
#endif

/* Firmware Metadata Magic */
#define FIRMWARE_METADATA_MAGIC     0x53424F4F  /* "SBOOT" */
#define FIRMWARE_METADATA_VERSION   0x0100      /* Version 1.0 */

/* Secure Boot Configuration Storage Addresses (STM32H7 Flash) */
#define SECURE_BOOT_CONFIG_BASE     0x08000000  /* Base of flash */
#define SECURE_BOOT_KEY_STORAGE     0x081F0000  /* Last sector before backup */
#define SECURE_BOOT_STATE_STORAGE   0x081F1000  /* State storage */

/* Maximum number of stored public keys */
#define MAX_PUBLIC_KEYS             5

/* Static storage for boot status */
static secure_boot_status_t g_secure_boot_status = {
	.secure_boot_enabled = SECURE_BOOT_ENABLED,
	.firmware_validated = false,
	.last_error = SECURE_BOOT_OK,
	.total_verifications = 0,
	.failed_verifications = 0,
	.last_verification_time_ms = 0
};

/* ==================== Helper Functions ==================== */

/**
 * @brief Calculate CRC32 checksum
 */
static uint32_t crc32_calculate(const uint8_t *data, uint32_t length)
{
	uint32_t crc = 0xFFFFFFFFU;

	for (uint32_t i = 0; i < length; i++) {
		crc = crc ^ data[i];
		for (int j = 0; j < 8; j++) {
			crc = (crc >> 1) ^ ((crc & 1) ? 0xEDB88320 : 0);
		}
	}

	return crc ^ 0xFFFFFFFFU;
}

/**
 * @brief Calculate CRC16 checksum for key integrity
 */
static uint16_t __attribute__((unused)) crc16_calculate(const uint8_t *data, uint32_t length)
{
	uint16_t crc = 0;

	for (uint32_t i = 0; i < length; i++) {
		crc = (crc >> 8) | ((crc & 0xFF) << 8);
		crc ^= data[i];
		crc ^= (crc & 0xFF) >> 4;
		crc ^= (crc << 8) << 4;
		crc ^= ((crc & 0xFF) << 4) << 1;
	}

	return crc;
}

static uint32_t metadata_get_firmware_version(const firmware_metadata_t *metadata)
{
	uint32_t firmware_version = 0;

	if (!metadata) {
		return 0;
	}

	memcpy(&firmware_version, metadata->reserved, sizeof(firmware_version));
	return firmware_version;
}

/**
 * @brief Simple SHA256 implementation with hardware acceleration
 * Uses STM32H7 HASH peripheral when available for 10-50x speedup
 */
static secure_boot_result_t sha256_hash(const uint8_t *data, 
                                        uint32_t data_len,
                                        uint8_t *hash)
{
	if (!data || !hash) {
		return SECURE_BOOT_ERR_MEMORY;
	}

	/* Try hardware acceleration first */
	if (stm32h7_crypto_is_available()) {
		if (stm32h7_sha256(data, data_len, hash) == 0) {
			return SECURE_BOOT_OK;
		}
	}

	/* Fallback to software SHA256 implementation from libtomcrypt. */
#ifdef PX4_CRYPTO
	hash_state md;

	if (sha256_init(&md) != CRYPT_OK) {
		return SECURE_BOOT_ERR_HARDWARE;
	}

	if (sha256_process(&md, data, data_len) != CRYPT_OK) {
		return SECURE_BOOT_ERR_HARDWARE;
	}

	if (sha256_done(&md, hash) != CRYPT_OK) {
		return SECURE_BOOT_ERR_HARDWARE;
	}

	return SECURE_BOOT_OK;
#else
	return SECURE_BOOT_ERR_HARDWARE;
#endif
}

/**
 * @brief ECDSA P-256 signature verification
 */
static secure_boot_result_t ecdsa_p256_verify(const uint8_t *hash,
                                               const uint8_t *signature,
                                               const uint8_t *public_key)
{
	if (!hash || !signature || !public_key) {
		return SECURE_BOOT_ERR_MEMORY;
	}

#ifdef PX4_CRYPTO
	const ltc_ecc_curve *curve = NULL;
	ecc_key key;
	uint8_t public_key_x963[1 + ECDSA_P256_PUBLIC_KEY_SIZE];
	int verify_status = 0;
	int ltc_result;
	bool key_imported = false;

	memset(&key, 0, sizeof(key));

	ltc_result = ecc_find_curve("secp256r1", &curve);

	if (ltc_result != CRYPT_OK || curve == NULL) {
		return SECURE_BOOT_ERR_HARDWARE;
	}

	public_key_x963[0] = 0x04; /* uncompressed point */
	memcpy(&public_key_x963[1], public_key, ECDSA_P256_PUBLIC_KEY_SIZE);

	ltc_result = ecc_ansi_x963_import_ex(public_key_x963, sizeof(public_key_x963), &key, curve);

	if (ltc_result != CRYPT_OK) {
		return SECURE_BOOT_ERR_SIGNATURE_INVALID;
	}

	key_imported = true;

	ltc_result = ecc_verify_hash_ex(signature, ECDSA_P256_SIGNATURE_SIZE,
					hash, SECURE_BOOT_HASH_SIZE,
					LTC_ECCSIG_RFC7518,
					&verify_status, &key);

	if (key_imported) {
		ecc_free(&key);
	}

	if (ltc_result != CRYPT_OK || verify_status != 1) {
		return SECURE_BOOT_ERR_SIGNATURE_INVALID;
	}

	return SECURE_BOOT_OK;
#else
	return SECURE_BOOT_ERR_HARDWARE;
#endif
}

/* ==================== Public API Implementation ==================== */

secure_boot_result_t secure_boot_init(void)
{
	/* Initialize secure boot subsystem */
	g_secure_boot_status.secure_boot_enabled = SECURE_BOOT_ENABLED;
	g_secure_boot_status.firmware_validated = false;
	g_secure_boot_status.last_error = SECURE_BOOT_OK;

#ifdef PX4_CRYPTO
	libtomcrypt_init();
#endif

	/* Initialize hardware crypto modules */
	if (stm32h7_crypto_init() == 0) {
		/* Hardware crypto available - performance optimized */
#ifdef DEBUG
		/* printf("CRYPTO: Hardware crypto initialized\n"); */
#endif
	} else {
		/* Hardware crypto not available - will fall back to software */
#ifdef DEBUG
		/* printf("CRYPTO: Hardware crypto initialization failed, using software fallback\n"); */
#endif
	}

	return SECURE_BOOT_OK;
}

secure_boot_result_t secure_boot_verify_firmware(uintptr_t firmware_address,
                                                  uint32_t firmware_size,
                                                  const firmware_metadata_t *metadata)
{
	if (!metadata) {
		return SECURE_BOOT_ERR_MEMORY;
	}

	/* Verify metadata magic */
	if (metadata->magic != FIRMWARE_METADATA_MAGIC) {
		g_secure_boot_status.last_error = SECURE_BOOT_ERR_INVALID_MAGIC;
		g_secure_boot_status.failed_verifications++;
		return SECURE_BOOT_ERR_INVALID_MAGIC;
	}

	/* Verify metadata version */
	if ((metadata->version & 0xFF00) != 0x0100) {
		g_secure_boot_status.last_error = SECURE_BOOT_ERR_INVALID_VERSION;
		g_secure_boot_status.failed_verifications++;
		return SECURE_BOOT_ERR_INVALID_VERSION;
	}

	/* Enforce anti-rollback minimum firmware version from metadata. */
	if (metadata_get_firmware_version(metadata) < SECURE_BOOT_MIN_FW_VERSION) {
		g_secure_boot_status.last_error = SECURE_BOOT_ERR_ROLLBACK;
		g_secure_boot_status.failed_verifications++;
		return SECURE_BOOT_ERR_ROLLBACK;
	}

	/* Verify firmware size doesn't exceed limit */
	if (firmware_size != metadata->firmware_size) {
		g_secure_boot_status.last_error = SECURE_BOOT_ERR_INVALID_CRC;
		g_secure_boot_status.failed_verifications++;
		return SECURE_BOOT_ERR_INVALID_CRC;
	}

	/* Calculate CRC32 of firmware */
	uint32_t calculated_crc = crc32_calculate((const uint8_t *)firmware_address, firmware_size);
	if (calculated_crc != metadata->firmware_crc32) {
		g_secure_boot_status.last_error = SECURE_BOOT_ERR_INVALID_CRC;
		g_secure_boot_status.failed_verifications++;
		return SECURE_BOOT_ERR_INVALID_CRC;
	}

	/* Calculate SHA256 hash */
	uint8_t calculated_hash[SECURE_BOOT_HASH_SIZE];
	secure_boot_result_t hash_result = sha256_hash((const uint8_t *)firmware_address,
	                                                 firmware_size,
	                                                 calculated_hash);
	if (hash_result != SECURE_BOOT_OK) {
		g_secure_boot_status.last_error = hash_result;
		g_secure_boot_status.failed_verifications++;
		return hash_result;
	}

	/* Verify hash matches */
	if (memcmp(calculated_hash, metadata->hash, SECURE_BOOT_HASH_SIZE) != 0) {
		g_secure_boot_status.last_error = SECURE_BOOT_ERR_HASH_MISMATCH;
		g_secure_boot_status.failed_verifications++;
		return SECURE_BOOT_ERR_HASH_MISMATCH;
	}

	/* Load public key for signature verification */
	secure_boot_public_key_t public_key;
	secure_boot_result_t key_result = secure_boot_load_public_key(metadata->signing_key_index, 
	                                                                &public_key);
	if (key_result != SECURE_BOOT_OK) {
		g_secure_boot_status.last_error = SECURE_BOOT_ERR_KEY_NOT_FOUND;
		g_secure_boot_status.failed_verifications++;
		return SECURE_BOOT_ERR_KEY_NOT_FOUND;
	}

	/* Verify signature */
	secure_boot_result_t sig_result = ecdsa_p256_verify(calculated_hash,
	                                                       metadata->signature,
	                                                       public_key.public_key);
	if (sig_result != SECURE_BOOT_OK) {
		g_secure_boot_status.last_error = SECURE_BOOT_ERR_SIGNATURE_INVALID;
		g_secure_boot_status.failed_verifications++;
		return SECURE_BOOT_ERR_SIGNATURE_INVALID;
	}

	/* All checks passed */
	g_secure_boot_status.firmware_validated = true;
	g_secure_boot_status.total_verifications++;
	g_secure_boot_status.last_error = SECURE_BOOT_OK;

	return SECURE_BOOT_OK;
}

secure_boot_result_t secure_boot_calculate_hash(uintptr_t firmware_address,
                                                 uint32_t firmware_size,
                                                 uint8_t *hash)
{
	if (!hash) {
		return SECURE_BOOT_ERR_MEMORY;
	}

	return sha256_hash((const uint8_t *)firmware_address, firmware_size, hash);
}

secure_boot_result_t secure_boot_verify_signature(const uint8_t *hash,
                                                   const uint8_t *signature,
                                                   const uint8_t *public_key)
{
	return ecdsa_p256_verify(hash, signature, public_key);
}

secure_boot_result_t secure_boot_load_public_key(uint8_t key_index,
                                                  secure_boot_public_key_t *key)
{
	if (!key || key_index >= MAX_PUBLIC_KEYS) {
		return SECURE_BOOT_ERR_INVALID_VERSION;
	}

	/* TODO: Load key from secure storage (STM32H7 flash or OTP)
	 * For now, return placeholder
	 */
	memset(key, 0, sizeof(secure_boot_public_key_t));
	key->index = key_index;
	key->key_type = SECURE_BOOT_SIGNATURE_TYPE;

	/* Validate CRC if we ever populate a real key */
	if (key->crc16) {
		uint16_t crc = crc16_calculate(key->public_key, ECDSA_P256_PUBLIC_KEY_SIZE);
		if (crc != key->crc16) {
			return SECURE_BOOT_ERR_INVALID_CRC;
		}
	}

	return SECURE_BOOT_OK;
}

secure_boot_result_t secure_boot_store_public_key(uint8_t key_index,
                                                   const secure_boot_public_key_t *key)
{
	if (!key || key_index >= MAX_PUBLIC_KEYS) {
		return SECURE_BOOT_ERR_INVALID_VERSION;
	}

	/* Calculate CRC16 over the public key bytes for integrity */
	uint16_t crc = crc16_calculate(key->public_key, ECDSA_P256_PUBLIC_KEY_SIZE);

	/* TODO: Store key + crc in secure storage with redundancy and rollback protection */
	(void)crc;

	return SECURE_BOOT_OK;
}

secure_boot_result_t secure_boot_get_status(secure_boot_status_t *status)
{
	if (!status) {
		return SECURE_BOOT_ERR_MEMORY;
	}

	memcpy(status, &g_secure_boot_status, sizeof(secure_boot_status_t));
	return SECURE_BOOT_OK;
}

secure_boot_result_t secure_boot_reset_stats(void)
{
	g_secure_boot_status.total_verifications = 0;
	g_secure_boot_status.failed_verifications = 0;
	g_secure_boot_status.last_verification_time_ms = 0;
	return SECURE_BOOT_OK;
}

secure_boot_result_t secure_boot_lockdown(void)
{
	/* TODO: Implement irreversible secure boot lockdown
	 * - Disable debug ports (JTAG/SWD)
	 * - Lock OTP/secure regions
	 * - Disable firmware updates without secure bootloader
	 * - Set tamper protection bits
	 */

	return SECURE_BOOT_OK;
}

secure_boot_result_t secure_boot_verify_bootloader(void)
{
	/* TODO: Verify bootloader integrity
	 * - Calculate hash of bootloader code
	 * - Compare with stored reference
	 * - Detect unauthorized modifications
	 */

	return SECURE_BOOT_OK;
}

const char* secure_boot_strerror(secure_boot_result_t error)
{
	switch (error) {
	case SECURE_BOOT_OK:
		return "OK";
	case SECURE_BOOT_ERR_INVALID_MAGIC:
		return "Invalid firmware metadata magic";
	case SECURE_BOOT_ERR_INVALID_VERSION:
		return "Invalid metadata version";
	case SECURE_BOOT_ERR_INVALID_CRC:
		return "CRC check failed";
	case SECURE_BOOT_ERR_HASH_MISMATCH:
		return "Hash mismatch";
	case SECURE_BOOT_ERR_SIGNATURE_INVALID:
		return "Invalid signature";
	case SECURE_BOOT_ERR_KEY_NOT_FOUND:
		return "Public key not found";
	case SECURE_BOOT_ERR_MEMORY:
		return "Memory error";
	case SECURE_BOOT_ERR_HARDWARE:
		return "Hardware error";
	case SECURE_BOOT_ERR_TIMEOUT:
		return "Operation timeout";
	case SECURE_BOOT_ERR_ROLLBACK:
		return "Firmware version below rollback minimum";
	default:
		return "Unknown error";
	}
}
