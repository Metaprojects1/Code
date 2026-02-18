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
 * @file secure_boot_integration.c
 *
 * Integration of Secure Boot with CubeOrange Bootloader
 * Validates firmware before jumping to application
 */

#include "secure_boot.h"
#include "secure_boot_audit.h"
#include "hw_config.h"
#include "bl.h"
#include <stdint.h>
#include <stdbool.h>

/* Application firmware location constants */
#define APP_FIRMWARE_BASE           APP_LOAD_ADDRESS
#define FIRMWARE_METADATA_MAGIC     0x53424F4FU  /* "SBOOT" */
#define FIRMWARE_METADATA_VERSION   0x0100U      /* Version 1.x */

/* Secure boot integration structure */
typedef struct {
	bool initialized;
	bool fw_verified;
	bool boot_allowed;
	uint32_t last_error;
} secure_boot_integration_t;

static secure_boot_integration_t g_sb_integration = {
	.initialized = false,
	.fw_verified = false,
	.boot_allowed = false,
	.last_error = 0
};

/**
 * @brief Read firmware metadata from flash
 */
static bool read_firmware_metadata(uintptr_t metadata_address, 
                                    firmware_metadata_t *metadata)
{
	if (!metadata) {
		return false;
	}

	/* Read metadata from flash directly */
	const firmware_metadata_t *flash_metadata = (const firmware_metadata_t *)metadata_address;
	
	/* Copy metadata to RAM */
	*metadata = *flash_metadata;

	return true;
}

static bool metadata_header_valid(const firmware_metadata_t *metadata)
{
	if (!metadata) {
		return false;
	}

	return metadata->magic == FIRMWARE_METADATA_MAGIC
	       && (metadata->version & 0xFF00U) == FIRMWARE_METADATA_VERSION;
}

static bool metadata_size_valid(const firmware_metadata_t *metadata, uint32_t firmware_region_size)
{
	const uint32_t metadata_size = (uint32_t)sizeof(firmware_metadata_t);

	if (!metadata || firmware_region_size <= metadata_size) {
		return false;
	}

	return metadata->firmware_size > 0
	       && metadata->firmware_size <= (firmware_region_size - metadata_size);
}

/*
 * Metadata can be provisioned in two layouts:
 * 1) fixed slot at end of firmware region
 * 2) appended directly after firmware payload
 */
static bool locate_firmware_metadata(uintptr_t firmware_base,
				     uint32_t firmware_region_size,
				     firmware_metadata_t *metadata,
				     uintptr_t *metadata_address)
{
	const uint32_t metadata_size = (uint32_t)sizeof(firmware_metadata_t);
	const uintptr_t fixed_metadata_address = firmware_base + firmware_region_size - metadata_size;
	firmware_metadata_t candidate;

	if (!metadata || !metadata_address || firmware_region_size <= metadata_size) {
		return false;
	}

	if (read_firmware_metadata(fixed_metadata_address, &candidate)
	    && metadata_header_valid(&candidate)) {
		*metadata = candidate;
		*metadata_address = fixed_metadata_address;
		return true;
	}

	for (uint32_t offset = 0; offset <= (firmware_region_size - metadata_size); offset += sizeof(uint32_t)) {
		const uintptr_t candidate_address = firmware_base + offset;
		const uint32_t magic = *(const uint32_t *)candidate_address;

		if (magic != FIRMWARE_METADATA_MAGIC) {
			continue;
		}

		if (!read_firmware_metadata(candidate_address, &candidate)
		    || !metadata_header_valid(&candidate)
		    || !metadata_size_valid(&candidate, firmware_region_size)) {
			continue;
		}

		/* Appended metadata must start exactly at firmware_base + firmware_size. */
		if ((firmware_base + candidate.firmware_size) != candidate_address) {
			continue;
		}

		*metadata = candidate;
		*metadata_address = candidate_address;
		return true;
	}

	return false;
}

/**
 * @brief Print secure boot status to console
 */
static void print_secure_boot_status(const char *prefix, secure_boot_result_t result)
{
	(void)prefix;
	(void)result;

	/* TODO: Implement UART output for debugging
	 * This would typically use printf or custom UART routines
	 */
}

/* ==================== Bootloader Integration ==================== */

/**
 * @brief Initialize secure boot during bootloader startup
 * Call this from bootloader_main()
 */
void secure_boot_bootloader_init(void)
{
	if (g_sb_integration.initialized) {
		return;
	}

	/* Initialize secure boot subsystem */
	secure_boot_result_t init_result = secure_boot_init();
	
	if (init_result != SECURE_BOOT_OK) {
		print_secure_boot_status("ERROR: Secure boot init failed: ", init_result);
		g_sb_integration.last_error = init_result;
		return;
	}

	g_sb_integration.initialized = true;
#ifdef DEBUG
	print_secure_boot_status("INFO: Secure boot initialized: ", SECURE_BOOT_OK);
#endif
}

/**
 * @brief Verify firmware before jumping to application
 * Call this before jump_to_app() in bootloader
 * 
 * @return true if firmware verification passed and boot is allowed
 */
bool secure_boot_verify_application(void)
{
	const uint32_t firmware_region_size = board_info.fw_size;
	const uint32_t metadata_size = (uint32_t)sizeof(firmware_metadata_t);
	const uintptr_t firmware_base = APP_FIRMWARE_BASE;

	if (!g_sb_integration.initialized) {
		secure_boot_bootloader_init();
		if (!g_sb_integration.initialized) {
			return false;
		}
	}

	if (firmware_region_size <= metadata_size) {
		g_sb_integration.last_error = SECURE_BOOT_ERR_MEMORY;
		g_sb_integration.boot_allowed = false;
		return false;
	}

	/* Initialize audit logging */
	audit_log_init();
	
	/* Log verification start */
	audit_log_record(AUDIT_EVT_FIRMWARE_VERIFY_START,
	                  AUDIT_SEVERITY_INFO, 0, 0, 0, NULL);

	/* Read firmware metadata from flash */
	firmware_metadata_t metadata;
	uintptr_t metadata_address = 0;
	
	if (!locate_firmware_metadata(firmware_base, firmware_region_size, &metadata, &metadata_address)) {
		print_secure_boot_status("ERROR: Failed to read firmware metadata", 
		                          SECURE_BOOT_ERR_MEMORY);
		g_sb_integration.last_error = SECURE_BOOT_ERR_INVALID_MAGIC;
		g_sb_integration.boot_allowed = false;
		
		/* Log verification failure */
		audit_log_record(AUDIT_EVT_FIRMWARE_VERIFY_FAIL,
		                  AUDIT_SEVERITY_ERROR,
		                  SECURE_BOOT_ERR_INVALID_MAGIC, 0, 0, NULL);
		
		return false;
	}
	(void)metadata_address;

	if (!metadata_size_valid(&metadata, firmware_region_size)) {
		g_sb_integration.last_error = SECURE_BOOT_ERR_INVALID_CRC;
		g_sb_integration.boot_allowed = false;
		g_sb_integration.fw_verified = false;

		audit_log_record(AUDIT_EVT_FIRMWARE_VERIFY_FAIL,
		                  AUDIT_SEVERITY_CRITICAL,
		                  SECURE_BOOT_ERR_INVALID_CRC,
		                  metadata.firmware_size,
		                  metadata.firmware_crc32,
		                  metadata.hash);

		return false;
	}

	/* Verify firmware signature and integrity */
	secure_boot_result_t verify_result = secure_boot_verify_firmware(
		firmware_base,
		metadata.firmware_size,
		&metadata
	);

	if (verify_result != SECURE_BOOT_OK) {
		print_secure_boot_status("ERROR: Firmware verification failed: ", verify_result);
		g_sb_integration.last_error = verify_result;
		g_sb_integration.boot_allowed = false;
		g_sb_integration.fw_verified = false;
		
		/* Log verification failure with error code */
		audit_log_record(AUDIT_EVT_FIRMWARE_VERIFY_FAIL,
		                  AUDIT_SEVERITY_CRITICAL,
		                  (uint16_t)verify_result,
		                  metadata.firmware_size,
		                  metadata.firmware_crc32,
		                  metadata.hash);
		
		return false;
	}

	/* Verify bootloader integrity */
	secure_boot_result_t bl_verify = secure_boot_verify_bootloader();
	
	if (bl_verify != SECURE_BOOT_OK) {
		print_secure_boot_status("ERROR: Bootloader verification failed: ", bl_verify);
		g_sb_integration.last_error = bl_verify;
		g_sb_integration.boot_allowed = false;
		
		/* Log bootloader verification failure */
		audit_log_record(AUDIT_EVT_FIRMWARE_VERIFY_FAIL,
		                  AUDIT_SEVERITY_CRITICAL,
		                  (uint16_t)bl_verify, 0, 0, NULL);
		
		return false;
	}

#ifdef DEBUG
	print_secure_boot_status("INFO: Firmware verification passed", SECURE_BOOT_OK);
#endif

	/* All security checks passed - log authorization */
	audit_log_record(AUDIT_EVT_FIRMWARE_VERIFY_PASS,
	                  AUDIT_SEVERITY_INFO,
	                  0,
	                  metadata.firmware_size,
	                  metadata.firmware_crc32,
	                  metadata.hash);
	
	audit_log_record(AUDIT_EVT_BOOT_AUTHORIZED,
	                  AUDIT_SEVERITY_INFO, 0, 0, 0, NULL);

	/* All security checks passed - allow boot */
	g_sb_integration.fw_verified = true;
	g_sb_integration.boot_allowed = true;
	g_sb_integration.last_error = SECURE_BOOT_OK;
	
	return true;
}

/**
 * @brief Check if boot is allowed (must call verify first)
 */
bool secure_boot_is_boot_allowed(void)
{
	return g_sb_integration.boot_allowed;
}

/**
 * @brief Get the last secure boot error
 */
uint32_t secure_boot_get_last_error(void)
{
	return g_sb_integration.last_error;
}

/**
 * @brief Reset secure boot integration
 */
void secure_boot_integration_reset(void)
{
	g_sb_integration.initialized = false;
	g_sb_integration.fw_verified = false;
	g_sb_integration.boot_allowed = false;
	g_sb_integration.last_error = 0;
}

/**
 * @brief Handle secure boot failure - can implement halt or recovery
 */
void secure_boot_failure_handler(secure_boot_result_t error)
{
	/* Log error (would write to persistent storage for diagnosis) */
	g_sb_integration.last_error = error;

	/* Flash LED pattern indicating secure boot failure */
	/* TODO: Implement LED flash pattern using board LED functions */
	
	/* Could implement:
	 * - Halt and require manual recovery
	 * - Attempt boot from backup firmware
	 * - Enable recovery mode
	 * - Trigger watchdog reset
	 */

	/* For maximum security, halt indefinitely */
	while (1) {
		/* TODO: Flash error code on LED or output to console */
		/* This prevents execution of untrusted code */
	}
}

/**
 * @brief Get secure boot version and build info
 */
const char* secure_boot_get_version(void)
{
	return "Secure Boot v1.0 - IEC 62443-4-1 Compliant";
}
