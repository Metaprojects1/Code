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
 * @file secure_boot_integration.h
 *
 * Bootloader Integration API for Secure Boot
 * Declares functions needed by bootloader to use secure boot
 */
#ifndef SECURE_BOOT_INTEGRATION_H
#define SECURE_BOOT_INTEGRATION_H

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "secure_boot.h"

/* ==================== Bootloader Integration API ==================== */

/**
 * @brief Initialize secure boot during bootloader startup
 * 
 * Call this once during bootloader initialization to set up
 * the secure boot subsystem.
 */
void secure_boot_bootloader_init(void);

/**
 * @brief Verify firmware before jumping to application
 * 
 * Performs complete firmware verification including:
 * - Metadata validation
 * - SHA256 hash verification
 * - ECDSA P-256 signature verification
 * - Anti-rollback checks
 * 
 * Call this after bootloader initialization and before jump_to_app()
 * to ensure only authentic firmware boots.
 * 
 * @return true if firmware verification passed and boot is allowed
 *         false if verification failed (don't boot firmware)
 */
bool secure_boot_verify_application(void);

/**
 * @brief Check if boot is allowed
 * 
 * Returns the current boot state from the last verification attempt.
 * 
 * @return true if boot is authorized, false otherwise
 */
bool secure_boot_is_boot_allowed(void);

/**
 * @brief Get the last secure boot error code
 * 
 * @return Error code from last operation
 */
uint32_t secure_boot_get_last_error(void);

/**
 * @brief Reset secure boot integration state
 * 
 * Clears internal state for reinitialization
 */
void secure_boot_integration_reset(void);

/**
 * @brief Handle secure boot failure
 * 
 * Called when firmware verification fails. Typically:
 * - Logs error to persistent storage
 * - Flashes error pattern on LED
 * - Can implement recovery mode
 * - Typically halts to prevent unsafe boot
 * 
 * @param error The error code that caused the failure
 */
void secure_boot_failure_handler(secure_boot_result_t error);

/**
 * @brief Get secure boot version string
 * 
 * @return Version string describing secure boot implementation
 */
const char* secure_boot_get_version(void);

#endif /* SECURE_BOOT_INTEGRATION_H */
